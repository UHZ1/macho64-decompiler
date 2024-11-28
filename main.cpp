#include <cstdint>
#include <cassert>
#include <iostream>
#include <fstream>
#include "mach-o/loader.h"
#include "mach-o/fixup-chains.h"

/*
31   28   24   20   16   12    8    4    0
|----|----|----|----|----|----|----|----|
[opcode][cond][Rn ][Rm ][Rd ][imm ][other]
*/

void read_segment_command_64(std::ifstream& file)
{
  segment_command_64 segment_cmd;
  file.read(reinterpret_cast<char*>(&segment_cmd), sizeof(segment_cmd));
  printf("-> segname: %s - nsects: %d - vmaddr: 0x%02llx - vmsize: 0x%2llx\n",
        segment_cmd.segname, segment_cmd.nsects, segment_cmd.vmaddr, segment_cmd.vmsize);

  for (uint32_t i = 0; i < segment_cmd.nsects; ++i)
  {
    section_64 section;
    file.read(reinterpret_cast<char*>(&section), sizeof(section));

    std::ios::pos_type  pos = file.tellg();
    printf("--> sect[%d]: %s\n    offset:  %u\n    size:    0x%02llx\n    addr:    0x%02llx\n",
                  i, section.sectname, section.offset, section.size, section.addr);

    file.seekg(section.offset);
    std::vector<char> data(section.size);
    file.read(data.data(), section.size);

    for (int j = 0; j < data.size(); ++j)
    {
      if (j % 16 == 0) std::cout << "      ";
      printf("%02x ", static_cast<unsigned char>(data[j]));
      if ((j + 1) % 16 == 0) std::cout << "\n";
    }
    if (data.size() % 16) std::cout << '\n';
    file.seekg(pos);
  }
}

void read_dyld_chained(std::ifstream& file)
{
  linkedit_data_command cmd;
  file.read(reinterpret_cast<char*>(&cmd), sizeof(cmd));

  file.seekg(cmd.dataoff);
  std::ios::pos_type base_pos = file.tellg();

  dyld_chained_fixups_header header;
  file.read(reinterpret_cast<char*>(&header), sizeof(header));

  printf("-> starts_offset: %u - imports_offset: %u - imports_count: %d - symbols_offset: %u\n",
      header.starts_offset, header.imports_offset, header.imports_count, header.symbols_offset);

  file.seekg(header.starts_offset + base_pos);
  
  uint32_t seg_count = 0;
  file.read(reinterpret_cast<char*>(&seg_count), sizeof(seg_count));

  std::vector<uint32_t> seg_info_offset(seg_count);
  file.read(reinterpret_cast<char*>(seg_info_offset.data()), 
                    seg_count * sizeof(uint32_t));

  // ASSERT SEG_COUNT == LC_SEGMENT_64 cnt
  for (uint32_t i = 0; i < seg_count; ++i)
  {
    printf("--> dyld_chained_start_seg[%d]\n", i);
    if (seg_info_offset[i])
    {
      file.seekg(header.starts_offset + seg_info_offset[i] + base_pos);
      dyld_chained_starts_in_segment start_seg;
      file.read(reinterpret_cast<char*>(&start_seg), 
                    sizeof(start_seg) - sizeof(uint16_t));
      
      std::vector<uint16_t> page_start(start_seg.page_count);
      file.read(reinterpret_cast<char*>(page_start.data()), 
                    start_seg.page_count * sizeof(uint16_t));

      char s[10] = "    ";
      printf("%ssize: 0x%02x\n%spage_size: 0x%02x\n%spointer_format: %d\n%ssegment_offset: %llu\n%spage_count: %u\n",
        s, start_seg.size, s, start_seg.page_size, s, start_seg.pointer_format, 
        s, start_seg.segment_offset, s, start_seg.page_count);
      
      for (uint16_t j = 0; j < start_seg.page_count; ++j)
      {
        printf("      page_start[%d]\n", j);
        if (page_start[j] == DYLD_CHAINED_PTR_START_NONE)
        {
          std::cout << "      no fixups on page\n";
          continue;
        }
        uint64_t page_pos = start_seg.segment_offset + start_seg.page_size * j + page_start[j];
        while (true)
        {
          dyld_chained_ptr_64_bind bind;
          file.seekg(page_pos);
          file.read(reinterpret_cast<char*>(&bind), sizeof(bind));

          if (bind.bind)
          {
            dyld_chained_import import;
            std::ios::pos_type import_pos = header.imports_offset + base_pos + sizeof(import) * bind.ordinal;
            file.seekg(import_pos);
            file.read(reinterpret_cast<char*>(&import), sizeof(import));

            char c;
            std::string symbol;
            file.seekg(import.name_offset + header.symbols_offset + base_pos);
            while (file.get(c) && c) symbol += c;
            std::cout << "      BIND:\n"
                      << "        lib_ordinal " << import.lib_ordinal << "\n" 
                      << "        weak_import " << import.weak_import << "\n" 
                      << "        name_offset " << import.name_offset << " "
                      << "(" << symbol << ")\n";
          }
          else
          {
            std::cout << "      REBASE\n"; 
            dyld_chained_ptr_64_rebase rebase;
            file.seekg(page_pos);
            file.read(reinterpret_cast<char*>(&rebase), sizeof(rebase));
            std::cout << "        target " << rebase.target << "\n"
                      << "        high8 " << rebase.high8 << "\n";
          }

          if (!bind.next)
            break;

          page_pos += bind.next * 4;
        }
      }
    }
    else
      printf("    empty\n");
  }

  file.seekg(base_pos);
}

uint64_t read_uleb128(std::ifstream& file, std::ios::pos_type max_offset)
{
  uint64_t res = 0;
  uint32_t shift = 0;
  while (true)
  {
    uint8_t slice;
    file.read(reinterpret_cast<char*>(&slice), sizeof(slice));

    res |= (uint64_t)(slice & 0x7f) << shift;
    shift += 7;

    if (!(slice & 0x80))
      break;
    
    if (file.tellg() >= max_offset || shift >= 64)
    {
      std::cout << "too big chungus\n";
      exit(1);
    }
  }
  return res;
}

void read_dyld_exports_trie_helper(std::ifstream& file, const std::string& prefix, 
                                   std::ios::pos_type start, std::ios::pos_type max_offset)
{
  if (file.tellg() >= max_offset) 
    return;

  char c;
  uint8_t terminal = read_uleb128(file, max_offset);
  std::ios::pos_type children_offset = terminal + file.tellg();

  if (terminal)
  {
    uint64_t flags = read_uleb128(file,  max_offset);
    if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT)
    {
      uint64_t dylib_ordinal = read_uleb128(file, max_offset);
      std::string import_name;
      while (file.read(&c, 1) && c != '\0') 
        import_name += c;
      printf("  Re-export: %s -> %s (library %llu)\n", prefix.c_str(), import_name.c_str(), dylib_ordinal);
    }
    else
    {
      uint64_t address = read_uleb128(file, max_offset);
      std::cout << "  Exported symbol: " << prefix << " at address 0x" << std::hex 
                << std::setw(8) << std::setfill('0') << address << std::dec << "\n";
    }
  }

  uint8_t num_children;
  file.seekg(children_offset);
  file.read(reinterpret_cast<char*>(&num_children), sizeof(num_children));

  for (uint8_t i = 0; i < num_children; ++i)
  {
    std::string edge_substr;
    while (file.read(&c, 1) && c != '\0') 
      edge_substr += c;

    uint32_t children_offset = read_uleb128(file, max_offset);

    std::ios::pos_type saved = file.tellg();

    file.seekg(children_offset + start);
    read_dyld_exports_trie_helper(file, prefix + edge_substr, start, max_offset);

    file.seekg(saved);
  }
}

void read_dyld_exports_trie(std::ifstream& file)
{
  linkedit_data_command data;
  file.read(reinterpret_cast<char*>(&data), sizeof(data)); 
  file.seekg(data.dataoff);
  read_dyld_exports_trie_helper(file, "", data.dataoff, data.dataoff + data.datasize);
}

void start_disassemble_process(const char* filename)
{
  std::ifstream file(filename, std::ios::binary);

  if (!file)
  {
    std::cerr << "Error file opening\n";
    exit(1);
  }

  mach_header_64 header;
  file.read(reinterpret_cast<char*>(&header), sizeof(header));

  if (header.magic != MH_MAGIC_64)
  {
    std::cerr << "Invalid mach-o 64 file\n";
    exit(1);
  }

  for (uint32_t i = 0; i < header.ncmds; ++i)
  {
    load_command lcmd;
    std::ios::pos_type pos = file.tellg();
    file.read(reinterpret_cast<char*>(&lcmd), sizeof(lcmd));
    file.seekg(pos);
    switch (lcmd.cmd)
    {
      // 64-bit segment of file mapped into address space of process that loads file
      case LC_SEGMENT_64:
        std::cout << "LC_SEGMENT_64\n";
        read_segment_command_64(file);
        break;
      // new thingy make code go vroom
      case LC_DYLD_CHAINED_FIXUPS:
        std::cout << "LC_DYLD_CHAINED_FIXUPS\n";
        read_dyld_chained(file);
        break;
      // information about symbols exported by binary
      case LC_DYLD_EXPORTS_TRIE:
        std::cout << "LC_DYLD_EXPORTS_TRIE\n";
        read_dyld_exports_trie(file);
        break;
      // specify dynamically linked library install name
      // data for rebasing and rebinding internal pointers at runtime
      case LC_ID_DYLIB:
      case LC_LOAD_DYLIB:
        std::cout << "LC_ID_DYLIB\n";
        dylib_command dylib;
        file.read(reinterpret_cast<char*>(&dylib), sizeof(dylib));
        break;
      // Symbol table information used by dynamic linker
      case LC_DYSYMTAB:
        std::cout << "LC_DYSYMTAB\n";
        dysymtab_command dysymtab;
        file.read(reinterpret_cast<char*>(&dysymtab), sizeof(dysymtab));
        break;
      // loaded dynamic linker
      case LC_LOAD_DYLINKER:
        std::cout << "LC_LOAD_DYLINKER\n";
        break;
      case LC_UUID:
        std::cout << "LC_UUID\n";
        break;
      // build for platform min OS version
      case LC_BUILD_VERSION:
        std::cout << "LC_BUILD_VERSION\n";
        break;
      // table of non-instructions in __text
      case LC_DATA_IN_CODE:
        std::cout << "LC_DATA_IN_CODE\n";
        break;
      // Symbol table used by static/dynamic linking and to map symbols to original source code
      case LC_SYMTAB:
        std::cout << "LC_SYMTAB\n";
        symtab_command symtab;
        file.read(reinterpret_cast<char*>(&symtab), sizeof(symtab));
        break;
      // Address of shared lib initialization routine
      case LC_ROUTINES_64:
        routines_command_64 routines;
        std::cout << "LC_ROUTroutines;INES_64\n";
        file.read(reinterpret_cast<char*>(&routines), sizeof(routines));
        break;
      // offsets to function entry points
      case LC_FUNCTION_STARTS:
        std::cout << "LC_FUNCTION_STARTS\n";
        linkedit_data_command funcs;
        file.read(reinterpret_cast<char*>(&funcs), sizeof(funcs));
        break;
      case LC_SOURCE_VERSION:
        std::cout << "LC_SOURCE_VERSION\n";
        break;
      // entry point into program
      case LC_MAIN:
        std::cout << "LC_MAIN\n";
        entry_point_command entry;
        file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
        break;
      case LC_CODE_SIGNATURE:
        std::cout << "LC_CODE_SIGNATURE\n";
        break;
      default:
        std::cout << "OTHER: " << lcmd.cmd << " " << lcmd.cmdsize << "\n";
        break;
    }
    file.seekg(lcmd.cmdsize + pos);
  }
  file.close();
}

int main(int argc, char* argv[])
{
  if (argc != 2)
    std::cout << "Usage: ./main [macho64 binary]\n";
  else
    start_disassemble_process(argv[1]);
}
