//
//  main.cpp
//
//  Created by 123456qwerty on 2023/8/11.
//

#include "LIEF/LIEF.hpp"
#include <fstream>
#include <iostream>
#include <mach-o/loader.h>
#include <random>
#include <string>

using namespace LIEF::MachO;

int main(int argc, const char *argv[]) {
  if (argc < 3) {
    std::cout << "Usage: machostrip [-strip-ext](optional) [mach-o file] "
                 "[output file]"
              << std::endl;
    return 1;
  }

  bool stripext = false;
  int fileargvindex = 1;
  int outputargvindex = 2;

  if (!strcmp(argv[1], "-strip-ext")) {
    stripext = true;
    fileargvindex++;
    outputargvindex++;
  }

  std::unique_ptr<FatBinary> Binaries = Parser::parse(argv[fileargvindex]);
  for (Binary &Bin : *Binaries) {
    // remove function starts
    Bin.function_starts()->functions({});
    // remove local and external symbols
    std::vector<Symbol *> symtoremove;
    for (Symbol &Sym : Bin.symbols()) {
      if (Sym.category() == Symbol::CATEGORY::LOCAL ||
          (stripext && Sym.category() == Symbol::CATEGORY::EXTERNAL))
        symtoremove.emplace_back(&Sym);
    }
    for (Symbol *Sym : symtoremove)
      Bin.remove(*Sym);
    for (SegmentCommand &Seg : Bin.segments()) {
      if (Seg.name() == "__TEXT" || Seg.name() == "__DATA" ||
          Seg.name() == "__DATA__CONST")
        for (Section &Sec : Seg.sections()) {
          if (Sec.name().find("__objc") == std::string::npos &&
              Sec.name().find("__swift") == std::string::npos &&
              Sec.name().find("__unwind") == std::string::npos &&
              Sec.name().find("__eh") == std::string::npos &&
              Sec.name().find("__gcc") == std::string::npos &&
              Sec.name().find("__auth") == std::string::npos &&
              Sec.name().find("__got") == std::string::npos) {
            // malformed section name can prevent Ghidra from loading the macho
            Sec.name("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                     "\x11\x11");
          }
        }
    }
    // Hopper Demo Version checks if the binary contains this string, and if it
    // does, disassembly is not allowed
    Bin.add_exported_function(
        0, "(c) 2014 - Cryptic Apps SARL - Disassembling not allowed.");
  }
  const std::string output_name = argv[outputargvindex];
  Binaries->write(output_name);

  // obfuscate symbol stub name
  std::set<uint32_t> stroffs;
  std::map<uint32_t, uint32_t> strtabsize;

  std::unique_ptr<FatBinary> Binaries2 = Parser::parse(output_name);
  for (Binary &Bin : *Binaries2) {
    uint32_t stroff =
        (uint32_t)Bin.fat_offset() + Bin.symbol_command()->strings_offset();
    stroffs.insert(stroff);
    strtabsize[stroff] = Bin.symbol_command()->strings_size();
  }

  std::mt19937 eng(rand());
  std::uniform_int_distribution<uint8_t> dis(1, 0xff);

  std::fstream file;
  file.open(output_name, std::ios::in | std::ios::out);
  for (uint32_t off : stroffs) {
    uint32_t temp = off + strtabsize[off];
    while (off != temp) {
      file.seekp(off, std::ios::beg);
      file << dis(eng);
      off += 1;
    }
  }
  file.close();

  return 0;
}
