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

// Function to remove unnecessary symbols
static void removeSymbols(Binary& bin, bool stripext) {
    std::vector<Symbol*> symtoremove;
    for (Symbol& sym : bin.symbols()) {
        if (sym.category() == Symbol::CATEGORY::LOCAL ||
            (stripext && sym.category() == Symbol::CATEGORY::EXTERNAL)) {
            symtoremove.push_back(&sym);
        }
    }
    for (Symbol* sym : symtoremove) {
        bin.remove(*sym);
    }
}

// Function to update section names
static void updateSectionNames(SegmentCommand& seg) {
    for (Section& sec : seg.sections()) {
        std::string secName = sec.name();
        if (secName.find("__objc") == std::string::npos &&
            secName.find("__swift") == std::string::npos &&
            secName.find("__unwind") == std::string::npos &&
            secName.find("__eh") == std::string::npos &&
            secName.find("__gcc") == std::string::npos &&
            secName.find("__auth") == std::string::npos &&
            secName.find("__got") == std::string::npos) {
            sec.name("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11");
        }
    }
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: machostrip [-strip-ext](optional) [mach-o file] [output file]" << std::endl;
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

    // Parse input binary
    std::unique_ptr<FatBinary> inputBinaries = Parser::parse(argv[fileargvindex]);
    for (Binary& bin : *inputBinaries) {
        bin.function_starts()->functions({});
        removeSymbols(bin, stripext);

        for (SegmentCommand& seg : bin.segments()) {
            if (seg.name() == "__TEXT"  || seg.name() == "__DATA"  || seg.name() == "__DATA__CONST") {
                updateSectionNames(seg);
            }
        }
        bin.add_exported_function(0, "(c) 2014 - Cryptic Apps SARL - Disassembling not allowed.");
    }

    const std::string outputName = argv[outputargvindex];
    inputBinaries->write(outputName);

    // Obfuscate symbol stub names
    std::set<uint32_t> stroffs;
    std::map<uint32_t, uint32_t> strtabsize;

    std::unique_ptr<FatBinary> outputBinaries = Parser::parse(outputName);
    for (Binary& bin : *outputBinaries) {
        uint32_t stroff = static_cast<uint32_t>(bin.fat_offset()) + bin.symbol_command()->strings_offset();
        stroffs.insert(stroff);
        strtabsize[stroff] = bin.symbol_command()->strings_size();
    }

    std::mt19937 eng(std::random_device{}());
    std::uniform_int_distribution<uint8_t> dis(1, 0xFF);

    std::fstream file(outputName, std::ios::in | std::ios::out);
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
