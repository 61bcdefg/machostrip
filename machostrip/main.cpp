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
#include <stdexcept>
#include <vector>
#include <set>
#include <map>
#include <cstring>

using namespace LIEF::MachO;

const std::string FUNC_NAME_PATTERN = "(c) 2014 - Cryptic Apps SARL - Disassembling not allowed.";

static void removeSymbols(Binary& bin, bool stripext, bool stripindirect, bool optimize) {
    std::vector<Symbol*> symtoremove;
    for (Symbol& sym : bin.symbols()) {
        if (sym.category() == Symbol::CATEGORY::LOCAL ||
            (stripext && sym.category() == Symbol::CATEGORY::EXTERNAL) ||
            (stripindirect && (sym.category() == Symbol::CATEGORY::INDIRECT_ABS ||
                              sym.category() == Symbol::CATEGORY::INDIRECT_LOCAL))) {
            symtoremove.push_back(&sym);
        }
    }


    for (Symbol* sym : symtoremove) {
        bin.remove(*sym);
    }
}

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

static void optimizeSectionsAlignment(SegmentCommand& seg, int alignment) {
    for (Section& section : seg.sections()) {
        // Optimize section alignment
        section.alignment(alignment);
        // For iOS on the ARM64 architecture (AArch64), it is usually recommended to use an alignment of 16 bytes (128 bits), since this corresponds to the size of the vector register (128 bits), which is often used for floating-point operations and other calculations. It can also improve performance, as it conforms to architectural features.
    }
}



int main(int argc, const char* argv[]) {
    if (argc < 4) {
            std::cout << "Usage: machostrip [-strip-ext](optional) [-strip-indirect](optional) [--optimize alignment](optional) [mach-o file] [output file]" << std::endl;
            return 1;
        }

        bool stripext = false;
        bool stripindirect = false;
        bool useoptimize = false;
        int fileargvindex = 1;
        int outputargvindex = 2;
        int opt_value = -1;

        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "-strip-ext")) {
                stripext = true;
                fileargvindex++;
                outputargvindex++;
            } else if (!strcmp(argv[i], "-strip-indirect")) {
                stripindirect = true;
                fileargvindex++;
                outputargvindex++;
            } else if (!strcmp(argv[i], "--optimize")) {
                useoptimize = true;
                if (i + 1 < argc) {
                    opt_value = std::atoi(argv[i + 1]);
                } else {
                    std::cerr << "Error: Missing argument for --optimize" << std::endl;
                    return 1;
                }
                fileargvindex += 2;
                outputargvindex += 2;
            }
        }
    
    try {
        std::unique_ptr<FatBinary> inputBinaries = Parser::parse(argv[fileargvindex]);
        
        for (Binary& bin : *inputBinaries) {
            bin.function_starts()->functions({});
            
            for (SegmentCommand& seg : bin.segments()) {
                if (seg.name() == "__TEXT"  || seg.name() == "__DATA"  || seg.name() == "__DATA__CONST") {
                    updateSectionNames(seg);
                    if (useoptimize) {
                        optimizeSectionsAlignment(seg, *argv[opt_value]);
                    }
                }
            }
            bin.add_exported_function(0, FUNC_NAME_PATTERN);
        }
        
        const std::string outputName = argv[outputargvindex];
        inputBinaries->write(outputName);
        
        std::set<uint32_t> stroffs;
        std::map<uint32_t, uint32_t> strtabsize;
        
        std::unique_ptr<FatBinary> outputBinaries = Parser::parse(outputName);
        for (Binary& bin : *outputBinaries) {
            SymbolCommand* symbolCommand = bin.symbol_command();
            if (symbolCommand) {
                uint32_t stroff = static_cast<uint32_t>(bin.fat_offset()) + symbolCommand->strings_offset();
                stroffs.insert(stroff);
                strtabsize[stroff] = symbolCommand->strings_size();
            }
        }
        
        std::random_device rd;
        std::mt19937 eng(rd());
        std::uniform_int_distribution<uint8_t> dis(1, 0xFF);
        
        std::fstream file(outputName, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open the output file for obfuscation.");
        }
        
        for (uint32_t off : stroffs) {
            uint32_t temp = off + strtabsize[off];
            while (off != temp) {
                file.seekp(off, std::ios::beg);
                uint8_t random_value = dis(eng);
                file.write(reinterpret_cast<const char*>(&random_value), sizeof(uint8_t));
                off += 1;
            }
        }
        
        file.close();
        
        return 0;
    } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
