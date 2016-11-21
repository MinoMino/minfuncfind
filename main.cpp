#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64)
#include "hde64.h"
const char app_name[] = "minfuncfind64";
#elif defined(__i386) || defined(_M_IX86)
#include "hde32.h"
const char app_name[] = "minfuncfind32";
#endif

#define uint uintptr_t

#define IS_RET(hde) (hde.opcode == 0xC3||hde.opcode == 0xCB||hde.opcode == 0xC2||hde.opcode == 0xCA)
#define PATTERN_TARGET_LENGTH 50 // The approximate length it will aim for.

std::vector<std::pair<std::string, uint>> funcs; // func_name, address
std::vector<std::pair<std::string, std::string>> patterns; // pattern, mask

// For when we have an address and want to know exactly where it is
// so we know where to apply the mask.
static int findValue(void* target, uint8_t value, int size) {
  for (int i = 0; i < size; i++)
    if (*(uint8_t*)((uint)target + i) == value) return i;

  return -1;
}

static int findValue(void* target, uint16_t value, int size) {
  for (int i = 0; i < size; i++)
    if (*(uint16_t*)((uint)target + i) == value) return i;

  return -1;
}

static int findValue(void* target, uint32_t value, int size) {
  for (int i = 0; i < size; i++)
    if (*(uint32_t*)((uint)target + i) == value) return i;

  return -1;
}

#if defined(__x86_64__) || defined(_M_X64)
static int findValue(void* target, uint64_t value, int size) {
  for (int i = 0; i < size; i++)
    if (*(uint64_t*)((uint)target + i) == value) return i;

  return -1;
}
#endif

int main(int argc, char* argv[]) {
  std::cout << app_name << " by Mino <mino@minomino.org>" << std::endl;
  uint base = 0;
  if (argc < 4) {
    std::cout << "Usage: " << argv[0] << " <header> <target> <output> [base_address]" << std::endl;
    return 0;
  }
  if (argc > 4) {
    base = strtoul(argv[4], NULL, 0);
    if (!base) {
      std::cout << "Invalid base!" << std::endl;
      return 1;
    }
  }

  std::ifstream header(argv[1]);
  std::ifstream target(argv[2], std::ifstream::binary);
  std::string line, def, name;
  uint address;

  if (!header) {
    std::cerr << "Error: Couldn't open header'" << argv[1] << "'!" << std::endl;
    return 1;
  }
  else if (!target) {
    std::cerr << "Error: Couldn't open target '" << argv[2] << "'!" << std::endl;
    return 1;
  }

  // Read the header and pull relevant info.
  while (std::getline(header, line)) {
    std::istringstream iss(line);
    iss >> def >> name >> std::hex >> address;

    if (!def.compare("#define")) {
      funcs.push_back(std::pair<std::string, uint>(name, address - base));
    }
  }
  header.close();

  // Read whole file into memory
  std::cout << "Reading target file..." << std::endl;
  target.seekg(0, target.end);
  int length = (int)target.tellg();
  target.seekg(0, target.beg);
  char * buffer = new char[length];
  if (buffer == NULL) {
    std::cerr << "Error: Failed to allocate memory to read the target file." << std::endl;
    return 1;
  }
  target.read(buffer, length);
  // Check if we made it.
  if (!target) {
    std::cerr << "Error: Failed to read the whole file." << std::endl;
    return 1;
  }
  target.close();

  // Start disassembling.
  std::cout << std::hex << std::setfill('0');
  for (auto it = funcs.begin(); it != funcs.end(); ++it) {
    std::cout << "Generating pattern and mask for " << it->first << " at 0x" << std::setw(8) << it->second << "..." << std::endl;

#if defined(__x86_64__) || defined(_M_X64)
    hde64s hde;
#elif defined(__i386) || defined(_M_IX86)
    hde32s hde;
#endif

    uint current = (uint)buffer + it->second;
    //std::cout << "CURRENT: 0x" << std::hex << std::setfill('0') << std::setw(sizeof(int) * 2) << (uint)current - (uint)buffer << std::endl;
#if defined(__x86_64__) || defined(_M_X64)
    uint length = hde64_disasm((void*)current, &hde);
#elif defined(__i386) || defined(_M_IX86)
    uint length = hde32_disasm((void*)current, &hde);
#endif

    union {
      uint8_t addr8;
      uint16_t addr16;
      uint32_t addr32;
#if defined(__x86_64__) || defined(_M_X64)
      uint64_t addr64;
#endif
    } value;
    uint value_length;
    uint pos;
    std::ostringstream pattern, mask;

    // Open string.
    pattern << "\"" << std::hex << std::setfill('0');
    mask << "\"" << std::hex << std::setfill('0');

    bool done = false, got_value;
    while (!done) {
      got_value = false;
      //std::cout << "CURRENT: 0x" << std::hex << std::setfill('0') << std::setw(sizeof(int)) << (uint)current - (uint)buffer << std::endl;
      if (length > PATTERN_TARGET_LENGTH) {
        break;
      }
      else if (hde.flags & F_ERROR) {
        std::cerr << "The target binary has invalid op codes at 0x" << current << ". Exiting!" << std::endl;
        return 1;
      }
      else if (IS_RET(hde)) {
        done = true;
      }
      else {
        if (hde.flags & F_IMM8) {
          got_value = true;
          value.addr8 = hde.imm.imm8;
          value_length = 1;
          pos = findValue((void*)current, value.addr8, hde.len);
        }
        else if (hde.flags & F_IMM16) {
          got_value = true;
          value.addr16 = hde.imm.imm16;
          value_length = 2;
          pos = findValue((void*)current, value.addr16, hde.len);
        }
        else if (hde.flags & F_IMM32) {
          got_value = true;
          value.addr32 = hde.imm.imm32;
          value_length = 4;
          pos = findValue((void*)current, value.addr32, hde.len);
        }
#if defined(__x86_64__) || defined(_M_X64)
        else if (hde.flags & F_IMM64) {
          got_value = true;
          value.addr64 = hde.imm.imm64;
          value_length = 8;
          pos = findValue((void*)current, value.addr64, hde.len);
        }
#endif
        else if (hde.flags & F_DISP8) {
          got_value = true;
          value.addr8 = hde.disp.disp8;
          value_length = 1;
          pos = findValue((void*)current, value.addr8, hde.len);
        }
        else if (hde.flags & F_DISP16) {
          got_value = true;
          value.addr16 = hde.disp.disp16;
          value_length = 2;
          pos = findValue((void*)current, value.addr16, hde.len);
        }
        else if (hde.flags & F_DISP32) {
          got_value = true;
          value.addr32 = hde.disp.disp32;
          value_length = 4;
          pos = findValue((void*)current, value.addr32, hde.len);
        }
      }

      for (uint i = 0; i < hde.len; i++) {
        if (got_value && (i >= pos && i < pos + value_length)) { // Skip?
          pattern << "\\x00";
          mask << "-";
        }
        else {
          pattern << "\\x" << std::setw(2) << ((int)(*(char*)(current + i)) & 0xFF);
          mask << "X";
        }
      }
      
      current += hde.len;
#if defined(__x86_64__) || defined(_M_X64)
      length += hde64_disasm((void*)current, &hde);
#elif defined(__i386) || defined(_M_IX86)
      length += hde32_disasm((void*)current, &hde);
#endif
    }

    // Close string.
    pattern << "\"";
    mask << "\"";

    patterns.push_back(std::pair<std::string, std::string>(pattern.str(), mask.str()));
  }

  std::ofstream output(argv[3]);
  if (!output) {
    std::cerr << "Error: Couldn't open '" << argv[3] << "' for output!" << std::endl;
    return 1;
  }

  // Write to output file.
  output << "// Generated by " << app_name << "." << std::endl;
  for (auto it = patterns.begin(); it != patterns.end(); ++it) {
    output << "#define " << "PTRN_" << funcs.at(it - patterns.begin()).first << " " << it->first << std::endl;
    output << "#define " << "MASK_" << funcs.at(it - patterns.begin()).first << " " << it->second << std::endl;
  }

  delete[] buffer;
  std::cout << "Done!" << std::endl;
  return 0;
}
