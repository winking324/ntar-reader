// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <istream>
#include <list>
#include <memory>

#include "block.h"
#include "byte_io.h"
#include "option.h"

namespace ntar {

class Section {
 public:
  size_t Read(std::istream *is);

 private:
  size_t ReadBlock(std::istream *is, Endianness endianness);

  std::unique_ptr<Block> CreateBlock(uint32_t type, uint32_t length);

 private:
  std::vector<std::unique_ptr<Option>> options_;
  std::vector<std::unique_ptr<Block>> blocks_;
};

}  // namespace ntar
