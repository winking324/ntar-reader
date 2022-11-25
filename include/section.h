// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <istream>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "block.h"   // NOLINT(build/include_subdir)
#include "option.h"  // NOLINT(build/include_subdir)

namespace ntar {

typedef std::vector<std::unique_ptr<Block>> BlockBuffer;

class Section {
 public:
  size_t Read(std::istream *is);

  std::string Output();

  const BlockBuffer &Blocks() const { return blocks_; }

 private:
  size_t ReadBlock(std::istream *is);

  std::unique_ptr<Block> CreateBlock(uint32_t type, uint32_t length);

 private:
  BlockBuffer blocks_;
};

}  // namespace ntar
