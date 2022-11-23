// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block.h"

namespace ntar {

size_t Block::ReadOptions(const uint8_t *data) {
  size_t read_size = 0;
  while (true) {
    std::unique_ptr<Option> opt{new Option(endianness_)};
    read_size += opt->Read(data + read_size);
    if (opt->Length() == 0 && opt->Code() == kEndOfOption) {
      // Do not add the end option to options
      break;
    }
    options_.push_back(std::move(opt));
  }
  return read_size;
}

}  // namespace ntar
