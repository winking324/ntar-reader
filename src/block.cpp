// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block.h"

namespace ntar {

size_t Block::ReadOptions(const uint8_t *data, ntar::Endianness endianness) {
  size_t read_size = 0;
  while (true) {
    std::unique_ptr<Option> opt{new Option()};
    read_size += opt->Read(data + read_size, endianness);
    if (opt->Length() == 0 && opt->Code() == OptionCode::kEndOfOption) {
      // Do not add the end option to options
      break;
    }
    options_.push_back(std::move(opt));
  }
  return read_size;
}

}  // namespace ntar
