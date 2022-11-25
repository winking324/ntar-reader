// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block.h"

#include <sstream>

namespace ntar {

constexpr uint32_t kBlockMinLength = sizeof(uint32_t) * 3;

size_t Block::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (Length() > kBlockMinLength) {
    uint32_t packet_data_length = Length() - kBlockMinLength;
    data_.resize(packet_data_length);
    std::copy(data + read_size, data + read_size + packet_data_length,
              data_.begin());
    read_size += packet_data_length;
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

std::string Block::Output() {
  std::ostringstream oss;
  oss << "[Block]Unknown Type: " << Type() << "\n";
  return oss.str();
}

size_t Block::ReadOptions(const uint8_t *data) {
  size_t read_size = 0;
  while (true) {
    std::unique_ptr<Option> opt{new Option()};
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
