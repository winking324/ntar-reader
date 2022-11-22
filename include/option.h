// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <cstdint>
#include <vector>

#include "byte_io.h"
#include "memory.h"

namespace ntar {

enum OptionCode : uint16_t {
  kEndOfOption = 0,
  kComment     = 1,
};

class Option : public NonCopyOrMovable {
 public:
  size_t Read(const uint8_t *data, Endianness endianness);

  uint16_t Code() const { return code_; }
  uint16_t Length() const { return length_; }
  const std::vector<uint8_t> &Data() const { return data_; }

 protected:
  uint16_t code_   = 0;
  uint16_t length_ = 0;
  std::vector<uint8_t> data_;
};

}  // namespace ntar
