// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <cstdint>
#include <string>
#include <vector>

#include "byte_io.h"
#include "memory.h"

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Option Code              |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Option Value                            /
// /          /* variable length, aligned to 32 bits */            /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                 . . . other options . . .                     /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Option Code == opt_endofopt  |  Option Length == 0          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

namespace ntar {

class Option : private NonCopyOrMovable {
 public:
  size_t Read(const uint8_t *data);

  uint16_t Code() const { return code_; }

  uint16_t Length() const { return length_; }

  const std::vector<uint8_t> &Data() const { return data_; }

  std::string OutputStringData();

  std::string OutputUint8Data();

  std::string OutputUint16Data();

  std::string OutputUint32Data();

  std::string OutputUint64Data();

  std::string OutputIpv4Data();

  std::string OutputIpv6Data();

  std::string OutputIpv4RecordData();

  std::string OutputIpv6RecordData();

  std::string OutputHexData();

 protected:
  uint16_t code_   = 0;
  uint16_t length_ = 0;
  std::vector<uint8_t> data_;
};

typedef std::string (Option::*kOutputPtr)();

}  // namespace ntar
