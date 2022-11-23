// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
// 0  |                    Block Type = 0x00000001                    |
//    +---------------------------------------------------------------+
// 4  |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8  |           LinkType            |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

namespace ntar {

class BlockInterfaceDescription : public Block {
 public:
  enum OptionType {
    kName                     = 2,
    kDescription              = 3,
    kIpv4Address              = 4,
    kIpv6Address              = 5,
    kMacAddress               = 6,
    kEuiAddress               = 7,
    kSpeed                    = 8,
    kTsResolution             = 9,
    kTimeZone                 = 10,
    kFilter                   = 11,
    kOs                       = 12,
    kFrameCheckSequenceLength = 13,
    kTsOffset                 = 14,
  };

 public:
  explicit BlockInterfaceDescription(uint32_t length, Endianness endianness)
      : Block(BlockType::kInterfaceDescription, length, endianness) {}

  size_t Read(const uint8_t *data) override;

  std::string Output() override;

  uint16_t LinkType() const { return link_type_; }

  uint32_t SnapLength() const { return snap_length_; }

 private:
  uint16_t link_type_   = 0;
  uint32_t snap_length_ = 0;
};

}  // namespace ntar
