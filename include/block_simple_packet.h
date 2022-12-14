// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <string>
#include <vector>

#include "block.h"  // NOLINT(build/include_subdir)

//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
//  0 |                    Block Type = 0x00000003                    |
//    +---------------------------------------------------------------+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                          Packet Len                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                                                               /
//    /                          Packet Data                          /
//    /          /* variable length, aligned to 32 bits */            /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

namespace ntar {

class BlockSimplePacket : public Block {
 public:
  explicit BlockSimplePacket(uint32_t length)
      : Block(BlockType::kSimplePacket, length) {}

  size_t Read(const uint8_t *data) override;

  std::string Output() override;

  uint32_t PacketLength() const { return packet_length_; }

 private:
  uint32_t packet_length_ = 0;
};

}  // namespace ntar
