// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

//                            1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0 |             Block Type = 0x00000BAD or 0x40000BAD             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    4 |                      Block Total Length                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    8 |                Private Enterprise Number (PEN)                |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   12 /                                                               /
//      /                          Custom Data                          /
//      /              variable length, padded to 32 bits               /
//      /                                                               /
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      /                                                               /
//      /                      Options (variable)                       /
//      /                                                               /
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                      Block Total Length                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

namespace ntar {

class BlockCustom : public Block {
 public:
  explicit BlockCustom(uint32_t length) : Block(BlockType::kCustom, length) {}

  explicit BlockCustom(BlockType type, uint32_t length) : Block(type, length) {}

  size_t Read(const uint8_t *data) override;

  std::string Output() override;

  uint32_t PrivateEnterpriseNo() const { return private_enterprise_no_; }

 protected:
  uint32_t private_enterprise_no_;
};

class BlockCustomCopiable : public BlockCustom {
 public:
  BlockCustomCopiable(uint32_t length)
      : BlockCustom(BlockType::kCustomCopiable, length) {}

  std::string Output() override;
};

}  // namespace ntar
