// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <vector>

#include "block.h"

namespace ntar {

class BlockSimplePacket : public Block {
 public:
  explicit BlockSimplePacket(uint32_t length)
      : Block(BlockType::kSimplePacket, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

  uint32_t PacketLength() const { return packet_length_; }

  const std::vector<uint8_t> &Data() const { return data_; }

 private:
  uint32_t packet_length_ = 0;
  std::vector<uint8_t> data_;
};

}  // namespace ntar
