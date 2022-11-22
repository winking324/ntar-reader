// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

namespace ntar {

class BlockEnhancedPacket : public Block {
 public:
  enum OptionType {
    kFlags     = 2,
    kHash      = 3,
    kDropCount = 4,
  };

 public:
  explicit BlockEnhancedPacket(uint32_t length)
      : Block(BlockType::kEnhancedPacket, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

  uint32_t InterfaceId() const { return id_; }

  uint64_t Timestamp() const { return ts_; }

  uint32_t CapturedLength() const { return captured_length_; }

  uint32_t PacketLength() const { return packet_length_; }

  const std::vector<uint8_t> &Data() const { return data_; }

 private:
  uint32_t id_              = 0;
  uint64_t ts_              = 0;
  uint32_t captured_length_ = 0;
  uint32_t packet_length_   = 0;
  std::vector<uint8_t> data_;
};

}  // namespace ntar
