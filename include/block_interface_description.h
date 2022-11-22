// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

namespace ntar {

class BlockInterfaceDescription : public Block {
 public:
  explicit BlockInterfaceDescription(uint32_t length)
      : Block(BlockType::kInterfaceDescription, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

  uint16_t LinkType() const { return link_type_; }

  uint32_t SnapLength() const { return snap_length_; }

 private:
  uint16_t link_type_   = 0;
  uint32_t snap_length_ = 0;
};

}  // namespace ntar
