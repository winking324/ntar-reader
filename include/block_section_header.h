// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

namespace ntar {

class BlockSectionHeader : public Block {
 public:
  explicit BlockSectionHeader(uint32_t length)
      : Block(BlockType::kSectionHeader, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

  uint16_t MajorVersion() const { return major_version_; }

  uint16_t MinorVersion() const { return minor_version_; }

  uint64_t SectionLength() const { return section_length_; }

 private:
  uint16_t major_version_  = 0;
  uint16_t minor_version_  = 0;
  uint64_t section_length_ = 0;
};

}  // namespace ntar
