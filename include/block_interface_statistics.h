// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include "block.h"

namespace ntar {

class BlockInterfaceStatistics : public Block {
 public:
  enum OptionType {
    kStartTime    = 2,
    kEndTime      = 3,
    kIfRecv       = 4,
    kIfDrop       = 5,
    kFilterAccept = 6,
    kOsDrop       = 7,
    kUserDeliver  = 8,
  };

 public:
  explicit BlockInterfaceStatistics(uint32_t length)
      : Block(BlockType::kInterfaceStatistics, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

  uint32_t InterfaceId() const { return id_; }

  uint64_t Timestamp() const { return ts_; }

 private:
  uint32_t id_ = 0;
  uint64_t ts_ = 0;
};

}  // namespace ntar
