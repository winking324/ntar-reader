// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <memory>
#include <vector>

#include "block.h"

namespace ntar {

enum RecordType {
  kEndOfRecord = 0,
  kIp4Record   = 1,
  kIp6Record   = 2,
};

class Record : public Option {
 public:
  uint16_t Type() const { return code_; }
};

class BlockNameResolution : public Block {
 public:
  explicit BlockNameResolution(uint32_t length)
      : Block(BlockType::kNameResolution, length) {}

  size_t Read(const uint8_t *data, Endianness endianness) override;

 private:
  size_t ReadRecords(const uint8_t *data, Endianness endianness);

 private:
  std::vector<std::unique_ptr<Record>> records_;
};

}  // namespace ntar
