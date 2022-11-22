// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <cstdint>
#include <istream>
#include <memory>
#include <vector>

#include "byte_io.h"
#include "memory.h"
#include "option.h"

namespace ntar {

enum BlockType : uint32_t {
  kInterfaceDescription = 0x00000001,
  kPacket               = 0x00000002,
  kSimplePacket         = 0x00000003,
  kNameResolution       = 0x00000004,
  kInterfaceStatistics  = 0x00000005,
  kEnhancedPacket       = 0x00000006,
  kSectionHeader        = 0x0A0D0D0A,
};

class Block : public NonCopyOrMovable {
 public:
  explicit Block(BlockType type, uint32_t length)
      : type_(type), length_(length) {}

  virtual ~Block() = default;

  virtual size_t Read(const uint8_t *data, Endianness endianness) = 0;

  uint32_t Type() const { return type_; }

  uint32_t Length() const { return length_; }

 protected:
  size_t ReadOptions(const uint8_t *data, Endianness endianness);

 protected:
  uint32_t type_;
  uint32_t length_;
  std::vector<std::unique_ptr<Option>> options_;
};

template <typename T>
struct BlockCreator {
  static Block *New(uint32_t length) { return (new T(length)); }
};
typedef Block *(*BlockCtreatorPtr)(uint32_t);

}  // namespace ntar