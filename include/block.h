// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "byte_io.h"
#include "memory.h"
#include "option.h"

namespace ntar {

enum BlockType {
  kInterfaceDescription = 0x00000001,
  kPacket               = 0x00000002,
  kSimplePacket         = 0x00000003,
  kNameResolution       = 0x00000004,
  kInterfaceStatistics  = 0x00000005,
  kEnhancedPacket       = 0x00000006,
  kSectionHeader        = 0x0A0D0D0A,
};

static const std::map<uint32_t, std::string> kBlockTypeName = {
    {kInterfaceDescription, "Interface Description Block"},
    {kPacket, "Packet Block"},
    {kSimplePacket, "Simple Packet Block"},
    {kNameResolution, "Name Resolution Block"},
    {kInterfaceStatistics, "Interface Statistics Block"},
    {kEnhancedPacket, "Enhanced Packet Block"},
    {kSectionHeader, "Section Header Block"},
};

typedef std::vector<std::unique_ptr<Option>> OptionBuffer;

class Block : public NonCopyOrMovable {
 public:
  enum OptionType {
    kEndOfOption = 0,
    kComment     = 1,
  };

 public:
  explicit Block(BlockType type, uint32_t length, Endianness endianness)
      : type_(type), length_(length), endianness_(endianness) {}

  virtual ~Block() = default;

  virtual size_t Read(const uint8_t *data) = 0;

  virtual std::string Output() = 0;

  uint32_t Type() const { return type_; }

  uint32_t Length() const { return length_; }

  const OptionBuffer &Options() const { return options_; }

 protected:
  size_t ReadOptions(const uint8_t *data);

 protected:
  uint32_t type_         = 0;
  uint32_t length_       = 0;
  Endianness endianness_ = kLittleEndian;
  OptionBuffer options_;
};

template <typename T>
struct BlockCreator {
  static Block *New(uint32_t l, Endianness e) { return (new T(l, e)); }
};
typedef Block *(*BlockCtreatorPtr)(uint32_t, Endianness);

}  // namespace ntar