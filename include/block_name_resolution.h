// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <memory>
#include <string>
#include <vector>

#include "block.h"  // NOLINT(build/include_subdir)

//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
//  0 |                    Block Type = 0x00000004                    |
//    +---------------------------------------------------------------+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |      Record Type              |         Record Length         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                       Record Value                            /
//    /          /* variable length, aligned to 32 bits */            /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    .                                                               .
//    .                  . . . other records . . .                    .
//    .                                                               .
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Record Type == end_of_recs   |  Record Length == 00          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

namespace ntar {

enum RecordType {
  kEndOfRecord = 0,
  kIpv4Record  = 1,
  kIpv6Record  = 2,
  kEui48Record = 3,
  kEui64Record = 4,
};

class Record : public Option {
 public:
  uint16_t Type() const { return code_; }
};

typedef std::vector<std::unique_ptr<Record>> RecordBuffer;

class BlockNameResolution : public Block {
 public:
  enum OptionType {
    kDnsName        = 2,
    kDnsIpv4Address = 3,
    kDnsIpv6Address = 4,
  };

 public:
  explicit BlockNameResolution(uint32_t length)
      : Block(BlockType::kNameResolution, length) {}

  size_t Read(const uint8_t *data) override;

  std::string Output() override;

  const RecordBuffer &Records() const { return records_; }

 private:
  size_t ReadRecords(const uint8_t *data);

 private:
  RecordBuffer records_;
};

}  // namespace ntar
