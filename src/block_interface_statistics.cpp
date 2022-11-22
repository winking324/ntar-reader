// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_interface_statistics.h"

namespace ntar {

//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
//  0 |                   Block Type = 0x00000005                     |
//    +---------------------------------------------------------------+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

constexpr uint32_t kBlockInterfaceStatisticsMinLength = sizeof(uint32_t) * 6;

size_t BlockInterfaceStatistics::Read(const uint8_t *data,
                                      ntar::Endianness endianness) {
  size_t read_size = 0;
  uint64_t ts_high, ts_low = 0;
  if (endianness == Endianness::kBigEndian) {
    id_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_high = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    id_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_high = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  ts_ = ts_high << 32 | ts_low;
  if (Length() > kBlockInterfaceStatisticsMinLength) {
    read_size += ReadOptions(data + read_size, endianness);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

}  // namespace ntar
