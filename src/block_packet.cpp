// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_packet.h"

namespace ntar {

//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
//  0 |                    Block Type = 0x00000002                    |
//    +---------------------------------------------------------------+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |         Interface ID          |          Drops Count          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                         Captured Len                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 |                          Packet Len                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 28 /                                                               /
//    /                          Packet Data                          /
//    /          /* variable length, aligned to 32 bits */            /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

constexpr uint32_t kBlockPacketMinLength = sizeof(uint32_t) * 8;

size_t BlockPacket::Read(const uint8_t *data, ntar::Endianness endianness) {
  size_t read_size = 0;
  uint64_t ts_high, ts_low;
  if (endianness == Endianness::kBigEndian) {
    id_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    drop_count_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    ts_high = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    captured_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    packet_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    id_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    drop_count_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    ts_high = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    captured_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    packet_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  ts_ = ts_high << 32 | ts_low;

  uint32_t padded_length = captured_length_ % 4 == 0
                               ? captured_length_
                               : (captured_length_ / 4 + 1) * 4;
  if (captured_length_ > 0) {
    data_.resize(captured_length_);
    std::copy(data + read_size, data + read_size + captured_length_,
              data_.begin());
    read_size += padded_length;
  }

  if (Length() > padded_length + kBlockPacketMinLength) {
    read_size += ReadOptions(data + read_size, endianness);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

}  // namespace ntar
