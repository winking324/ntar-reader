// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_interface_description.h"

namespace ntar {

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +---------------------------------------------------------------+
// 0  |                    Block Type = 0x00000001                    |
//    +---------------------------------------------------------------+
// 4  |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8  |           LinkType            |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +---------------------------------------------------------------+
//

constexpr uint32_t kBlockInterfaceDescriptionMinLength = sizeof(uint32_t) * 5;

size_t BlockInterfaceDescription::Read(const uint8_t *data,
                                       Endianness endianness) {
  size_t read_size = 0;
  if (endianness == Endianness::kBigEndian) {
    link_type_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);

    // reserved
    ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);

    snap_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    link_type_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);

    // reserved
    ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);

    snap_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  if (Length() > kBlockInterfaceDescriptionMinLength) {
    read_size += ReadOptions(data + read_size, endianness);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

}  // namespace ntar