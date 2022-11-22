// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "option.h"

#include <cassert>

namespace ntar {

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Option Code              |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Option Value                            /
// /          /* variable length, aligned to 32 bits */            /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                 . . . other options . . .                     /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Option Code == opt_endofopt  |  Option Length == 0          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

size_t Option::Read(const uint8_t *data, Endianness endianness) {
  size_t read_size = 0;
  if (endianness == Endianness::kBigEndian) {
    code_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    length_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
  } else {
    code_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    length_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
  }

  data_.resize(length_);
  std::copy(data + read_size, data + read_size + length_, data_.begin());

  uint32_t padded_length = length_ % 4 == 0 ? length_ : (length_ / 4 + 1) * 4;
  read_size += padded_length;
  return read_size;
}

}  // namespace ntar
