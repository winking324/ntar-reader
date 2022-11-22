// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_section_header.h"

#include "byte_io.h"

namespace ntar {

constexpr uint32_t kBlockSectionHeaderMinLength = sizeof(uint32_t) * 7;

size_t BlockSectionHeader::Read(const uint8_t *data, Endianness endianness) {
  size_t read_size = 0;
  if (endianness == Endianness::kBigEndian) {
    uint32_t byte_order = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    assert(byte_order == static_cast<uint32_t>(endianness));

    major_version_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    minor_version_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    section_length_ = ByteReader<uint64_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint64_t);
  } else {
    uint32_t byte_order =
        ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    assert(byte_order == static_cast<uint32_t>(endianness));

    major_version_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    minor_version_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    section_length_ = ByteReader<uint64_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint64_t);
  }

  if (Length() > kBlockSectionHeaderMinLength) {
    read_size += ReadOptions(data + read_size, endianness);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

}  // namespace ntar