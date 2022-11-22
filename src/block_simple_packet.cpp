// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_simple_packet.h"

namespace ntar {

constexpr uint32_t kBlockSimplePacketMinLength = sizeof(uint32_t) * 4;

size_t BlockSimplePacket::Read(const uint8_t *data, Endianness endianness) {
  size_t read_size = 0;
  if (endianness == Endianness::kBigEndian) {
    packet_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    packet_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  if (Length() > kBlockSimplePacketMinLength) {
    uint32_t packet_data_length = Length() - kBlockSimplePacketMinLength;
    // variable length, aligned to 32 bits
    assert(packet_data_length % 4 == 0);

    data_.resize(packet_data_length);
    std::copy(data + read_size, data + read_size + packet_data_length,
              data_.begin());
    read_size += packet_data_length;
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

}  // namespace ntar
