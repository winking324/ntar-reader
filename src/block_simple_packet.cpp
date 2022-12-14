// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_simple_packet.h"  // NOLINT(build/include_subdir)

#include <cassert>
#include <sstream>

#include "ntar_meta.h"  // NOLINT(build/include_subdir)

namespace ntar {

constexpr uint32_t kBlockSimplePacketMinLength = sizeof(uint32_t) * 4;

size_t BlockSimplePacket::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    packet_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    packet_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  if (Length() > kBlockSimplePacketMinLength) {
    uint32_t packet_data_length = Length() - kBlockSimplePacketMinLength;
    data_.resize(packet_data_length);
    std::copy(data + read_size, data + read_size + packet_data_length,
              data_.begin());
    read_size += packet_data_length;
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

std::string BlockSimplePacket::Output() {
  std::ostringstream oss;
  oss << "[Block]Simple Packet: \n"
      << "\tPacketLength: " << packet_length_ << "\n";
  return oss.str();
}

}  // namespace ntar
