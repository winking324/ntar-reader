// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_enhanced_packet.h"

#include <sstream>

namespace ntar {

const uint32_t kBlockEnhancedPacketMinLength = sizeof(uint32_t) * 8;

size_t BlockEnhancedPacket::Read(const uint8_t *data) {
  size_t read_size = 0;
  uint64_t ts_high, ts_low;
  if (endianness_ == Endianness::kBigEndian) {
    id_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_high = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    captured_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    packet_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    id_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
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

  if (Length() > padded_length + kBlockEnhancedPacketMinLength) {
    read_size += ReadOptions(data + read_size);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

std::string BlockEnhancedPacket::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
          {kFlags, {"Flags", &Option::OutputUint32Data}},
          {kHash, {"Hash", nullptr}},
          {kDropCount, {"DropCount", &Option::OutputUint64Data}},
      };

  std::ostringstream oss;
  oss << "[Block]Enhanced Packet: \n"
      << "\tInterfaceId: " << id_ << "\n"
      << "\tTimestamp: " << ts_ << "\n"
      << "\tCapturedLength: " << captured_length_ << "\n"
      << "\tPacketLength: " << packet_length_ << "\n";
  if (!options_.empty()) {
    oss << "\tOptions: \n";
    for (auto &opt : options_) {
      oss << "\t\t[" << opt->Code() << "]";
      auto it = kOptionTypeName.find(opt->Code());
      if (it == kOptionTypeName.end()) {
        oss << ": Unsupported\n";
        continue;
      }

      oss << it->second.first;
      if (it->second.second != nullptr) {
        oss << ": " << (opt.get()->*(it->second.second))();
      }
      oss << "\n";
    }
  }

  return oss.str();
}

}  // namespace ntar
