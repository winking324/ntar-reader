// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_interface_description.h"

#include <sstream>

namespace ntar {

constexpr uint32_t kBlockInterfaceDescriptionMinLength = sizeof(uint32_t) * 5;

size_t BlockInterfaceDescription::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (endianness_ == Endianness::kBigEndian) {
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
    read_size += ReadOptions(data + read_size);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

std::string BlockInterfaceDescription::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
          {kName, {"Name", &Option::OutputStringData}},
          {kDescription, {"Description", &Option::OutputStringData}},
          {kIpv4Address, {"IPv4 Address", &Option::OutputIpv4Data}},
          {kIpv6Address, {"IPv6 Address", &Option::OutputIpv6Data}},
          {kMacAddress, {"MAC Address", &Option::OutputHexData}},
          {kEuiAddress, {"EUI Address", &Option::OutputHexData}},
          {kSpeed, {"Speed", &Option::OutputUint64Data}},
          {kTsResolution, {"Timestamp Resolution", &Option::OutputUint8Data}},
          {kTimeZone, {"Time Zone", &Option::OutputUint32Data}},
          {kFilter, {"Filter", &Option::OutputStringData}},
          {kOs, {"OS", &Option::OutputStringData}},
          {kFrameCheckSequenceLength,
           {"Frame Check Sequence Length", &Option::OutputUint8Data}},
          {kTsOffset, {"Timestamp Offset", &Option::OutputUint64Data}},
      };

  std::ostringstream oss;
  oss << "[Block]Interface Description: \n"
      << "\tLinkType: " << link_type_ << "\n"
      << "\tSnapLength: " << snap_length_ << "\n";
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
