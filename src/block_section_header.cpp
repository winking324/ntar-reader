// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_section_header.h"

#include <sstream>

#include "byte_io.h"
#include "ntar_meta.h"

namespace ntar {

constexpr uint32_t kBlockSectionHeaderMinLength = sizeof(uint32_t) * 7;

size_t BlockSectionHeader::Read(const uint8_t *data) {
  size_t read_size = sizeof(uint32_t);  // ignore uint32_t Byte-Order Magic
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    major_version_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    minor_version_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    section_length_ = ByteReader<uint64_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint64_t);
  } else {
    major_version_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    minor_version_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    section_length_ = ByteReader<uint64_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint64_t);
  }

  if (Length() > kBlockSectionHeaderMinLength) {
    read_size += ReadOptions(data + read_size);
  }

  read_size += sizeof(uint32_t);
  assert(GlobalNtarMeta::Instance()->PaddedLength(Length()) == read_size + 8);
  return read_size;
}

std::string BlockSectionHeader::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
          {kHardware, {"Hardware", &Option::OutputStringData}},
          {kOs, {"OS", &Option::OutputStringData}},
          {kUserApplication, {"User Application", &Option::OutputStringData}},
      };

  std::ostringstream oss;
  oss << "[Block]Section Header: \n"
      << "\tVersion: " << major_version_ << "." << minor_version_ << "\n";

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