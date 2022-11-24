// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_name_resolution.h"

#include <sstream>

#include "ntar_meta.h"

namespace ntar {

constexpr uint32_t kBlockNameResolutionMinLength = sizeof(uint32_t) * 3;

size_t BlockNameResolution::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (Length() > kBlockNameResolutionMinLength) {
    read_size += ReadRecords(data + read_size);
  }

  if (Length() > read_size + kBlockNameResolutionMinLength) {
    read_size += ReadOptions(data + read_size);
  }

  read_size += sizeof(uint32_t);
  assert(GlobalNtarMeta::Instance()->PaddedLength(Length()) == read_size + 8);
  return read_size;
}

size_t BlockNameResolution::ReadRecords(const uint8_t *data) {
  size_t read_size = 0;
  while (true) {
    std::unique_ptr<Record> record{new Record()};
    read_size += record->Read(data + read_size);
    if (record->Length() == 0 && record->Type() == RecordType::kEndOfRecord) {
      // Do not add the end record to records
      break;
    }
    records_.push_back(std::move(record));
  }
  return read_size;
}

std::string BlockNameResolution::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
          {kDnsName, {"DNS Name", &Option::OutputStringData}},
          {kDnsIpv4Address, {"DNS IPv4 Address", &Option::OutputIpv4Data}},
          {kDnsIpv6Address, {"DNS IPv6 Address", &Option::OutputIpv6Data}},
      };

  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kRecordTypeName = {
          {kIpv4Record, {"IPv4 Record", &Option::OutputStringData}},
          {kIpv6Record, {"IPv6 Record", &Option::OutputStringData}},
      };

  std::ostringstream oss;
  oss << "[Block]Name Resolution: \n";
  if (!records_.empty()) {
    oss << "\tRecords: \n";
    for (auto &record : records_) {
      oss << "\t\t[" << record->Type() << "]";
      auto it = kRecordTypeName.find(record->Type());
      if (it == kRecordTypeName.end()) {
        oss << ": Unsupported\n";
        continue;
      }

      oss << it->second.first;
      if (it->second.second != nullptr) {
        oss << ": " << (record.get()->*(it->second.second))();
      }
      oss << "\n";
    }
  }

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
