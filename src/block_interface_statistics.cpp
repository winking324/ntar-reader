// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_interface_statistics.h"  // NOLINT(build/include_subdir)

#include <sstream>

#include "ntar_meta.h"  // NOLINT(build/include_subdir)

namespace ntar {

constexpr uint32_t kBlockInterfaceStatisticsMinLength = sizeof(uint32_t) * 6;

size_t BlockInterfaceStatistics::Read(const uint8_t *data) {
  size_t read_size = 0;
  uint64_t ts_high, ts_low;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    id_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_high = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    id_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_high = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    ts_low = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  ts_ = ts_high << 32 | ts_low;
  if (Length() > kBlockInterfaceStatisticsMinLength) {
    read_size += ReadOptions(data + read_size);
  }

  read_size += sizeof(uint32_t);
  if (GlobalNtarMeta::Instance()->PaddedLength(Length()) != read_size + 8) {
    printf("Warn: Packet[%u] not totally read[%u].\n", Length(),
           static_cast<uint32_t>(read_size + 8));
    read_size = GlobalNtarMeta::Instance()->PaddedLength(Length()) - 8;
  }
  return read_size;
}

std::string BlockInterfaceStatistics::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
          {kStartTime, {"Start Time", &Option::OutputUint64Data}},
          {kEndTime, {"End Time", &Option::OutputUint64Data}},
          {kIfRecv, {"Interface Received", &Option::OutputUint64Data}},
          {kIfDrop, {"Interface Dropped", &Option::OutputUint64Data}},
          {kFilterAccept, {"Filter Accepted", &Option::OutputUint64Data}},
          {kOsDrop, {"OS Dropped", &Option::OutputUint64Data}},
          {kUserDeliver, {"Delivered to User", &Option::OutputUint64Data}},
      };

  std::ostringstream oss;
  oss << "[Block]Interface Statistics: \n"
      << "\tInterfaceId: " << id_ << "\n"
      << "\tTimestamp: " << ts_ << "\n";
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
