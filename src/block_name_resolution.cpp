// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_name_resolution.h"

namespace ntar {

constexpr uint32_t kBlockNameResolutionMinLength = sizeof(uint32_t) * 3;

size_t BlockNameResolution::Read(const uint8_t *data, Endianness endianness) {
  size_t read_size = 0;
  if (Length() > kBlockNameResolutionMinLength) {
    read_size += ReadRecords(data + read_size, endianness);
  }

  if (Length() > read_size + kBlockNameResolutionMinLength) {
    read_size += ReadOptions(data + read_size, endianness);
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

size_t BlockNameResolution::ReadRecords(const uint8_t *data,
                                        ntar::Endianness endianness) {
  size_t read_size = 0;
  while (true) {
    std::unique_ptr<Record> record{new Record()};
    read_size += record->Read(data + read_size, endianness);
    if (record->Length() == 0 && record->Type() == RecordType::kEndOfRecord) {
      // Do not add the end record to records
      break;
    }
    records_.push_back(std::move(record));
  }
  return read_size;
}

}  // namespace ntar
