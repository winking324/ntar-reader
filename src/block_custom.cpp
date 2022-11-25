// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_custom.h"  // NOLINT(build/include_subdir)

#include <cassert>
#include <sstream>

#include "ntar_meta.h"  // NOLINT(build/include_subdir)

namespace ntar {

constexpr uint32_t kBlockCustomMinLength = sizeof(uint32_t) * 4;

size_t BlockCustom::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    private_enterprise_no_ =
        ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    private_enterprise_no_ =
        ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  if (Length() > kBlockCustomMinLength) {
    uint32_t packet_data_length = Length() - kBlockCustomMinLength;
    data_.resize(packet_data_length);
    std::copy(data + read_size, data + read_size + packet_data_length,
              data_.begin());
    read_size += packet_data_length;
  }

  read_size += sizeof(uint32_t);
  assert(Length() == read_size + 8);
  return read_size;
}

std::string BlockCustom::Output() {
  std::ostringstream oss;
  oss << "[Block]Custom: \n"
      << "\tPrivateEnterpriseNumber: " << private_enterprise_no_ << "\n";
  return oss.str();
}

std::string BlockCustomCopiable::Output() {
  std::ostringstream oss;
  oss << "[Block]Custom(Copiable): \n"
      << "\tPrivateEnterpriseNumber: " << private_enterprise_no_ << "\n";
  return oss.str();
}

}  // namespace ntar
