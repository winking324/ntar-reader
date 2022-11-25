// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "block_decryption_secrets.h"

#include <sstream>

#include "ntar_meta.h"

namespace ntar {

constexpr uint32_t kBlockDecryptionSecretsMinLength = sizeof(uint32_t) * 5;

size_t BlockDecryptionSecrets::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    secrets_type_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
    secrets_length_ = ByteReader<uint32_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint32_t);
  } else {
    secrets_type_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
    secrets_length_ = ByteReader<uint32_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint32_t);
  }

  uint32_t padded_length =
      GlobalNtarMeta::Instance()->PaddedLength(secrets_length_);
  if (padded_length > Length()) {
    return 0;
  }

  if (secrets_length_ > 0) {
    data_.resize(secrets_length_);
    std::copy(data + read_size, data + read_size + secrets_length_,
              data_.begin());
    read_size += padded_length;
  }

  if (Length() > padded_length + kBlockDecryptionSecretsMinLength) {
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

std::string BlockDecryptionSecrets::Output() {
  static const std::map<uint16_t, std::pair<std::string, kOutputPtr>>
      kOptionTypeName = {
          {kComment, {"Comment", &Option::OutputStringData}},
      };

  std::stringstream oss;
  oss << "[Block]Decryption Secrets: \n"
      << "\tSecretsType: " << secrets_type_ << "\n"
      << "\tSecretsLength: " << secrets_length_ << "\n";
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