// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <vector>

#include "block.h"

//                            1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0 |                   Block Type = 0x0000000A                     |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    4 |                      Block Total Length                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    8 |                          Secrets Type                         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   12 |                         Secrets Length                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   16 /                                                               /
//      /                          Secrets Data                         /
//      /              (variable length, padded to 32 bits)             /
//      /                                                               /
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      /                                                               /
//      /                       Options (variable)                      /
//      /                                                               /
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      /                       Block Total Length                      /
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

namespace ntar {

enum SecretsType {
  kTls       = 0x544c534b,
  kWireGuard = 0x57474b4c,
  kZigBeeNwk = 0x5a4e574b,
  kZigBeeAps = 0x5a415053,
};

class BlockDecryptionSecrets : public Block {
 public:
  explicit BlockDecryptionSecrets(uint32_t length)
      : Block(BlockType::kDecryptionSecrets, length) {}

  size_t Read(const uint8_t *data) override;

  std::string Output() override;

  uint32_t SecretsType() const { return secrets_type_; }

  uint32_t SecretsLength() const { return secrets_length_; }

 private:
  uint32_t secrets_type_;
  uint32_t secrets_length_;
  std::vector<uint8_t> data_;
};

}  // namespace ntar
