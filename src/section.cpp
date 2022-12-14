// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "section.h"  // NOLINT(build/include_subdir)

#include <map>
#include <sstream>

#include "block_custom.h"                 // NOLINT(build/include_subdir)
#include "block_decryption_secrets.h"     // NOLINT(build/include_subdir)
#include "block_enhanced_packet.h"        // NOLINT(build/include_subdir)
#include "block_interface_description.h"  // NOLINT(build/include_subdir)
#include "block_interface_statistics.h"   // NOLINT(build/include_subdir)
#include "block_name_resolution.h"        // NOLINT(build/include_subdir)
#include "block_packet.h"                 // NOLINT(build/include_subdir)
#include "block_section_header.h"         // NOLINT(build/include_subdir)
#include "block_simple_packet.h"          // NOLINT(build/include_subdir)
#include "byte_io.h"                      // NOLINT(build/include_subdir)
#include "ntar_meta.h"                    // NOLINT(build/include_subdir)

namespace ntar {

size_t Section::Read(std::istream *is) {
  if (is->eof()) return 0;

  if (!GlobalNtarMeta::Instance()->Init(is)) {
    printf("Error: NTAR meta info init failed.\n");
    return 0;
  }

  size_t block_size;
  size_t section_size = 0;
  do {
    block_size = ReadBlock(is);
    section_size += block_size;
  } while (block_size != 0);
  return section_size;
}

std::string Section::Output() {
  std::stringstream ss;
  ss << GlobalNtarMeta::Instance()->Output();
  ss << "[Section] Block Count: " << blocks_.size() << "\n";
  for (auto &block : blocks_) {
    ss << block->Output();
  }
  return ss.str();
}

size_t Section::ReadBlock(std::istream *is) {
  uint32_t type, length;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    char buffer[sizeof(uint32_t)];
    is->read(buffer, sizeof(uint32_t));
    type = ByteReader<uint32_t>::ReadBigEndian(
        reinterpret_cast<uint8_t *>(buffer));
    is->read(buffer, sizeof(uint32_t));
    length = ByteReader<uint32_t>::ReadBigEndian(
        reinterpret_cast<uint8_t *>(buffer));
  } else {
    char buffer[sizeof(uint32_t)];
    is->read(buffer, sizeof(uint32_t));
    type = ByteReader<uint32_t>::ReadLittleEndian(
        reinterpret_cast<uint8_t *>(buffer));
    is->read(buffer, sizeof(uint32_t));
    length = ByteReader<uint32_t>::ReadLittleEndian(
        reinterpret_cast<uint8_t *>(buffer));
  }

  if (is->eof()) {
    return 0;
  }

  if (type == BlockType::kSectionHeader && !blocks_.empty()) {
    is->seekg(-static_cast<int>(sizeof(uint32_t) * 2), std::ios::cur);
    return 0;
  }
  length = GlobalNtarMeta::Instance()->PaddedLength(length);

  std::vector<uint8_t> data;
  data.resize(length - sizeof(uint32_t) * 2);
  is->read(reinterpret_cast<char *>(&data[0]), static_cast<int>(data.size()));
  if (is->eof()) {
    return 0;
  }

  std::unique_ptr<Block> block = CreateBlock(type, length);

  size_t read_size = block->Read(data.data());
  if (read_size == 0) {
    printf("Error: block type %u, length %u read failed.\n", type, length);
    return 0;
  }
  blocks_.push_back(std::move(block));
  return length;
}

std::unique_ptr<Block> Section::CreateBlock(uint32_t type, uint32_t length) {
  static const std::map<uint32_t, BlockCtreatorPtr> kCreator = {
      {BlockType::kInterfaceDescription,
       BlockCreator<BlockInterfaceDescription>::New},
      {BlockType::kPacket, BlockCreator<BlockPacket>::New},
      {BlockType::kSimplePacket, BlockCreator<BlockSimplePacket>::New},
      {BlockType::kNameResolution, BlockCreator<BlockNameResolution>::New},
      {BlockType::kInterfaceStatistics,
       BlockCreator<BlockInterfaceStatistics>::New},
      {BlockType::kEnhancedPacket, BlockCreator<BlockEnhancedPacket>::New},
      {BlockType::kSectionHeader, BlockCreator<BlockSectionHeader>::New},
      {BlockType::kDecryptionSecrets,
       BlockCreator<BlockDecryptionSecrets>::New},
      {BlockType::kCustom, BlockCreator<BlockCustom>::New},
      {BlockType::kCustomCopiable, BlockCreator<BlockCustomCopiable>::New},
  };

  auto it = kCreator.find(type);
  if (it == kCreator.end()) {
    return std::unique_ptr<Block>(new Block(type, length));
  }

  return std::unique_ptr<Block>(it->second(length));
}

}  // namespace ntar
