// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "section.h"

#include <map>

#include "block_enhanced_packet.h"
#include "block_interface_description.h"
#include "block_interface_statistics.h"
#include "block_name_resolution.h"
#include "block_packet.h"
#include "block_section_header.h"
#include "block_simple_packet.h"

namespace ntar {

size_t Section::Read(std::istream *is) {
  uint32_t type, size, endianness;
  is->read(reinterpret_cast<char *>(&type), sizeof(uint32_t));
  if (type != BlockType::kSectionHeader) {
    return 0;
  }

  is->read(reinterpret_cast<char *>(&size), sizeof(uint32_t));
  is->read(reinterpret_cast<char *>(&endianness), sizeof(uint32_t));
  if (is->eof()) {
    return 0;
  }

  if (endianness != Endianness::kBigEndian &&
      endianness != Endianness::kLittleEndian) {
    return 0;
  }

  is->seekg(-static_cast<int>(sizeof(uint32_t) * 3), std::ios::cur);
  size_t block_size;
  size_t section_size = 0;
  do {
    block_size = ReadBlock(is, static_cast<Endianness>(endianness));
    section_size += block_size;
  } while (block_size != 0);
  return section_size;
}

size_t Section::ReadBlock(std::istream *is, Endianness endianness) {
  uint32_t type, length;
  if (endianness == Endianness::kBigEndian) {
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

  if (type == BlockType::kSectionHeader && !blocks_.empty()) {
    is->seekg(-static_cast<int>(sizeof(uint32_t) * 2), std::ios::cur);
    return 0;
  }

  std::vector<uint8_t> data;
  data.resize(length - sizeof(uint32_t) * 2);
  is->read(reinterpret_cast<char *>(&data[0]), data.size());
  if (is->eof()) {
    return 0;
  }

  std::unique_ptr<Block> block = CreateBlock(type, length, endianness);
  if (block) {
    size_t read_size = block->Read(data.data());
    if (read_size == 0) {
      // TODO(winking324): read error here
    }
    blocks_.push_back(std::move(block));
  }
  return length;
}

std::unique_ptr<Block> Section::CreateBlock(uint32_t type, uint32_t length,
                                            Endianness endianness) {
  const static std::map<uint32_t, BlockCtreatorPtr> kCreator = {
      {BlockType::kInterfaceDescription,
       BlockCreator<BlockInterfaceDescription>::New},
      {BlockType::kPacket, BlockCreator<BlockPacket>::New},
      {BlockType::kSimplePacket, BlockCreator<BlockSimplePacket>::New},
      {BlockType::kNameResolution, BlockCreator<BlockNameResolution>::New},
      {BlockType::kInterfaceStatistics,
       BlockCreator<BlockInterfaceStatistics>::New},
      {BlockType::kEnhancedPacket, BlockCreator<BlockEnhancedPacket>::New},
      {BlockType::kSectionHeader, BlockCreator<BlockSectionHeader>::New},
  };

  auto it = kCreator.find(type);
  if (it == kCreator.end()) {
    return nullptr;
  }

  return std::unique_ptr<Block>(it->second(length, endianness));
}

}  // namespace ntar