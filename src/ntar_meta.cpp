// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "ntar_meta.h"  // NOLINT(build/include_subdir)

#include <algorithm>
#include <sstream>
#include <vector>

#include "block.h"  // NOLINT(build/include_subdir)

namespace ntar {

bool NtarMeta::Init(std::istream *is) {
  if (initialized_) {
    if (!multi_endianness_) {
      return true;
    }
    return ReAnalyzeEndianness(is);
  }

  initialized_ = true;
  is->clear();
  is->seekg(0, std::ios::beg);

  typedef bool (NtarMeta::*AnalyzeHandler)(std::istream *);
  static const std::vector<AnalyzeHandler> kAnalyzeHandlers = {
      &NtarMeta::AnalyzeLength,
      &NtarMeta::AnalyzeEndianness,
      &NtarMeta::AnalyzeAligned32Bits,
      &NtarMeta::AnalyzeBlockLength,
  };
  return std::all_of(kAnalyzeHandlers.begin(), kAnalyzeHandlers.end(),
                     [&](AnalyzeHandler handler) {
                       auto r = (this->*(handler))(is);
                       is->clear();
                       is->seekg(0, std::ios::beg);
                       return r;
                     });
}

void NtarMeta::Reset() {
  initialized_    = false;
  aligned_32bits_ = true;
  stream_length_  = 0;
  block_length_   = 0;
  endianness_     = Endianness::kUnknown;
}

uint32_t NtarMeta::PaddedLength(uint32_t length) const {
  if (!IsAlignedTo32Bits()) {
    return length;
  }
  return length % 4 == 0 ? length : (length / 4 + 1) * 4;
}

std::string NtarMeta::Output() {
  std::stringstream ss;
  ss << "[NTAR] Meta:\n"
     << "\tStreamLength: " << StreamLength() << "\n"
     << "\tTotalBlockLength: " << block_length_ << "\n"
     << "\tEndianness: " << (IsBigEndian() ? "Big\n" : "Little\n")
     << "\tIsAlignedTo32Bits: " << (IsAlignedTo32Bits() ? "Yes\n" : "No\n");
  return ss.str();
}

bool NtarMeta::AnalyzeLength(std::istream *is) {
  is->seekg(0, std::ios::end);
  stream_length_ = is->tellg();
  return true;
}

bool NtarMeta::AnalyzeEndianness(std::istream *is) {
  uint32_t endianness;
  is->seekg(static_cast<int>(sizeof(uint32_t) * 2), std::ios::beg);
  is->read(reinterpret_cast<char *>(&endianness), sizeof(uint32_t));
  if (is->eof()) {
    return false;
  }

  if (endianness != Endianness::kBigEndian &&
      endianness != Endianness::kLittleEndian) {
    return false;
  }
  endianness_ = static_cast<Endianness>(endianness);
  return true;
}

bool NtarMeta::AnalyzeAligned32Bits(std::istream *is) {
  if (stream_length_ % 4 != 0) {
    aligned_32bits_ = false;
    return true;
  }

  bool all_block_aligned_32bits = true;
  while (!is->eof()) {
    uint32_t type, length;
    if (IsBigEndian()) {
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
      break;
    }

    if (type == BlockType::kSectionHeader) {
      // Note: endianness may be changed for each section
      // Refer to pcapng-test-generator/output_le/difficult/test202.txt
      uint32_t endianness;
      is->read(reinterpret_cast<char *>(&endianness), sizeof(uint32_t));
      if (endianness != endianness_) {
        printf("Warn: Section endianness changed.\n");
        multi_endianness_ = true;
        endianness_       = static_cast<Endianness>(endianness);
        length            = SwapEndian(length);
      }
    }

    if (length % 4 != 0) {
      all_block_aligned_32bits = false;
    }

    block_length_ += length;
    if (block_length_ == stream_length_) {
      break;
    }

    is->seekg(block_length_, std::ios::beg);
  }

  if (block_length_ != stream_length_) {
    // Block length may be a fault value, such as `test006.ntar` from
    // https://wiki.wireshark.org/Development/PcapNg
    aligned_32bits_ = true;
    return true;
  }

  aligned_32bits_ = all_block_aligned_32bits;
  return true;
}

bool NtarMeta::AnalyzeBlockLength(std::istream *is) {
  if (block_length_ == stream_length_) {
    return true;
  }

  uint32_t block_length = 0;
  while (!is->eof()) {
    uint32_t type, length;
    if (IsBigEndian()) {
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
      break;
    }

    if (type == BlockType::kSectionHeader) {
      // Note: endianness may be changed for each section
      // Refer to pcapng-test-generator/output_le/difficult/test202.txt
      uint32_t endianness;
      is->read(reinterpret_cast<char *>(&endianness), sizeof(uint32_t));
      if (endianness != endianness_) {
        printf("Warn: Section endianness changed.\n");
        multi_endianness_ = true;
        endianness_       = static_cast<Endianness>(endianness);
        length            = SwapEndian(length);
      }
    }

    uint32_t padded_length = PaddedLength(length);
    // printf("Block Type %u, Length: %u, Padded Length: %u\n", type, length,
    //       padded_length);

    block_length += padded_length;
    if (block_length >= stream_length_) {
      break;
    }

    is->seekg(block_length, std::ios::beg);
  }

  block_length_ = block_length;
  return block_length_ == stream_length_;
}

bool NtarMeta::ReAnalyzeEndianness(std::istream *is) {
  auto pos = is->tellg();
  uint32_t type, length;
  if (IsBigEndian()) {
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
    return false;
  }

  if (type != BlockType::kSectionHeader) {
    printf("Error: Should start with SectionHeaderBlock.\n");
    return false;
  }

  // Note: endianness may be changed for each section
  // Refer to pcapng-test-generator/output_le/difficult/test202.txt
  uint32_t endianness;
  is->read(reinterpret_cast<char *>(&endianness), sizeof(uint32_t));
  if (endianness != endianness_) {
    printf("Warn: Section endianness changed.\n");
    endianness_ = static_cast<Endianness>(endianness);
  }

  is->seekg(pos);
  return true;
}

}  // namespace ntar
