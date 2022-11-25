// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <istream>
#include <string>

#include "byte_io.h"  // NOLINT(build/include_subdir)
#include "memory.h"   // NOLINT(build/include_subdir)

namespace ntar {

class NtarMeta : private NonCopyOrMovable {
 public:
  bool Init(std::istream *is);

  void Reset();

  bool IsAlignedTo32Bits() const { return aligned_32bits_; }

  bool IsBigEndian() const { return endianness_ == Endianness::kBigEndian; }

  bool IsLittleEndian() const {
    return endianness_ == Endianness::kLittleEndian;
  }

  uint32_t StreamLength() const { return stream_length_; }

  uint32_t PaddedLength(uint32_t length) const;

  std::string Output();

 private:
  bool AnalyzeLength(std::istream *is);

  bool AnalyzeEndianness(std::istream *is);

  bool AnalyzeAligned32Bits(std::istream *is);

  bool AnalyzeBlockLength(std::istream *is);

  bool ReAnalyzeEndianness(std::istream *is);

 private:
  bool initialized_       = false;
  bool aligned_32bits_    = true;
  bool multi_endianness_  = false;
  uint32_t stream_length_ = 0;
  uint32_t block_length_  = 0;
  Endianness endianness_  = Endianness::kUnknown;
};

typedef Singleton<NtarMeta> GlobalNtarMeta;

}  // namespace ntar
