// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <string>

#include "block.h"  // NOLINT(build/include_subdir)

namespace ntar {

class PcapReader {
 public:
  bool Read(const std::string &pcap_file);
};

}  // namespace ntar
