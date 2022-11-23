// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

#include <memory>
#include <vector>

#include "block.h"

namespace ntar {

class PcapReader {
 public:
  bool Read(const std::string &pcap_file);

 private:

};

}  // namespace ntar
