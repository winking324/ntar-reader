// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "pcap_reader.h"  // NOLINT(build/include_subdir)

#include <fstream>
#include <iostream>
#include <memory>

#include "ntar_meta.h"  // NOLINT(build/include_subdir)
#include "section.h"    // NOLINT(build/include_subdir)

namespace ntar {

bool PcapReader::Read(const std::string &pcap_file) {
  std::ifstream ifs(pcap_file, std::ios::binary | std::ios::in);
  if (!ifs.is_open()) {
    return false;
  }

  GlobalNtarMeta::Instance()->Reset();
  size_t read_size;
  do {
    Section section;
    read_size = section.Read(&ifs);
    if (read_size > 0) {
      std::cout << section.Output();
    }
  } while (read_size != 0);
  return true;
}

}  // namespace ntar
