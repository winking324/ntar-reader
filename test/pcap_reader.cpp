// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "pcap_reader.h"

#include <fstream>
#include <iostream>
#include <memory>

#include "section.h"

namespace ntar {

bool PcapReader::Read(const std::string &pcap_file) {
  std::ifstream ifs(pcap_file, std::ios::binary | std::ios::in);
  while (!ifs.eof()) {
    Section section;
    auto read_size = section.Read(&ifs);
    if (read_size == 0) {
      break;
    }

    auto &blocks = section.Blocks();
    std::cout << "Section total block count: " << blocks.size() << std::endl;
    for (auto &block : blocks) {
      std::cout << block->Output();
    }
  }
  return true;
}

}  // namespace ntar
