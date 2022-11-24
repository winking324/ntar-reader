// Copyright (c) 2014-2022 Agora.io, Inc.
// Refer: https://wiki.wireshark.org/Development/PcapNg
//

#include <iostream>
#include <string>
#include <vector>

#include "pcap_reader.h"

int main(int argc, char **argv) {
  if (argc <= 1) {
    std::cout << "Usage: ./ntar-test file" << std::endl;
    return -1;
  }

  ntar::PcapReader reader;
  std::string file_name(argv[1]);
  std::cout << "--- Test: " << file_name << " ---\n";
  if (!reader.Read(file_name)) {
    std::cout << "Error reading." << std::endl;
    return -1;
  }

  return 0;
}
