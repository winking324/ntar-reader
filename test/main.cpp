// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "pcap_reader.h"

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  ntar::PcapReader reader;
  reader.Read("/path/to/file.pcapng");
  return 0;
}
