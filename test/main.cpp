// Copyright (c) 2014-2022 Agora.io, Inc.
// Refer: https://wiki.wireshark.org/Development/PcapNg
//

#include "pcap_reader.h"

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  ntar::PcapReader reader;
  reader.Read("/path/to/file.pcapng");
  return 0;
}
