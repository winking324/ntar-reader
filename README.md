# ntar-reader

Reader for NTAR(Network Trace Archival and Retrieval).

| BlockType | BlockName | Status |
| --- | --- | --- |
| 0x00000001 | Interface Description Block | ✅ |
| 0x00000002 | Packet Block | ✅ |
| 0x00000003 | Simple Packet Block | ✅ |
| 0x00000004 | Name Resolution Block | ✅ |
| 0x00000005 | Interface Statistics Block | ✅ |
| 0x00000006 | Enhanced Packet Block | ✅ |
| 0x0A0D0D0A | Section Header Block | ✅ |

## Refer to

- [PcapNg](https://wiki.wireshark.org/Development/PcapNg)
- [PCAP Next Generation Dump File Format](https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html)
- [NTAR Library](https://github.com/winking324/NTAR)
- [pcapng-test-generator](https://github.com/hadrielk/pcapng-test-generator)
