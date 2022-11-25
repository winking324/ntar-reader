# ntar-reader

Reader for NTAR(Network Trace Archival and Retrieval).

## Features

Block types:

| BlockType | BlockName | Status |
| --- | --- | --- |
| 0x00000001 | Interface Description Block | ✅ |
| 0x00000002 | Packet Block | ✅ |
| 0x00000003 | Simple Packet Block | ✅ |
| 0x00000004 | Name Resolution Block | ✅ |
| 0x00000005 | Interface Statistics Block | ✅ |
| 0x00000006 | Enhanced Packet Block | ✅ |
| 0x0000000A | Decryption Secrets Block | ✅ |
| 0x00000BAD | Custom Block(Copiable) | ✅ |
| 0x40000BAD | Custom Block | ✅ |
| 0x0A0D0D0A | Section Header Block | ✅ |

Others:

1. ✅ multiple SHB sections.
2. ✅ multiple SHB sections of different endianness.
3. ✅ packet data not padded to 32bits.
4. ❎ multiple SHB sections of different padding(32bits).

## Refer to

- [PcapNg WiKi](https://wiki.wireshark.org/Development/PcapNg)
- [PCAP Next Generation Dump File Format](https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html)
- [NTAR Library](https://github.com/winking324/NTAR)
- [pcapng-test-generator](https://github.com/hadrielk/pcapng-test-generator)
- [PcapNg Repo](https://github.com/pcapng/pcapng)
- [PCAP Next Generation (pcapng) Capture File Format](https://pcapng.github.io/pcapng/draft-tuexen-opsawg-pcapng.txt)

