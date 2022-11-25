// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "option.h"

#include <cassert>

#include "ntar_meta.h"

namespace ntar {

std::string ToHexString(uint8_t *d, size_t s) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string o;
  o.reserve(s * 2);
  for (size_t i = 0; i < s; ++i) {
    o.push_back(kHex[d[i] >> 4]);
    o.push_back(kHex[d[i] & 0x0F]);
  }
  return o;
}

std::string ToIpv4String(uint8_t *d) {
  auto f = [](uint8_t d) { return std::to_string(static_cast<uint32_t>(d)); };
  return f(d[0]) + "." + f(d[1]) + "." + f(d[2]) + "." + f(d[3]);
}

std::string ToIpv6String(uint8_t *d) {
  std::string o;
  for (size_t i = 0; i < 16; i += 2) {
    o += ToHexString(d + i, 2) + ":";
  }
  o.pop_back();
  return o;
}

size_t Option::Read(const uint8_t *data) {
  size_t read_size = 0;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    code_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
    length_ = ByteReader<uint16_t>::ReadBigEndian(data + read_size);
    read_size += sizeof(uint16_t);
  } else {
    code_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
    length_ = ByteReader<uint16_t>::ReadLittleEndian(data + read_size);
    read_size += sizeof(uint16_t);
  }

  data_.resize(length_);
  std::copy(data + read_size, data + read_size + length_, data_.begin());
  uint32_t padded_length = GlobalNtarMeta::Instance()->PaddedLength(length_);
  read_size += padded_length;
  return read_size;
}

std::string Option::OutputStringData() {
  return reinterpret_cast<const char *>(data_.data());
}

std::string Option::OutputUint8Data() {
  assert(data_.size() == sizeof(uint8_t));
  return std::to_string(static_cast<uint32_t>(
      *(reinterpret_cast<const uint8_t *>(data_.data()))));
}

std::string Option::OutputUint16Data() {
  assert(data_.size() == sizeof(uint16_t));
  uint16_t data;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    data = ByteReader<uint16_t>::ReadBigEndian(data_.data());
  } else {
    data = ByteReader<uint16_t>::ReadLittleEndian(data_.data());
  }
  return std::to_string(static_cast<uint32_t>(data));
}

std::string Option::OutputUint32Data() {
  assert(data_.size() == sizeof(uint32_t));
  uint32_t data;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    data = ByteReader<uint32_t>::ReadBigEndian(data_.data());
  } else {
    data = ByteReader<uint32_t>::ReadLittleEndian(data_.data());
  }
  return std::to_string(data);
}

std::string Option::OutputUint64Data() {
  assert(data_.size() == sizeof(uint64_t));
  uint64_t data_high, data_low;
  if (GlobalNtarMeta::Instance()->IsBigEndian()) {
    data_high = ByteReader<uint32_t>::ReadBigEndian(data_.data());
    data_low =
        ByteReader<uint32_t>::ReadBigEndian(data_.data() + sizeof(uint32_t));
  } else {
    data_high = ByteReader<uint32_t>::ReadLittleEndian(data_.data());
    data_low =
        ByteReader<uint32_t>::ReadLittleEndian(data_.data() + sizeof(uint32_t));
  }
  return std::to_string(data_high << 32 | data_low);
}

std::string Option::OutputIpv4Data() {
  assert(data_.size() == 4 || data_.size() == 8);
  std::string o = ToIpv4String(data_.data());
  if (data_.size() > 4) {
    o += "/" + ToIpv4String(&data_[4]);
  }
  return o;
}

std::string Option::OutputIpv6Data() {
  assert(data_.size() == 16 || data_.size() == 17);
  std::string o = ToIpv6String(data_.data());
  if (data_.size() > 16) {
    o += "/" + ToHexString(&data_[16], 1);
  }
  return o;
}

std::string Option::OutputIpv4RecordData() {
  assert(data_.size() > 4);
  std::string o = ToIpv4String(data_.data());
  o += " " + std::string(reinterpret_cast<char *>(&data_[4]));
  return o;
}

std::string Option::OutputIpv6RecordData() {
  assert(data_.size() > 16);
  std::string o = ToIpv6String(data_.data());
  o += " " + std::string(reinterpret_cast<char *>(&data_[16]));
  return o;
}

std::string Option::OutputHexData() {
  return ToHexString(data_.data(), data_.size());
}

}  // namespace ntar
