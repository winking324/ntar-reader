// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#include "option.h"

#include <cassert>

#include "ntar_meta.h"

namespace ntar {

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
  auto f = [](uint8_t d) { return std::to_string(static_cast<uint32_t>(d)); };
  std::string o =
      f(data_[0]) + "." + f(data_[1]) + "." + f(data_[2]) + "." + f(data_[3]);
  if (data_.size() > 4) {
    o += "/" + f(data_[4]) + "." + f(data_[5]) + "." + f(data_[6]) + "." +
         f(data_[7]);
  }
  return o;
}

std::string Option::OutputIpv6Data() {
  assert(data_.size() == 16 || data_.size() == 17);
  auto f = [](uint8_t d) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string o;
    o.push_back(kHex[d >> 4]);
    o.push_back(kHex[d & 0x0F]);
    return o;
  };

  std::string o = f(data_[0]) + f(data_[1]) + ":" + f(data_[2]) + f(data_[3]) +
                  ":" + f(data_[4]) + f(data_[5]) + ":" + f(data_[6]) +
                  f(data_[7]) + ":" + f(data_[8]) + f(data_[9]) + ":" +
                  f(data_[10]) + f(data_[11]) + ":" + f(data_[12]) +
                  f(data_[13]) + ":" + f(data_[14]) + f(data_[15]);
  if (data_.size() > 16) {
    o += "/" + f(data_[16]);
  }
  return o;
}

std::string Option::OutputHexData() {
  static const char kHex[] = "0123456789ABCDEF";
  std::string o;
  o.reserve(data_.size() * 2);
  for (auto d : data_) {
    o.push_back(kHex[d >> 4]);
    o.push_back(kHex[d & 0x0F]);
  }
  return o;
}

}  // namespace ntar
