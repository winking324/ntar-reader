// Copyright (c) winking324
// Refer: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
//

#pragma once  // NOLINT(build/header_guard)

namespace ntar {

class NonCopyOrMovable {
 protected:
  NonCopyOrMovable() {}
  ~NonCopyOrMovable() {}

 private:
  NonCopyOrMovable(const NonCopyOrMovable &)            = delete;
  NonCopyOrMovable(NonCopyOrMovable &&)                 = delete;
  NonCopyOrMovable &operator=(const NonCopyOrMovable &) = delete;
  NonCopyOrMovable &operator=(NonCopyOrMovable &&)      = delete;
};

template <class T>
class Singleton : private NonCopyOrMovable {
 public:
  static T *Instance() {
    static T inst;
    return &inst;
  }

  Singleton()  = delete;
  ~Singleton() = delete;
};

}  // namespace ntar
