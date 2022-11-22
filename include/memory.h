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

}  // namespace ntar
