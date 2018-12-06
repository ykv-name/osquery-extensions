/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <netdb.h>
#include <string>
#include <sys/socket.h>

#include <boost/algorithm/string/trim.hpp>

namespace trailofbits {
std::string ipAsString(const struct sockaddr* in) {
  char dst[INET6_ADDRSTRLEN] = {0};

  socklen_t addrlen = in->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                               : sizeof(struct sockaddr_in6);
  if (getnameinfo(in, addrlen, dst, sizeof(dst), nullptr, 0, NI_NUMERICHOST) !=
      0) {
    return "";
  }

  std::string address(dst);
  boost::algorithm::trim(address);
  return address;
}

std::string ipAsString(const struct in_addr* in) {
  struct sockaddr_in addr;
  addr.sin_addr = *in;
  addr.sin_family = AF_INET;
  addr.sin_port = 0;

  return ipAsString(reinterpret_cast<struct sockaddr*>(&addr));
}
} // namespace trailofbits
