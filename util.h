#pragma once

#include <iostream>
#include <string>
#include <netinet/ip.h>
#include <netinet/ip6.h>

extern void throw_errno(const std::string& what);
extern std::string strlower(const uint8_t* buf, size_t n);
extern void hexdump(std::ostream&, const void* buf, size_t n);

extern std::string inet_ntop(const in_addr& addr);
extern std::string inet_ntop(const in6_addr& addr);
