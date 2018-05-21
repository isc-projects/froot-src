#pragma once

#include <iostream>
#include <string>

extern void throw_errno(const std::string& what);
extern std::string strlower(const uint8_t* buf, size_t n);
extern void hexdump(std::ostream&, const uint8_t* buf, size_t n);
