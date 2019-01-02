/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <system_error>
#include <cerrno>

#include <arpa/inet.h>

#include "util.h"

// potentially branchless conversion to lower-case
uint8_t lower(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
}

std::string strlower(const uint8_t* p, size_t n)
{
	std::string result(reinterpret_cast<const char*>(p), n);
	std::transform(result.cbegin(), result.cend(), result.begin(), lower);
	return result;
}

void throw_errno(const std::string& what)
{
	throw std::system_error(errno, std::system_category(), what);
}

void hexdump(std::ostream& os, const void* buf, size_t n)
{
	auto p = reinterpret_cast<const uint8_t*>(buf);

	using namespace std;

	ios init(nullptr);
	init.copyfmt(os);

	os << hex;
	for (auto i = 0U; i < n; i += 16) {

		auto j = 0U, x = i;

		os << setw(4) << setfill('0') << i << " ";
		for ( ; j < 16 && x < n; ++j, ++x) {
			os << setw(2) << (uint16_t)p[x] << " ";
		}
		for ( ; j < 16; ++j) {
			os << "   ";
		}

		j = 0; x = i;
		for ( ; j < 16 && x < n; ++j, ++x) {
			auto c = p[x];
			if (c < ' ' || c > 127) c = '.';
			os << c;
		}
		os << endl;
	}
	os << endl;
	os.copyfmt(init);
}

std::string inet_ntop(const in_addr& addr)
{
	char buf[INET_ADDRSTRLEN];
	auto res = ::inet_ntop(AF_INET, &addr, buf, sizeof buf);
	if (!res) {
		throw_errno("inet_ntop");
	}
	return std::string(res);
}

std::string inet_ntop(const in6_addr& addr)
{
	char buf[INET6_ADDRSTRLEN];
	auto res = ::inet_ntop(AF_INET6, &addr, buf, sizeof buf);
	if (!res) {
		throw_errno("inet_ntop");
	}
	return std::string(res);
}
