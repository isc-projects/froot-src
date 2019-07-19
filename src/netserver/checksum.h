/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <sys/socket.h>

class Checksum {

private:
	uint32_t sum = 0;
	bool     odd = false;

public:
	Checksum& add(const void* p, size_t len);
	Checksum& add(const iovec& iov);
	Checksum& add(uint16_t n);
	uint16_t  value() const;
};

inline uint16_t Checksum::value() const
{
	uint32_t tmp = sum;
	while (tmp >> 16) {
		tmp = (tmp & 0xffff) + (tmp >> 16);
	}
	tmp = ~tmp;

	return static_cast<uint16_t>(htons(tmp));
}

inline Checksum& Checksum::add(const void* p, size_t n)
{
	// no data
	if (!n) return *this;

	// sweep up any LSB
	auto b = reinterpret_cast<const uint8_t*>(p);
	if (odd) {
		auto c = *b++;
		sum += c;
		odd = false;
		--n;
	}

	// then any sixteen bit words - precondition: odd == false
	auto w = reinterpret_cast<const uint16_t*>(b);
	while (n >= 2) {
		sum += htons(*w++);
		n -= 2;
	}

	// then any byte left over - precondition odd == false => MSB
	if (n) {
		b = reinterpret_cast<const uint8_t*>(w);
		auto c = *b++;
		sum += (c << 8);
		odd = true;
	}

	return *this;
}

inline Checksum& Checksum::add(const iovec& iov)
{
	return add(iov.iov_base, iov.iov_len);
}

inline Checksum& Checksum::add(uint16_t n)
{
	n = htons(n);
	add(&n, sizeof n);
	return *this;
}
