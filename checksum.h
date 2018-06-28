#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>

class Checksum {

private:
	uint32_t sum = 0;

public:
	Checksum& add(const void* p, size_t len);
	Checksum& add(const iovec& iov);
	Checksum& add(uint16_t n);
	uint16_t value() const;

};

inline uint16_t Checksum::value() const
{
	uint32_t tmp = sum;
	while (tmp >> 16) {
		tmp = (tmp & 0xffff) + (tmp >> 16);
	}
	tmp = ~tmp;

	return static_cast<uint16_t>(tmp);
}

inline Checksum& Checksum::add(const void* p, size_t n)
{
        auto w = reinterpret_cast<const uint16_t*>(p);
        while (n > 1) {
                sum += *w++;
		n -= 2;
        }

	if (n) {
		auto* q = reinterpret_cast<const char *>(w);
		sum += ntohl(*q);
	}

	return *this;
}

inline Checksum& Checksum::add(const iovec& iov)
{
	return add(iov.iov_base, iov.iov_len);
}

inline Checksum& Checksum::add(uint16_t n)
{
	sum += htons(n);
	return *this;
}
