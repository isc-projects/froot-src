#include "checksum.h"

uint16_t Checksum::value() const
{
	uint32_t tmp = sum;
	while (tmp >> 16) {
		tmp = (tmp & 0xffff) + (tmp >> 16);
	}
	tmp = ~tmp;

	return static_cast<uint16_t>(tmp);
}

void Checksum::add(const void* p, size_t n)
{
        auto w = reinterpret_cast<const uint16_t*>(p);
        while (n > 1) {
                sum += *w++;
		n -= 2;
        }

	// how to carry over ?
}

Checksum::Checksum(const void* p, size_t n)
	: sum(0)
{
	add(p, n);
}
