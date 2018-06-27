#include <iostream>
#include <iomanip>
#include <algorithm>
#include <system_error>
#include <cerrno>

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

uint16_t checksum(const void* p, size_t n)
{
        uint32_t sum = 0;
	n /= 2;

	// TODO: account for odd-n
        auto w = reinterpret_cast<const uint16_t*>(p);
        for (size_t i = 0; i < n; ++i) {
                sum += *w++;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        return static_cast<uint16_t>(~sum);
}
