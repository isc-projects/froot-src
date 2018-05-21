#include <iostream>
#include <iomanip>
#include <algorithm>
#include <system_error>
#include <cerrno>

#include "util.h"

// potentially branchless conversion to lower-case
uint8_t lower(uint8_t c)
{
	return c | ((c >= 'A' && c <= 'Z') * 0x20);
}

std::string strlower(const uint8_t* p, size_t n)
{
	std::string result;
	result.resize(n);
	std::transform(p, p + n, result.begin(), lower);
	return result;
}

void throw_errno(const std::string& what)
{
	throw std::system_error(errno, std::system_category(), what);
}

void hexdump(std::ostream& os, const uint8_t* buf, size_t n)
{
	using namespace std;

	ios init(nullptr);
	init.copyfmt(os);

	os << hex;
	for (auto i = 0U; i < n; i += 16) {

		auto j = 0U, x = i;

		os << setw(4) << setfill('0') << i << " ";
		for ( ; j < 16 && x < n; ++j, ++x) {
			os << setw(2) << (uint16_t)buf[x] << " ";
		}
		for ( ; j < 16; ++j) {
			os << "   ";
		}

		j = 0; x = i;
		for ( ; j < 16 && x < n; ++j, ++x) {
			auto c = buf[x];
			if (c < ' ' || c > 127) c = '.';
			os << c;
		}
		os << endl;
	}
	os << endl;
	os.copyfmt(init);
}
