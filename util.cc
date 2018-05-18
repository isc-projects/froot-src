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
