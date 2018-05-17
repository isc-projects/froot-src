#include <system_error>
#include <cerrno>

#include "util.h"

void throw_errno(const std::string& what)
{
	throw std::system_error(errno, std::system_category(), what);
}

static uint8_t lower(uint8_t c)
{
	if (c < 'A' || c > 'Z') {
		return c;
	} else {
		return c | 0x20;
	}
}

std::string strlower(const uint8_t* p, size_t n)
{
	std::string result;
	std::transform(p, p + n, std::back_inserter(result), lower);
	return result;
}
