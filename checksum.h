#pragma once

#include <cstddef>
#include <cstdint>

class Checksum {

private:
	uint32_t sum;

public:
	Checksum(const void* p, size_t len);

public:
	void add(const void* p, size_t len);
	uint16_t value() const;

};
