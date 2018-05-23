#pragma once

#include <cstdint>

class Buffer {

private:

	uint8_t*		_base;
	size_t			_size;
	size_t			_offset;

public:
	Buffer(uint8_t* base, size_t size);

public:
	size_t size() const;
	size_t used() const;
	size_t available() const;

	uint8_t* reserve(size_t n);
	uint8_t* current() const;

	uint8_t& operator[](size_t x) const;

	template<typename T> T& reserve_ref();
	template<typename T> T& current_ref() const;

	template<typename T> T* reserve();
	template<typename T> T* current() const;
};

inline Buffer::Buffer(uint8_t* base, size_t size) : _base(base), _size(size), _offset(0)
{
}

inline uint8_t* Buffer::reserve(size_t n)
{
	auto p = _base + _offset;
	_offset += n;
	return p;
}

inline uint8_t* Buffer::current() const {
	return _base + _offset;
}

inline size_t Buffer::size() const {
	return _size;
}

inline size_t Buffer::used() const {
	return _offset;
}

inline size_t Buffer::available() const {
	return _size - _offset;
}

inline uint8_t& Buffer::operator[](size_t x) const {
	return _base[x];
}

template<typename T>
T& Buffer::reserve_ref() {
	return *reinterpret_cast<T*>(reserve(sizeof(T)));
}

template<typename T>
T& Buffer::current_ref() const {
	return *reinterpret_cast<T*>(current());
}

template<typename T>
T* Buffer::reserve() {
	return reinterpret_cast<T*>(reserve(sizeof(T)));
}

template<typename T>
T* Buffer::current() const {
	return reinterpret_cast<T*>(current());
}
