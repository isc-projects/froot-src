#pragma once

#include <cstdint>

class Buffer {

protected:

	uint8_t*		_base;
	size_t			_size;
	size_t			_position;

protected:
	Buffer(uint8_t* base, size_t size);

public:
	size_t size() const;
	size_t position() const;
	size_t available() const;
	void reset();
};

class ReadBuffer : public Buffer {

public:
	ReadBuffer(const uint8_t* base, size_t size);

public:
	const void* base() const;
	const uint8_t* current() const;
	const uint8_t* read(size_t n);

	template<typename T> const T& read();
	template<typename T> const T* read_array(size_t n);

	const uint8_t& operator[](size_t x) const;
};

class WriteBuffer : public Buffer {

public:
	WriteBuffer(const uint8_t* base, size_t size);

public:
	void* base() const;
	uint8_t* write(size_t n);

	template<typename T> T& write();
	template<typename T> T* write_array(size_t n);

	uint8_t& operator[](size_t x) const;
};

inline Buffer::Buffer(uint8_t* base, size_t size) : _base(base), _size(size), _position(0)
{
}

inline ReadBuffer::ReadBuffer(const uint8_t* base, size_t size)
	: Buffer(const_cast<uint8_t*>(base), size)
{
}

inline WriteBuffer::WriteBuffer(const uint8_t* base, size_t size)
	: Buffer(const_cast<uint8_t*>(base), size)
{
}

#if 0
inline ReadBuffer& ReadBuffer::operator=(const Buffer& rhs)
{
	_base = const_cast<uint8_t*>(rhs.base());
	_size = rhs.size();
	_position = rhs.position();

	return *this;
}
#endif

inline void Buffer::reset() {
	_position = 0;
};

inline size_t Buffer::size() const {
	return _size;
}

inline size_t Buffer::position() const {
	return _position;
}

inline size_t Buffer::available() const {
	return _size - _position;
}

inline const void* ReadBuffer::base() const {
	return _base;
}

inline void* WriteBuffer::base() const {
	return _base;
}

inline const uint8_t* ReadBuffer::current() const {
	return _base + _position;
}

inline const uint8_t& ReadBuffer::operator[](size_t x) const {
	return _base[x];
}

inline const uint8_t* ReadBuffer::read(size_t n) {
	auto p = _base + _position;
	_position += n;
	return p;
}

template<typename T>
const T& ReadBuffer::read() {
	return *read_array<T>(1);
}

template<typename T>
const T* ReadBuffer::read_array(size_t n) {
	return reinterpret_cast<const T*>(read(n * sizeof(T)));
}

inline uint8_t& WriteBuffer::operator[](size_t x) const {
	return _base[x];
}

inline uint8_t* WriteBuffer::write(size_t n) {
	auto p = _base + _position;
	_position += n;
	return p;
}

template<typename T>
T& WriteBuffer::write() {
	return *write_array<T>(1);
}

template<typename T>
T* WriteBuffer::write_array(size_t n) {
	return reinterpret_cast<T*>(write(n * sizeof(T)));
}
