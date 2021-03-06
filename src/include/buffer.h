/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <cassert>
#include <cstdint>
#include <sys/socket.h> // for iovec

class Buffer {

private:
	uint8_t* _base = nullptr;
	size_t   _size = 0;
	size_t   _position = 0;

protected:
	uint8_t* allocate(size_t n);
	uint8_t& element(size_t x) const;
	Buffer(uint8_t* base, size_t size);

public:
	size_t size() const;
	size_t position() const;
	size_t available() const;
	void   reset();
};

class ReadBuffer : public Buffer {

public:
	ReadBuffer(const uint8_t* base, size_t size);
	const void* base() const;

	template <typename T> const T& read();
	template <typename T> const T* read(size_t n);

	const uint8_t& operator[](size_t x) const;
		       operator iovec() const;
};

class WriteBuffer : public Buffer {

public:
	WriteBuffer(uint8_t* base, size_t size);
	void* base() const;

	template <typename T> T& reserve();
	template <typename T> T* reserve(size_t n);

	template <typename T> T& write(const T& v);

	uint8_t& operator[](size_t x) const;
		 operator iovec() const;
};

//---------------------------------------------------------------------

inline Buffer::Buffer(uint8_t* base, size_t size) : _base(base), _size(size)
{
	assert(base);
}

inline ReadBuffer::ReadBuffer(const uint8_t* base, size_t size)
    : Buffer(const_cast<uint8_t*>(base), size)
{
}

inline WriteBuffer::WriteBuffer(uint8_t* base, size_t size) : Buffer(base, size)
{
}

//---------------------------------------------------------------------

inline void Buffer::reset()
{
	_position = 0;
}

inline size_t Buffer::size() const
{
	return _size;
}

inline size_t Buffer::position() const
{
	return _position;
}

inline size_t Buffer::available() const
{
	assert(_size >= _position);
	return _size - _position;
}

inline uint8_t* Buffer::allocate(size_t n)
{
	assert(_base);
	assert(available() >= n);
	auto* p = _base + _position;
	_position += n;
	return p;
}

//---------------------------------------------------------------------

inline const void* ReadBuffer::base() const
{
	return &element(0);
}

inline void* WriteBuffer::base() const
{
	return &element(0);
}

//---------------------------------------------------------------------

inline uint8_t& Buffer::element(size_t x) const
{
	assert(_base);
	assert(x < _size);
	return _base[x];
}

inline const uint8_t& ReadBuffer::operator[](size_t x) const
{
	return element(x);
}

inline uint8_t& WriteBuffer::operator[](size_t x) const
{
	return element(x);
}

//---------------------------------------------------------------------

template <typename T> const T* ReadBuffer::read(size_t n)
{
	return reinterpret_cast<const T*>(allocate(n * sizeof(T)));
}

template <typename T> const T& ReadBuffer::read()
{
	return *read<T>(1);
}

//---------------------------------------------------------------------

template <typename T> T* WriteBuffer::reserve(size_t n)
{
	return reinterpret_cast<T*>(allocate(n * sizeof(T)));
}

template <typename T> T& WriteBuffer::reserve()
{
	return *reserve<T>(1);
}

template <typename T> T& WriteBuffer::write(const T& v)
{
	auto* p = reserve<T>(1);
	*p = v;
	return *p;
}

//---------------------------------------------------------------------

inline ReadBuffer::operator iovec() const
{
	return iovec{const_cast<void*>(base()), size()};
}

inline WriteBuffer::operator iovec() const
{
	return iovec{base(), position()};
}

//---------------------------------------------------------------------
