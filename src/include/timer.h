/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

/*
 * timer.h
 */

#pragma once

#include <time.h>
#include <iostream>
#include <string>

std::ostream& operator<<(std::ostream& os, const timespec& ts);

extern timespec operator-(const timespec& a, const timespec& b);
extern timespec operator+(const timespec& a, const timespec& b);
extern timespec operator+(const timespec& a, const uint64_t ns);

constexpr inline bool operator==(const timespec& a, const timespec& b)
{
	return (a.tv_sec == b.tv_sec) && (a.tv_nsec == b.tv_nsec);
}

constexpr inline bool operator!=(const timespec& a, const timespec& b)
{
	return !(a == b);
}
