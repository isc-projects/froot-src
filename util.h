/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <iostream>
#include <string>
#include <netinet/ip.h>
#include <netinet/ip6.h>

extern void throw_errno(const std::string& what);
extern std::string strlower(const uint8_t* buf, size_t n);
extern void hexdump(std::ostream&, const void* buf, size_t n);

extern std::string inet_ntop(const in_addr& addr);
extern std::string inet_ntop(const in6_addr& addr);
