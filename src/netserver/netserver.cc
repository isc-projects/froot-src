/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include "netserver.h"

void NetserverLayer::attach(NetserverLayer& layer, uint16_t protocol)
{
	layer.layers[protocol] = this;
}

NetserverPacket::NetserverPacket(const uint8_t* buf, size_t buflen, const sockaddr* addr, socklen_t addrlen)
	: readbuf(buf, buflen), addr(addr), addrlen(addrlen)
{
	layers.reserve(5);
	iovs.reserve(5);
}
