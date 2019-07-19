/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <iostream>
#include <thread>

#include <sys/stat.h>

#include "context.h"
#include "netserver/tcp.h"
#include "server.h"
#include "thread.h"
#include "timer.h"
#include "util.h"

//---------------------------------------------------------------------

void DNSServer::recv(NetserverPacket& p) const
{
	bool tcp = (p.l4 == IPPROTO_TCP);

	Context ctx(zone);
	auto    reply = ctx.execute(p.readbuf, p.iovs, tcp);

	// consume the rest of the inbound TCP segment so it can be ACK'd.
	if (tcp) {
		(void)p.readbuf.read<uint8_t>(p.readbuf.available());
	}

	if (reply) {
		send_up(p);
	}
}

//---------------------------------------------------------------------

void DNSServer::loader_thread(std::string filename, bool compress)
{
	timespec    mtim = {0, 0};
	struct stat st;
	bool	first = true;

	while (true) {
		int res = ::stat(filename.c_str(), &st);
		if (first || (res == 0 && !(st.st_mtim == mtim))) {
			try {
				zone.load(filename, compress);
				mtim = st.st_mtim;
			} catch (std::exception& e) {
				std::cerr << "error: " << e.what() << std::endl;
			}
		}
		first = false;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void DNSServer::load(const std::string& filename, bool compress)
{
	auto t = std::thread(&DNSServer::loader_thread, this, filename, compress);
	thread_setname(t, "zone-loader");
	t.detach();
}

void DNSServer::load_sync(const std::string& filename, bool compress)
{
	zone.load(filename, compress, false);
}
