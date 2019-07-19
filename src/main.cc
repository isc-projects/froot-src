/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>

#include "netserver/afpacket.h"
#include "netserver/arp.h"
#include "netserver/icmp.h"
#include "netserver/icmpv6.h"
#include "netserver/ipv4.h"
#include "netserver/ipv6.h"
#include "netserver/tcp.h"
#include "netserver/udp.h"

#include "server.h"
#include "thread.h"
#include "util.h"

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)
static const char prefix[] = TO_STRING(PREFIX);

void usage(int result = EXIT_FAILURE)
{
	using namespace std;

	cout << "froot -i <ifname> -s <ipaddr> [-f <zonefile>] [-T <threads>]" << endl;
	cout << "  -i the network interface to listen on" << endl;
	cout << "  -s the IP address to answer on" << endl;
	cout << "  -p the UDP port to listen on (default: 53)" << endl;
	cout << "  -f the zone file to load (default: " << prefix << "/etc/root.zone)" << endl;
	cout << "  -T the number of threads to run (default: ncpus)" << endl;

	exit(result);
}

int app(int argc, char* argv[])
{
	const char* zfname = TO_STRING(PREFIX) "/etc/root.zone";
	const char* ifname = nullptr;
	const char* ipaddr = nullptr;
	uint16_t    port = 53;
	auto	max_threads = std::thread::hardware_concurrency();
	auto	threads = max_threads;
	auto	compress = true;

	int opt;
	while ((opt = getopt(argc, argv, "i:f:s:p:T:Ch")) != -1) {
		switch (opt) {
		case 'i': ifname = optarg; break;
		case 'f': zfname = optarg; break;
		case 's': ipaddr = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'T': threads = atoi(optarg); break;
		case 'C': compress = false; break;
		case 'h': usage(EXIT_SUCCESS);
		default: usage();
		}
	}

	if ((optind < argc) || !ifname || !ipaddr) {
		usage();
	}

	in_addr host;
	if (inet_aton(ipaddr, &host) != 1) {
		std::cerr << "invalid IP option" << std::endl;
		return EXIT_FAILURE;
	}

	// configure syslog
	openlog("froot", LOG_PID | LOG_CONS, LOG_DAEMON);

	DNSServer server;
	server.load(zfname, compress);

	// limit thread range
	threads = std::min(threads, max_threads);
	threads = std::max(1U, threads);

	syslog(LOG_NOTICE, "starting %d worker threads", threads);
	std::vector<std::thread> workers(threads);

	for (auto i = 0U; i < threads; ++i) {

		workers[i] = std::thread(
		    [&](int n) {
			    auto raw = Netserver_AFPacket(ifname);
			    auto arp = Netserver_ARP(raw.gethwaddr(), host);

			    const in6_addr ll =
				Netserver_IPv6::ether_to_link_local(raw.gethwaddr());
			    auto ipv6 = Netserver_IPv6({ll});
			    auto ipv4 = Netserver_IPv4(host);

			    auto icmp4 = Netserver_ICMP();
			    auto icmp6 = Netserver_ICMPv6(raw.gethwaddr());

			    auto udp = Netserver_UDP();
			    auto tcp = Netserver_TCP();

			    arp.attach(raw);
			    ipv4.attach(raw);
			    ipv6.attach(raw);

			    icmp4.attach(ipv4);
			    icmp6.attach(ipv6);

			    udp.attach(ipv4);
			    udp.attach(ipv6);

			    tcp.attach(ipv4);
			    tcp.attach(ipv6);

			    server.attach(udp, port);
			    server.attach(tcp, port);

			    if (n == 0) {
				    syslog(LOG_NOTICE, "listening on %s:%d",
					   inet_ntop(host).c_str(), port);
				    syslog(LOG_NOTICE, "listening on [%s]:%d",
					   inet_ntop(ll).c_str(), port);
			    }

			    raw.loop();
		    },
		    i);

		thread_setcpu(workers[i], i);
		thread_setname(workers[i], "worker" + std::to_string(i));
	}

	for (auto i = 0U; i < threads; ++i) {
		workers[i].join();
	}

	return 0;
}

int main(int argc, char* argv[])
{
	try {
		return app(argc, argv);
	} catch (std::exception& e) {
		syslog(LOG_ERR, "exception: %s", e.what());
		std::cerr << "error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
}
