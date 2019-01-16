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
#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "netserver/fuzz.h"
#include "netserver/ipv4.h"
#include "netserver/ipv6.h"
#include "netserver/icmp.h"
#include "netserver/icmpv6.h"
#include "netserver/arp.h"
#include "netserver/udp.h"
#include "netserver/tcp.h"

#include "server.h"
#include "util.h"

void usage(int result = EXIT_FAILURE)
{
	using namespace std;

	cout << "fuzz_packet -i <ifile> -s <ipaddr> [-f <zonefile>]" << endl;
	cout << "  -i the input file to read" << endl;
	cout << "  -s the IP address to answer on" << endl;
	cout << "  -p the UDP port to listen on (default: 53)" << endl;
	cout << "  -f the zone file to load (default: root.zone)" << endl;

	exit(result);
}

int app(int argc, char *argv[])
{
	const char *zfname = "root.zone";
	const char *ifile = nullptr;
	const char *ipaddr = nullptr;
	uint16_t port = 53;
	auto compress = true;

	int opt;
	while ((opt = getopt(argc, argv, "i:f:s:p:Ch")) != -1) {
		switch (opt) {
			case 'i': ifile = optarg; break;
			case 'f': zfname = optarg; break;
			case 's': ipaddr = optarg; break;
			case 'p': port = atoi(optarg); break;
			case 'C': compress = false; break;
			case 'h': usage(EXIT_SUCCESS);
			default: usage();
		}
	}

	if ((optind < argc) || !ifile || !ipaddr) {
		usage();
	}

	in_addr host;
	if (inet_aton(ipaddr, &host) != 1) {
		std::cerr << "invalid IP option" << std::endl;
		return EXIT_FAILURE;
	}

	DNSServer server;
	server.load_sync(zfname, compress);

	ether_addr hwaddr( { 0x00,0x0c,0x29,0xda,0x75,0x9f } );

	auto raw = Netserver_Fuzz(ifile);
	auto arp = Netserver_ARP(hwaddr, host);

	const in6_addr ll = Netserver_IPv6::ether_to_link_local(hwaddr);
	auto ipv6 = Netserver_IPv6({ ll });
	auto ipv4 = Netserver_IPv4(host);

	auto icmp4 = Netserver_ICMP();
	auto icmp6 = Netserver_ICMPv6(hwaddr);

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

	raw.loop();

	return 0;
}

int main(int argc, char *argv[])
{
	return app(argc, argv);
}
