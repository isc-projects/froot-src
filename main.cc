#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "netserver/afpacket.h"
#include "netserver/ipv4.h"
#include "netserver/icmp.h"
#include "netserver/arp.h"
#include "netserver/udp.h"
#include "netserver/tcp.h"

#include "server.h"

void thread_setcpu(std::thread& t, unsigned int n)
{
        cpu_set_t cpu;
        CPU_ZERO(&cpu);
        CPU_SET(n, &cpu);
        pthread_setaffinity_np(t.native_handle(), sizeof(cpu), &cpu);
}

void usage(int result = EXIT_FAILURE)
{
	using namespace std;

	cout << "lightning -i <ifname> -s <ipaddr> [-f <zonefile>] [-T <threads>]" << endl;
	cout << "  -i the network interface to listen on" << endl;
	cout << "  -s the IP address to answer on" << endl;
	cout << "  -p the UDP port to listen on (default: 53)" << endl;
	cout << "  -z the zone file to load (default: root.zone)" << endl;
	cout << "  -T the number of threads to run (default: ncpus)" << endl;

	exit(result);
}

int app(int argc, char *argv[])
{
	const char *zfname = "root.zone";
	const char *ifname = nullptr;
	const char *ipaddr = nullptr;
	uint16_t port = 53;
	auto max_threads = std::thread::hardware_concurrency();
	auto threads = max_threads;
	auto compress = true;

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

	DNSServer server;
	server.load(zfname, compress);

	// limit thread range
	threads = std::min(threads, max_threads);
	threads = std::max(1U, threads);

	std::vector<std::thread> workers(threads);

	for (auto i = 0U; i < threads; ++i) {

		workers[i] = std::thread([&]() {
			Netserver_AFPacket raw(ifname);
			Netserver_ARP arp(raw.gethwaddr(), host);
			Netserver_ICMP icmp;
			Netserver_IPv4 ipv4(host);
			Netserver_UDP udp4;
			Netserver_TCP tcp4;

			arp.attach(raw);
			icmp.attach(raw);
			ipv4.attach(raw);
			udp4.attach(ipv4);
			tcp4.attach(ipv4);
			server.attach(udp4, port);
			server.attach(tcp4, port);

			raw.loop();
		});

		thread_setcpu(workers[i], i);
	}

	for (auto i = 0U; i < threads; ++i) {
		workers[i].join();
	}

	return 0;
}

int main(int argc, char *argv[])
{
	try {
		return app(argc, argv);
	} catch (std::exception& e) {
		std::cerr << "error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
}
