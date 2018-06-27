#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

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

	cout << "lightning -i <ifname> [-z <zonefile>] [-T <threads>]" << endl;
	cout << "  -i the network interface to listen on" << endl;
	cout << "  -p the UDP port to listen on (default: 53)" << endl;
	cout << "  -z the zone file to load (default: root.zone)" << endl;
	cout << "  -T the number of threads to run (default: ncpus)" << endl;

	exit(result);
}

int app(int argc, char *argv[])
{
	const char *zfname = "root.zone";
	const char *ifname = nullptr;
	uint16_t port = 53;
	auto max_threads = std::thread::hardware_concurrency();
	auto threads = max_threads;
	auto compress = true;

	int opt;
	while ((opt = getopt(argc, argv, "i:f:p:T:Ch")) != -1) {
		switch (opt) {
			case 'i': ifname = optarg; break;
			case 'f': zfname = optarg; break;
			case 'p': port = atoi(optarg); break;
			case 'T': threads = atoi(optarg); break;
			case 'C': compress = false; break;
			case 'h': usage(EXIT_SUCCESS);
			default: usage();
		}
	}

	if ((optind < argc) || !ifname) {
		usage();
	}

	// limit thread range
	threads = std::min(threads, max_threads);
	threads = std::max(1U, threads);

	Server server;
	server.load(zfname, compress);

	std::vector<std::thread> workers(threads);
	std::vector<PacketSocket> socks(threads);

	for (auto i = 0U; i < threads; ++i) {

		socks[i].open();
		socks[i].bind(ifname);
		socks[i].rx_ring_enable(11, 128);

		workers[i] = std::thread(
			&Server::worker_thread, &server, std::ref(socks[i]), port);
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
