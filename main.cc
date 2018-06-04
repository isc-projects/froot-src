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

int app(int argc, char *argv[])
{
	Server server;
	server.load("root.zone");
	std::string ifname("enp5s0f1");

	auto n = std::thread::hardware_concurrency();

	std::vector<std::thread> threads;
	std::vector<PacketSocket> socks(n);

	for (auto i = 0U; i < n; ++i) {

		socks[i].open();
		socks[i].bind(ifname);
		socks[i].rx_ring_enable(11, 128);

		threads.emplace_back(std::thread(&Server::worker, &server, std::ref(socks[i])));
		thread_setcpu(threads[i], i);
	}

	for (auto i = 0U; i < n; ++i) {
		threads[i].join();
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
