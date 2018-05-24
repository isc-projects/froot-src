#include <cstdlib>
#include <iostream>
#include <map>

#include "server.h"
#include "datafile.h"
#include "buffer.h"
#include "timer.h"

int app(int argc, char *argv[])
{
	Server server;
	Datafile queries;

	{
		BenchmarkTimer t("load zone");
		server.load("root.zone");
	}

	{
		BenchmarkTimer t("load queries");
		queries.read_raw("default.raw");
	}

	std::map<int, uint64_t> rcodes;
	{
		BenchmarkTimer t("10M queries");
		for (size_t i = 0; i < 1e7; ++i) {
			auto& q = queries[i];

			Buffer in { q.data(), q.size() };
			in.reserve(q.size());

			uint8_t bufout[4096];
			Buffer out { bufout, 4096 };

			auto rcode = server.query(in, out);
			++rcodes[rcode];
		}
	}

	for (const auto it: rcodes) {
		std::cerr << it.first << " : " << it.second << std::endl;
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
