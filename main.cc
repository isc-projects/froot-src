#include <cstdlib>
#include <iostream>

#include "zone.h"
#include "datafile.h"
#include "timer.h"

int app(int argc, char *argv[])
{
	Zone root;
	Datafile queries;

	{
		BenchmarkTimer t("load zone");
		root.load("root.zone");
	}

	{
		BenchmarkTimer t("load queries");
		queries.read_raw("default.raw");
	}

	uint64_t res = 0;
	{
		BenchmarkTimer t("1M queries");
		for (size_t i = 0; i < 1e6; ++i) {
			auto q = queries[i];
			res += root.lookup(q.data(), q.size());
		}
	}
	std::cerr << res << std::endl;

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
