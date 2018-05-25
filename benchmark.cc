#include <cstdlib>
#include <iostream>
#include <map>

#include "zone.h"
#include "queryfile.h"
#include "parser.h"
#include "timer.h"

int app(int argc, char *argv[])
{
	Zone zone;
	QueryFile queries;

	{
		BenchmarkTimer t("load zone");
		zone.load("root.zone");
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
			uint8_t tmp[512];

			ReadBuffer in { q.data(), q.size() };
			WriteBuffer head { tmp, sizeof tmp };
			ReadBuffer body { nullptr, 0 } ;

			(void) parse_query(zone, in, head, body);
			if (head.position() >= 12) {
				auto rcode = head[3] & 0x0f;
				++rcodes[rcode];
			}
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
