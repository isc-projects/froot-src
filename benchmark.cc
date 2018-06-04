#include <cstdlib>
#include <iostream>
#include <map>

#include "context.h"
#include "zone.h"
#include "queryfile.h"
#include "timer.h"

void worker(const Zone& zone, const QueryFile& queries)
{
	std::map<int, uint64_t> rcodes;
	{
		std::vector<iovec> iov;
		iov.reserve(5);

		BenchmarkTimer t("100M queries");
		for (size_t n = 0; n < 10; ++n) {
			for (size_t i = 0; i < 1e7; ++i) {

				auto& q = queries[i];
				ReadBuffer in { q.data(), q.size() };
				iov.clear();

				Context ctx(zone, in);
				(void) ctx.execute(iov);
				if (iov.size() >= 1) {
					auto p = reinterpret_cast<uint8_t*>(iov[0].iov_base);
					auto rcode = p[3] & 0x0f;
					++rcodes[rcode];
				}
			}
		}
	}

	for (const auto it: rcodes) {
		std::cerr << it.first << " : " << it.second << std::endl;
	}
}

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

	worker(zone, queries);

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
