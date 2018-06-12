#include <cstdlib>
#include <iostream>
#include <map>

#include "context.h"
#include "zone.h"
#include "queryfile.h"
#include "timer.h"

void worker(const Zone& zone, const QueryFile& queries)
{
	std::map<uint16_t, uint64_t> rcode_count;
	std::map<bool, uint64_t> tc_count;

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
					auto tc = !!(p[2] & 0x02);

					++rcode_count[rcode];
					++tc_count[tc];

				}
			}
		}
	}

	for (const auto it: rcode_count) {
		std::cerr << "rcode " << it.first << " : " << it.second << std::endl;
	}

	for (const auto it: tc_count) {
		std::cerr << "tc " << it.first << " : " << it.second << std::endl;
	}
}

void usage(int result = EXIT_FAILURE)
{
        using namespace std;

        cout << "lightbench [-C]" << endl;
        cout << "  -C disable compression" << endl;

        exit(result);
}

int app(int argc, char *argv[])
{
        auto compress = true;

        --argc;
        ++argv;
        while (argc > 0 && **argv == '-') {
                char o = *++*argv;
                switch (o) {
                        case 'C': compress = false; break;
                        case 'h': usage(EXIT_SUCCESS);
                        default: usage();
                }
                --argc;
                ++argv;
        }

        if (argc) {
                usage();
        }

	Zone zone;
	QueryFile queries;

	{
		BenchmarkTimer t("load zone");
		zone.load("root.zone", compress);
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
