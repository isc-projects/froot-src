#include <cstdlib>
#include <iostream>
#include <map>

#include <unistd.h>	// for getopt

#include "context.h"
#include "zone.h"
#include "queryfile.h"
#include "timer.h"

void worker(const Zone& zone, const QueryFile& queries)
{
	std::map<uint16_t, uint64_t> rcode_count;
	std::map<bool, uint64_t> tc_count;

	{
		Context ctx(zone);

		std::vector<iovec> iov;
		iov.reserve(5);

		BenchmarkTimer t("100M queries");
		for (size_t n = 0; n < 10; ++n) {
			for (size_t i = 0; i < 1e7; ++i) {

				auto& q = queries[i];
				ReadBuffer in { q.data(), q.size() };
				iov.clear();

				(void) ctx.execute(in, iov);
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

        cout << "lightbench [-C] [-b <bufsize>] [-D]" << endl;
        cout << "  -C disable compression" << endl;
        cout << "  -b specify EDNS buffer size" << endl;
        cout << "  -D send DO bit (implies EDNS)" << endl;

        exit(result);
}

int app(int argc, char *argv[])
{
        bool compress = true;
	bool edns = false;
	bool do_bit = false;
	uint16_t bufsize = 0;

	int opt;
	while ((opt = getopt(argc, argv, "Cb:Dh")) != -1) {
                switch (opt) {
                        case 'C': compress = false; break;
			case 'b': bufsize = atoi(optarg); edns = true; break;
			case 'D': do_bit = true; break;
                        case 'h': usage(EXIT_SUCCESS);
                        default: usage();
                }
	}

        if (optind < argc) {
                usage();
        }

	if (bufsize < 512) {
		bufsize = 512;
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

	if (edns || do_bit) {
		BenchmarkTimer t("add EDNS RRs");
		queries.edns(bufsize, (do_bit << 15));
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
