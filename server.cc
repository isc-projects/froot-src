#include <iostream>
#include <thread>

#include <sys/stat.h>

#include "netserver/tcp.h"
#include "server.h"
#include "context.h"
#include "timer.h"
#include "util.h"

//---------------------------------------------------------------------

void DNSServer::recv(NetserverPacket& p) const
{
	auto state = p.layers.back();
	auto *up = state.first;
	bool tcp = (dynamic_cast<const Netserver_TCP*>(up) != nullptr);

	Context ctx(zone);
	if (ctx.execute(p.readbuf, p.iovs, tcp)) {
		send_up(p);
	}
}

//---------------------------------------------------------------------

void DNSServer::loader_thread(std::string filename, bool compress)
{
	timespec mtim = { 0, 0 };
	struct stat st;
	bool first = true;

	while (true) {
		int res = ::stat(filename.c_str(), &st);
		if (first || (res == 0 && !(st.st_mtim == mtim))) {
			try {
				zone.load(filename, compress);
				mtim = st.st_mtim;
			} catch (std::exception& e) {
				std::cerr << "error: " << e.what() << std::endl;
			}
		}
		first = false;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void DNSServer::load(const std::string& filename, bool compress)
{
	auto t = std::thread(&DNSServer::loader_thread, this, filename, compress);
	t.detach();
}
