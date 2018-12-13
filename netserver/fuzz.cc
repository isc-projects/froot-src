#include <cstring>
#include <iostream>
#include <stdexcept>

#include <unistd.h>
#include <fcntl.h>

#include <net/ethernet.h>

#include "fuzz.h"
#include "../util.h"

Netserver_Fuzz::Netserver_Fuzz(const std::string& filename)
{
	fd = open(filename.c_str(), O_RDONLY);
	if (fd < 0) {
		throw_errno("open");
	}
}

Netserver_Fuzz::~Netserver_Fuzz()
{
	if (fd >= 0) {
		::close(fd);
		fd = -1;
	}
}

void Netserver_Fuzz::recv(NetserverPacket& p) const
{
	auto& buf = p.readbuf;

	if (buf.available() < sizeof(ether_header)) return;

	auto& ether = buf.read<ether_header>();
	p.l3 = ntohs(ether.ether_type);
	dispatch(p, p.l3);
}

void Netserver_Fuzz::send(NetserverPacket& p, const std::vector<iovec>& iovs, size_t iovlen) const
{
	// std::cerr << "send: " << iovlen << std::endl;
}

void Netserver_Fuzz::loop()
{
	uint8_t buffer[2048];
	ssize_t n = ::read(fd, buffer, sizeof buffer);
	if (n > 0) {
		NetserverPacket packet(buffer, n, nullptr, 0U);
		recv(packet);
	}
}
