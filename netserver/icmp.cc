#include <netinet/ip_icmp.h>

#include "icmp.h"
#include "checksum.h"

void Netserver_ICMP::recv(NetserverPacket& p) const
{
	auto& in = p.readbuf;
	auto& iov = p.iovs;

	// read ICMP header
	if (in.available() < sizeof(icmphdr)) return;
	auto hdr = in.read<icmphdr>();

	// we only answer pings
	if (hdr.type != ICMP_ECHO) return;

	// code 0 is the only valid one for echo
	if (hdr.code != 0) return;

	// use the copy of the header to generate the response
	iov.push_back(iovec { &hdr, sizeof hdr });
	hdr.type = ICMP_ECHOREPLY;
	hdr.checksum = 0;

	// start accumulating the checksum
	Checksum crc;
	crc.add(iov.back());

	// use the remaining data in the read buffer as payload
	size_t n = in.available();
	auto payload = const_cast<uint8_t*>(in.read<uint8_t>(n));
	iov.push_back(iovec { payload, n });

	// update the checksum
	crc.add(iov.back());
	hdr.checksum = crc.value();

	send_up(p, p.layers.size());
}
