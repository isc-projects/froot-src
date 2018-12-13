#include "netserver.h"

void NetserverLayer::attach(NetserverLayer& layer, uint16_t protocol)
{
	layer.layers[protocol] = this;
}

NetserverPacket::NetserverPacket(const uint8_t* buf, size_t buflen, const sockaddr* addr, socklen_t addrlen)
	: readbuf(buf, buflen), addr(addr), addrlen(addrlen)
{
	layers.reserve(5);
	iovs.reserve(5);
}
