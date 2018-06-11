#pragma once

#include <sys/types.h>
#include <sys/socket.h>

#include "zone.h"
#include "packet.h"

class Server {

private:
	Zone			zone;
	uint16_t		port;

private:
	void send(PacketSocket&s, msghdr& msg, std::vector<iovec>& iov) const;
	void handle_packet(PacketSocket& s, uint8_t* buffer, size_t buflen, const sockaddr_ll* addr, void* userdata);

public:
	void worker(PacketSocket& s, uint16_t port);
	void load(const std::string& filename, bool compress);

public:
	Server();
	~Server();
};
