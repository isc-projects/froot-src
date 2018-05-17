#pragma once

#include "zone.h"

class Server {

private:
	Zone			zone;

public:
	void load(const std::string& filename);
	int query(const uint8_t* buffer, size_t len) const;

public:
	Server();
	~Server();

};
