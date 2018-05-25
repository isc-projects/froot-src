#include <cstdlib>
#include <iostream>
#include <map>

#include "server.h"

int app(int argc, char *argv[])
{
	Server server;
	server.load("root.zone");
	server.worker("enp2s0");

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
