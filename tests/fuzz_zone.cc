/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <cstdlib>
#include <iostream>

#include "zone.h"
#include "util.h"

void usage(int result = EXIT_FAILURE)
{
	using namespace std;

	cout << "fuzz_zone [-f <zonefile>]" << endl;

	exit(result);
}

int app(int argc, char *argv[])
{
	const char *zfname = "root.zone";
	bool compress = true;

	int opt;
	while ((opt = getopt(argc, argv, "f:Ch")) != -1) {
		switch (opt) {
			case 'f': zfname = optarg; break;
			case 'C': compress = false; break;
			case 'h': usage(EXIT_SUCCESS);
			default: usage();
		}
	}

	if (optind < argc) {
		usage();
	}

	try {
		Zone zone;
		zone.load(zfname, compress, false);
	} catch (std::runtime_error& e) {
		// ignore
	}

	return 0;
}

int main(int argc, char *argv[])
{
	return app(argc, argv);
}
