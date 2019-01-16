/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <iostream>
#include <iomanip>
#include "benchmark.h"
#include "timer.h"

uint64_t BenchmarkTimer::current_id = 0;

BenchmarkTimer::BenchmarkTimer(const std::string& _name, clockid_t _clock_id)
{
	name = _name;
	timer_id = current_id++;
	clock_id = _clock_id;
	clock_gettime(clock_id, &start);
}

BenchmarkTimer::~BenchmarkTimer()
{
	write(std::cerr);
	std::cerr << std::endl;
}

timespec BenchmarkTimer::elapsed() const
{
	timespec now;
	clock_gettime(clock_id, &now);
	return now - start;
}

std::ostream& BenchmarkTimer::write(std::ostream& os) const
{
	auto t = elapsed();

	using namespace std;
	ios init(nullptr);
	init.copyfmt(os);
	os << "timer " << setw(4) << timer_id << " - " << setw(20) << left << name << ": " << t;
	os.copyfmt(init);

	return os;
}

std::ostream& operator<<(std::ostream& os, const BenchmarkTimer& timer)
{
	return timer.write(os);
}
