/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include "thread.h"

void thread_setcpu(std::thread& t, unsigned int n)
{
        cpu_set_t cpu;
        CPU_ZERO(&cpu);
        CPU_SET(n, &cpu);
        pthread_setaffinity_np(t.native_handle(), sizeof(cpu), &cpu);
}

void thread_setname(std::thread&t, const std::string& name)
{
	pthread_setname_np(t.native_handle(), name.substr(0, 15).c_str());
}
