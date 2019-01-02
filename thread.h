#pragma once

#include <thread>

extern void thread_setcpu(std::thread& t, unsigned int n);
extern void thread_setname(std::thread&t, const std::string& name);
