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
