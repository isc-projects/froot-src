#include "context.h"
#include "zone.h"

Context::Context(const Zone& zone, ReadBuffer& in, WriteBuffer& head) :
	zone(zone), in(in), head(head),
	bufsize(512), match(false), edns(false), do_bit(false)
{
	answer = Answer::empty;
}
