#include "context.h"
#include "zone.h"

Context::Context() :
	bufsize(512), match(false), edns(false), do_bit(false)
{
	answer = Answer::empty;
}
