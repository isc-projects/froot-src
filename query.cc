#pragma once

#include "query.h"

Query::Query() :
	match(false), edns(false), do_bot(false), bufsize(512)
{
}
