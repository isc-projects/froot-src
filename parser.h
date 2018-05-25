#pragma once

#include "zone.h"
#include "buffer.h"

extern bool parse_query(const Zone& zone, ReadBuffer& in, WriteBuffer& head, ReadBuffer& body);
