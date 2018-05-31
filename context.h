#pragma once

#include <string>

#include "buffer.h"
#include "answer.h"

class Zone;

class Context {

public:
	enum Type {
		ctx_root_soa = 0,
		ctx_root_ns,
		ctx_root_dnskey,
		ctx_root_nsec,
		ctx_root_nodata,
		ctx_tld_ds,
		ctx_tld_referral,
		ctx_nxdomain,
		ctx_size
	};

private:
	void parse_edns();
	void parse_question();
	void parse_packet();
	void perform_lookup();

private:
	const Zone&		zone;
	ReadBuffer&		in;
	WriteBuffer&		head;
	ReadBuffer&		body;

private:
	std::string		qname;
	uint16_t		qtype;
	uint16_t		qdstart;
	uint16_t		qdsize;
	uint16_t		bufsize;

	uint8_t			qlabels;

	bool			match;
	bool			edns;
	bool			do_bit;
	const Answer*		answer;

public:
	uint16_t		rcode;

public:
	Context(const Zone& zone, ReadBuffer& in, WriteBuffer& head, ReadBuffer& body);
	~Context();

	bool execute();
	Type type() const;
};
