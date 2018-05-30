#pragma once

#include <ldns/dnssec.h>
#include <memory>
#include <vector>

class RRList {

private:
	std::vector<std::shared_ptr<ldns_rr>> list;

public:
	void append(const ldns_rr* rr);
	void append(const ldns_dnssec_rrs* rrs);
	void append(const ldns_dnssec_rrsets* rrset, bool sigs = false);

	void to_buffer_wire(ldns_buffer* buf, int section) const;
	size_t count() const;

public:
	RRList();
	~RRList();

};
