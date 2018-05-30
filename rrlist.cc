#include <ldns/ldns.h>
#include <ldns/host2wire.h>

#include "rrlist.h"

void RRList::append(const ldns_rr* rr)
{
	auto p = std::shared_ptr<ldns_rr>(ldns_rr_clone(rr), [](ldns_rr* p) { ldns_rr_free(p); });
	list.push_back(p);
}

void RRList::append(const ldns_dnssec_rrs* rrs)
{
	while (rrs) {
		append(rrs->rr);
		rrs = rrs->next;
	}
}

void RRList::append(const ldns_dnssec_rrsets* rrset, bool sigs)
{
	append(rrset->rrs);
	if (sigs) {
		append(rrset->signatures);
	}
}

void RRList::to_buffer_wire(ldns_buffer* buf, int section) const
{
	for (auto rr: list) {
		ldns_rr2buffer_wire(buf, rr.get(), section);
	}
}

size_t RRList::count() const {
	return list.size();
}

RRList::RRList()
{
}

RRList::~RRList()
{
}
