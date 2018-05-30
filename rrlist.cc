#include <ldns/ldns.h>
#include <ldns/host2wire.h>

#include "rrlist.h"

void RRList::append(const ldns_rr* rr)
{
	if (rr) {
		auto p = std::shared_ptr<ldns_rr>(ldns_rr_clone(rr), [](ldns_rr* p) { ldns_rr_free(p); });
		list.push_back(p);
	}
}

void RRList::append(const ldns_dnssec_rrs* rrs)
{
	while (rrs) {
		append(rrs->rr);
		rrs = rrs->next;
	}
}

void RRList::append(const ldns_dnssec_rrsets* rrset)
{
	if (rrset) {
		append(rrset->rrs);
		append(rrset->signatures);
	}
}

size_t RRList::to_buffer_wire(ldns_buffer* buf, int section, bool sigs) const
{
	size_t n = 0;

	for (auto rrp: list) {
		auto rr = rrp.get();
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
			if (sigs) {
				ldns_rr2buffer_wire(buf, rr, section);
				++n;
			}
		} else {
			ldns_rr2buffer_wire(buf, rr, section);
			++n;
		}
	}

	return n;
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
