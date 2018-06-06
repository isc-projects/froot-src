#include <map>

#include <ldns/ldns.h>

#include "rrlist.h"

void RRList::append(const ldns_rr* rr)
{
	if (rr) {
		auto p = std::shared_ptr<ldns_rr>(ldns_rr_clone(rr), ldns_rr_free);
		_list.push_back(p);
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

RRList RRList::operator+(const RRList& rhs) const
{
	RRList result;

	for (auto rr: _list) {
		result._list.push_back(rr);
	}

	for (auto rr: rhs._list) {
		result._list.push_back(rr);
	}

	return result;
}

RRList::RRList(const ldns_dnssec_rrsets* rrs)
{
	append(rrs);
}

RRList::RRList(RRList&& rhs)
{
	std::swap(_list, rhs._list);
}
