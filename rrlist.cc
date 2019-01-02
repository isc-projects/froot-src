/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

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

RRList::RRList(const RRList& rhs)
{
	for (auto rr: rhs._list) {
		_list.push_back(rr);
	}
}

RRList::RRList(RRList&& rhs)
{
	std::swap(_list, rhs._list);
}
