/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <ldns/ldns.h>
#include <memory>
#include <vector>

class RRList {

public:
	typedef std::vector<std::shared_ptr<ldns_rr>> List;

private:
	List _list;

public:
	void append(const ldns_rr* rr);
	void append(const ldns_dnssec_rrs* rrs);
	void append(const ldns_dnssec_rrsets* rrset);

	RRList operator+(const RRList& rhs) const;

	const List& list() const
	{
		return _list;
	};
	size_t count() const
	{
		return _list.size();
	};

public:
	RRList() = default;

	RRList(const ldns_dnssec_rrsets* rrs);
	RRList(const RRList& rhs);
	RRList(RRList&& rhs);
};
