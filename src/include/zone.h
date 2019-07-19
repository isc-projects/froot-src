/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include <ldns/ldns.h>

#include "context.h"

class AnswerSet;

class Zone {

private:
	typedef std::map<std::string, std::shared_ptr<const AnswerSet>>		  Data;
	typedef std::unordered_map<std::string, std::shared_ptr<const AnswerSet>> Aux;

	typedef std::shared_ptr<Data> PData;
	typedef std::shared_ptr<Aux>  PAux;

private:
	PData data;
	PAux  aux;
	bool  loaded = false;

private:
	void build_answers(PData& data, PAux& aux, const ldns_dnssec_zone* zone,
			   const ldns_dnssec_name* name, bool compress);
	void check_zone(const ldns_dnssec_zone* zone);
	void build_zone(const ldns_dnssec_zone* zone, bool compress);

public:
	void		 load(const std::string& filename, bool compress, bool notice = true);
	const AnswerSet* lookup(const std::string& qname, bool& match) const;

public:
	Zone();
	~Zone();
};
