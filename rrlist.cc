#include <map>

#include <ldns/ldns.h>

#include "rrlist.h"

void RRList::append(const ldns_rr* rr)
{
	if (rr) {
		auto p = std::shared_ptr<ldns_rr>(ldns_rr_clone(rr), ldns_rr_free);
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

struct DNameCompare {
	bool operator()(const ldns_rdf* a, const ldns_rdf* b) {
		return ldns_dname_compare(a, b) < 0;
	}
};

typedef std::map<const ldns_rdf*, uint16_t, DNameCompare> CompressTable;
typedef std::vector<uint16_t> CompressOffsets;

void dname_to_buffer(ldns_buffer* buf, const ldns_rdf* name, CompressTable& compress, CompressOffsets& offsets)
{
	if (ldns_dname_label_count(name) == 0) {
		ldns_buffer_write_u8(buf, 0);
		return;
	}

	auto iter = compress.find(name);
	if (iter != compress.end()) {
		auto pos = iter->second;
		offsets.push_back(pos);
		ldns_buffer_write_u16(buf, pos | 0xc000);
		return;
	}

	uint16_t pos = ldns_buffer_position(buf);
	if (pos < 16384) {
		auto clone = ldns_rdf_clone(name);
		compress[clone] = pos;
	}

	auto label = ldns_dname_label(name, 0);
	auto rest = ldns_dname_left_chop(name);
	auto size = ldns_rdf_size(label) - 1;
	auto data = ldns_rdf_data(label);

	ldns_buffer_write(buf, data, size);
	ldns_rdf_deep_free(label);

	dname_to_buffer(buf, rest, compress, offsets);
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
