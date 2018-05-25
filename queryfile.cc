#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <cerrno>
#include <map>
#include <algorithm>

#include <arpa/inet.h>		// for ntohs() etc
#include <resolv.h>		// for res_mkquery()

#include "queryfile.h"
#include "util.h"

static std::map<std::string, uint16_t> type_map = {
	{ "A",		  1 },
	{ "SOA",	  6 },
	{ "PTR",	 12 },
	{ "MX",		 15 },
	{ "TXT",	 16 },
	{ "AAAA",	 28 },
	{ "SRV",	 33 },
};

uint16_t type_to_number(const std::string& type, bool check_case = true)
{
	auto itr = type_map.find(type);
	if (itr != type_map.end()) {
		return itr->second;
	} else if (type.compare(0, 4, "TYPE", 4) == 0) {
		size_t index;
		std::string num = type.substr(4, std::string::npos);
		try {
			unsigned long val = std::stoul(num, &index, 10);
			if (num.cbegin() + index != num.cend()) {
				throw std::runtime_error("numeric QTYPE trailing garbage");
			} else if (val > std::numeric_limits<uint16_t>::max()) {
				throw std::runtime_error("numeric QTYPE out of range");
			} else {
				return type_map[type] = val;
			}
		} catch (std::logic_error& e) {
			throw std::runtime_error("numeric QTYPE unparseable");
		}
	} else {
		if (check_case) {
			std::string tmp(type);
			std::transform(tmp.cbegin(), tmp.cend(), tmp.begin(), ::toupper);
			return type_map[type] = type_to_number(tmp, false);
		} else {
			throw std::runtime_error("unrecognised QTYPE: " + type);
		}
	}
}

QueryRecord::QueryRecord(const std::string& name, const std::string& type)
{
	uint16_t qtype = type_to_number(type);

	int n = res_mkquery(0, name.c_str(), 1, qtype, nullptr, 0, nullptr,
			    buffer.data(), buffer.size());
	if (n < 0) {
		throw std::runtime_error("couldn't parse domain name");
	} else {
		len = n;
	}
}

QueryRecord::QueryRecord(const QueryRecord::Buffer& input, size_t _len)
{
	len = _len;
	buffer.resize(len);
	std::copy(input.cbegin(), input.cbegin() + len, buffer.begin());
}

//---------------------------------------------------------------------
//
void QueryFile::read_txt(const std::string& filename)
{
	std::ifstream file(filename);
	if (!file) {
		throw_errno("opening query file");
	}

	storage_t list;
	std::string name, type;
	size_t line_no = 0;

	while (file >> name >> type) {
		line_no++;

		try {
			list.emplace_back(QueryRecord(name, type));
		} catch (std::runtime_error &e) {
			std::string error = "reading query file at line "
					+ std::to_string(line_no)
					+ ": " + e.what();
			throw_errno(error);
		}
	}

	file.close();

	std::swap(queries, list);
}

void QueryFile::read_raw(const std::string& filename)
{
	std::ifstream file(filename, std::ifstream::binary);
	if (!file) {
		throw_errno("opening query file");
	}

	storage_t list;
	QueryRecord::Buffer buffer;
	uint16_t len;

	while (file) {
		if (file.read(reinterpret_cast<char*>(&len), sizeof(len))) {

			len = ntohs(len);			// swap to host order
			buffer.resize(len);			// ensure there's room

			if (file.read(reinterpret_cast<char*>(buffer.data()), len)) {
				list.emplace_back(QueryRecord(buffer, len));
			}
		}
	}

	file.close();

	std::swap(queries, list);
}

void QueryFile::write_raw(const std::string& filename)
{
	std::ofstream file(filename, std::ifstream::binary);
	if (!file) {
		throw_errno("opening query file");
	}

	for (const auto& query: queries) {
		uint16_t len = htons(query.size());	// big-endian
		file.write(reinterpret_cast<const char*>(&len), sizeof(len));
		file.write(reinterpret_cast<const char*>(query.data()), query.size());
	}

	file.close();
}
