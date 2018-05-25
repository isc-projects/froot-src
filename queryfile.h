#pragma once

#include <string>
#include <vector>
#include <deque>

class QueryRecord {

public:
	typedef std::vector<uint8_t>	Buffer;

private:
	Buffer				buffer;
	size_t				len;

public:
	QueryRecord(const std::string& name, const std::string& qtype);
	QueryRecord(const QueryRecord::Buffer& buffer, size_t len);

	size_t size() const {
		return len;
	}

	const uint8_t* const data() const {
		return buffer.data();
	}
};

class QueryFile {

private:
	typedef std::deque<QueryRecord>	storage_t;
	storage_t			queries;

public:
	void				read_txt(const std::string& filename);
	void				read_raw(const std::string& filename);
	void				write_raw(const std::string& filename);

public:

	const QueryRecord&		operator[](size_t n) const {
		return queries[n];
	};

	size_t				size() const {
		return queries.size();
	};
};
