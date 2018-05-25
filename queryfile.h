#pragma once

#include <string>
#include <vector>
#include <deque>

#if 0

class QueryRecord {

public:
	typedef std::vector<uint8_t>	Buffer;

private:
	Buffer				buffer;

public:
	QueryRecord(const std::string& name, const std::string& qtype);
	QueryRecord(QueryRecord::Buffer&& buffer, size_t len);

	size_t size() const {
		return buffer.size();
	}

	const uint8_t* const data() const {
		return buffer.data();
	}
};

#endif

class QueryFile {

public:
	typedef std::vector<uint8_t>	Record;

private:
	typedef std::deque<Record>	storage_t;
	storage_t			queries;

public:
	void				read_txt(const std::string& filename);
	void				read_raw(const std::string& filename);
	void				write_raw(const std::string& filename);

public:

	const Record&			operator[](size_t n) const {
		return queries[n];
	};

	size_t				size() const {
		return queries.size();
	};
};
