#pragma once

#include <string>
#include <deque>
#include "query.h"

class Datafile {

public:
	typedef std::deque<Query>	storage_t;

private:
	storage_t			queries;

public:
	void				read_txt(const std::string& filename);
	void				read_raw(const std::string& filename);
	void				write_raw(const std::string& filename);

public:

	const Query&			operator[](size_t n) const {
		return queries[n];
	};

	size_t				size() const {
		return queries.size();
	};
};
