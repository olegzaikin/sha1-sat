/*
 * sha1-sat -- SAT instance generator for SHA-1
 * Copyright (C) 2011-2012, 2021  Vegard Nossum <vegard.nossum@gmail.com>
 *               2023 Oleg Zaikin <zaikin.icc@gmailcom>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <boost/program_options.hpp>

extern "C" {
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
}

#include "format.hh"

std::string version = "1.1.0";

/* Instance options */
static std::string config_attack = "preimage";
static std::string config_message_file = "";
static unsigned int config_nr_rounds = 80;
static unsigned int config_nr_message_bits = 0;
static unsigned int config_nr_hash_bits = 160;
static int config_hash_value = -1;
// How many message bits are unknown on the last step:
static unsigned int config_equal_toM_bits = 32; // intermediate inverse problem value
static std::string config_hash_function = "sha1"; // sha1, md4, or md5
// Whether the incremental operation is done after the last step (0 or 1):
static unsigned int is_incremental_step = 1;
// Whether a compact encoding for intermediate inverse problems is used:
static bool config_compact_interm_enc = false;

/* Format options */
static bool config_cnf = false;
static bool config_opb = false;

/* CNF options */
static bool config_use_xor_clauses = false;
static bool config_use_halfadder_clauses = false;
static bool config_use_tseitin_adders = false;
static bool config_restrict_branching = false;

/* OPB options */
static bool config_use_compact_adders = false;

static std::ostringstream cnf;
static std::ostringstream opb;

static int nr_variables = 0;
static unsigned int nr_clauses = 0;
static unsigned int nr_xor_clauses = 0;
static unsigned int nr_constraints = 0;

unsigned MD4_M_indicies[48]{0, 1, 2,  3,  4, 5,  6,  7,  8, 9, 10, 11,  12, 13, 14, 15,
                            0, 4, 8, 12,  1, 5,  9, 13,  2, 6, 10, 14,  3,   7, 11, 15,
														0, 8, 4, 12,  2, 10, 6, 14,  1, 9,  5, 13,  3,  11,  7, 15};

int MD4_shifts[48]{ 3, 7, 11, 19,  3, 7, 11, 19,  3, 7, 11, 19,  3, 7, 11, 19,
                    3, 5,  9, 13,  3, 5,  9, 13,  3, 5,  9, 13,  3, 5,  9, 13,
										3, 9, 11, 15,  3, 9, 11, 15,  3, 9, 11, 15,  3, 9, 11, 15};

unsigned MD5_const[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
													0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
													0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
													0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
													0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
													0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
													0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
													0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
													0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
													0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
													0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
													0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
													0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
													0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
													0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
													0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

int MD5_shifts[64]{ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
										5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
										4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
										6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 };

static void comment(std::string str)
{
	cnf << format("c $\n", str);
	opb << format("* $\n", str);
}

static void new_vars(std::string label, int x[], unsigned int n, bool decision_var = true)
{
	for (unsigned int i = 0; i < n; ++i)
		x[i] = ++nr_variables;

	comment(format("var $/$ $", x[0], n, label));

	if (config_restrict_branching) {
		if (decision_var) {
			for (unsigned int i = 0; i < n; ++i)
				cnf << format("d $ 0\n", x[i]);
		} else {
			for (unsigned int i = 0; i < n; ++i)
				cnf << format("d -$ 0\n", x[i]);
		}
	}
}

static void constant(int r, bool value)
{
	cnf << format("$$ 0\n", (r < 0) ^ value ? "" : "-", r);
	opb << format("1 x$ = $;\n", r, (r < 0) ^ value ? 1 : 0);

	nr_clauses += 1;
	nr_constraints += 1;
}

static void constant32(int r[], uint32_t value)
{
	comment(format("constant32 ($)", value));

	for (unsigned int i = 0; i < 32; ++i) {
		constant(r[i], (value >> i) & 1);
	}
}

static void new_constant(std::string label, int r[32], uint32_t value)
{
	new_vars(label, r, 32);
	constant32(r, value);
}

template<typename T>
static void args_to_vector(std::vector<T> &v)
{
}

template<typename T, typename... Args>
static void args_to_vector(std::vector<T> &v, T x, Args... args)
{
	v.push_back(x);
	return args_to_vector(v, args...);
}

static void clause(const std::vector<int> &v)
{
	for (int x: v) {
		cnf << format("$$ ", x < 0 ? "-" : "", abs(x));
		opb << format("1 $x$ ", x < 0 ? "~" : "", abs(x));
	}

	cnf << format("0\n");
	opb << format(">= 1;\n");

	nr_clauses += 1;
	nr_constraints += 1;
}

template<typename... Args>
static void clause(Args... args)
{
	std::vector<int> v;
	args_to_vector(v, args...);
	clause(v);
}

static void xor_clause(const std::vector<int> &v)
{
	cnf << format("x ");

	for (int x: v)
		cnf << format("$$ ", x < 0 ? "-" : "", abs(x));

	cnf << format("0\n");

	nr_xor_clauses += 1;
}

template<typename... Args>
static void xor_clause(Args... args)
{
	std::vector<int> v;
	args_to_vector(v, args...);
	xor_clause(v);
}

static void halfadder(const std::vector<int> &lhs, const std::vector<int> &rhs)
{
	if (config_use_halfadder_clauses) {
		cnf << "h ";

		for (int x: lhs)
			cnf << format("$ ", x);

		cnf << "0 ";

		for (int x: rhs)
			cnf << format("$ ", x);

		cnf << "0\n";
	} else {
		static std::map<std::pair<unsigned int, unsigned int>, std::vector<std::vector<int>>> cache;

		unsigned int n = lhs.size();
		unsigned int m = rhs.size();
		//std::cout << "n : " << n << std::endl;
		//std::cout << "m : " << m << std::endl;

		std::vector<std::vector<int>> clauses;
		auto it = cache.find(std::make_pair(n, m));
		if (it != cache.end()) {
			clauses = it->second;
		} else {
			auto filename = format("data/halfadder-$-$.out.txt", n, m);

			FILE *in = fopen(filename.c_str(), "r");
			if (!in)
				throw std::runtime_error("fopen() failed");

			while (1) {
				char buf[512];
				if (!fgets(buf, sizeof(buf), in))
					break;

				if (!strncmp(buf, ".i", 2))
					continue;
				if (!strncmp(buf, ".o", 2))
					continue;
				if (!strncmp(buf, ".p", 2))
					continue;
				if (!strncmp(buf, ".e", 2))
					break;
	
				std::vector<int> c;
				for (unsigned i = 0; i < n + m; ++i) {
					if (buf[i] == '0')
						c.push_back(-((int)i + 1));
					else if (buf[i] == '1')
						c.push_back(i + 1);
				}

				clauses.push_back(c);
			}

			fclose(in);

			cache.insert(std::make_pair(std::make_pair(n, m), clauses));
		}

		for (std::vector<int> &c: clauses) {
			std::vector<int> real_clause;

			for (int i: c) {
			  unsigned j = (unsigned)(abs(i) - 1);
				int var = j < n ? lhs[j] : rhs[m - 1 - (j - n)];
				real_clause.push_back(i < 0 ? -var : var);
			}

			clause(real_clause);
		}
	}

	for (int x: lhs)
		opb << format("1 x$ ", x);

	for (unsigned int i = 0; i < rhs.size(); ++i)
		opb << format("-$ x$ ", 1U << i, rhs[i]);

	opb << format("= 0;\n");

	nr_constraints += 1;
}

static void xor2(int r[], int a[], int b[], unsigned int n)
{
	comment("xor2");

	if (config_use_xor_clauses) {
		for (unsigned int i = 0; i < n; ++i)
			xor_clause(-r[i], a[i], b[i]);
	} else {
		for (unsigned int i = 0; i < n; ++i) {
			for (unsigned int j = 0; j < 8; ++j) {
				if (__builtin_popcount(j ^ 1) % 2 == 1)
					continue;

				clause((j & 1) ? -r[i] : r[i],
					(j & 2) ? a[i] : -a[i],
					(j & 4) ? b[i] : -b[i]);
			}
		}
	}
}

static void xor3(int r[], int a[], int b[], int c[], unsigned int n = 32)
{
	comment("xor3");

	if (config_use_xor_clauses) {
		for (unsigned int i = 0; i < n; ++i)
			xor_clause(-r[i], a[i], b[i], c[i]);
	} else {
		for (unsigned int i = 0; i < n; ++i) {
			for (unsigned int j = 0; j < 16; ++j) {
				if (__builtin_popcount(j ^ 1) % 2 == 0)
					continue;

				clause((j & 1) ? -r[i] : r[i],
					(j & 2) ? a[i] : -a[i],
					(j & 4) ? b[i] : -b[i],
					(j & 8) ? c[i] : -c[i]);
			}
		}
	}
}

static void xor4(int r[32], int a[32], int b[32], int c[32], int d[32])
{
	comment("xor4");

	if (config_use_xor_clauses) {
		for (unsigned int i = 0; i < 32; ++i)
			xor_clause(-r[i], a[i], b[i], c[i], d[i]);
	} else {
		for (unsigned int i = 0; i < 32; ++i) {
			for (unsigned int j = 0; j < 32; ++j) {
				if (__builtin_popcount(j ^ 1) % 2 == 1)
					continue;

				clause((j & 1) ? -r[i] : r[i],
					(j & 2) ? a[i] : -a[i],
					(j & 4) ? b[i] : -b[i],
					(j & 8) ? c[i] : -c[i],
					(j & 16) ? d[i] : -d[i]);
			}
		}
	}
}

static void eq(int a[], int b[], unsigned int n = 32)
{
	if (config_use_xor_clauses) {
		for (unsigned int i = 0; i < n; ++i)
			xor_clause(-a[i], b[i]);
	} else {
		for (unsigned int i = 0; i < n; ++i) {
			clause(-a[i], b[i]);
			clause(a[i], -b[i]);
		}
	}
}

static void neq(int a[], int b[], unsigned int n = 32)
{
	if (config_use_xor_clauses) {
		for (unsigned int i = 0; i < n; ++i)
			xor_clause(a[i], b[i]);
	} else {
		for (unsigned int i = 0; i < n; ++i) {
			clause(a[i], b[i]);
			clause(-a[i], -b[i]);
		}
	}
}

static void and2(int r[], int a[], int b[], unsigned int n)
{
	for (unsigned int i = 0; i < n; ++i) {
		clause(r[i], -a[i], -b[i]);
		clause(-r[i], a[i]);
		clause(-r[i], b[i]);
	}
}

static void or2(int r[], int a[], int b[], unsigned int n)
{
	for (unsigned int i = 0; i < n; ++i) {
		clause(-r[i], a[i], b[i]);
		clause(r[i], -a[i]);
		clause(r[i], -b[i]);
	}
}

static void add2(std::string label, int r[32], int a[32], int b[32])
{
	comment("add2");

	if (config_use_tseitin_adders) {
		int c[31];
		new_vars("carry", c, 31);

		int t0[31];
		new_vars("t0", t0, 31);

		int t1[31];
		new_vars("t1", t1, 31);

		int t2[31];
		new_vars("t2", t2, 31);

		and2(c, a, b, 1);
		xor2(r, a, b, 1);

		xor2(t0, &a[1], &b[1], 31);
		and2(t1, &a[1], &b[1], 31);
		and2(t2, t0, c, 31);
		or2(&c[1], t1, t2, 30);
		xor2(&r[1], t0, c, 31);
	} else if (config_use_compact_adders) {
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, a[i]);
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, b[i]);

		for (unsigned int i = 0; i < 32; ++i)
			opb << format("-$ x$ ", 1UL << i, r[i]);

		opb << format("= 0;\n");

		++nr_constraints;
	} else {
		std::vector<int> addends[32 + 5];
		for (unsigned int i = 0; i < 32; ++i) {
			addends[i].push_back(a[i]);
			addends[i].push_back(b[i]);

			unsigned int m = floor(log2(addends[i].size()));
			std::vector<int> rhs(1 + m);
			rhs[0] = r[i];
			new_vars(format("$_rhs[$]", label, i), &rhs[1], m);

			for (unsigned int j = 1; j < 1 + m; ++j)
				addends[i + j].push_back(rhs[j]);

			halfadder(addends[i], rhs);
		}
	}
}

static void add5(std::string label, int r[32], int a[32], int b[32], int c[32], int d[32], int e[32])
{
	comment("add5");

	if (config_use_tseitin_adders) {
		int t0[32];
		new_vars("t0", t0, 32);

		int t1[32];
		new_vars("t1", t1, 32);

		int t2[32];
		new_vars("t2", t2, 32);

		add2(label, t0, a, b);
		add2(label, t1, c, d);
		add2(label, t2, t0, t1);
		add2(label, r, t2, e);
	} else if (config_use_compact_adders) {
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, a[i]);
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, b[i]);
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, c[i]);
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, d[i]);
		for (unsigned int i = 0; i < 32; ++i)
			opb << format("$ x$ ", 1L << i, e[i]);

		for (unsigned int i = 0; i < 32; ++i)
			opb << format("-$ x$ ", 1UL << i, r[i]);

		opb << format("= 0;\n");

		++nr_constraints;
	} else {
		std::vector<int> addends[32 + 5];
		for (unsigned int i = 0; i < 32; ++i) {
			addends[i].push_back(a[i]);
			addends[i].push_back(b[i]);
			addends[i].push_back(c[i]);
			addends[i].push_back(d[i]);
			addends[i].push_back(e[i]);

			unsigned int m = floor(log2(addends[i].size()));
			std::vector<int> rhs(1 + m);
			rhs[0] = r[i];
			new_vars(format("$_rhs[$]", label, i), &rhs[1], m);

			for (unsigned int j = 1; j < 1 + m; ++j)
				addends[i + j].push_back(rhs[j]);

			halfadder(addends[i], rhs);
		}
	}
}

// Add-on: sum-4 for MD5:
static void add4(std::string label, int r[32], int a[32], int b[32], int c[32], int d[32])
{
	comment("add4");

	std::vector<int> addends[32 + 5];
	for (unsigned int i = 0; i < 32; ++i) {
		addends[i].push_back(a[i]);
		addends[i].push_back(b[i]);
		addends[i].push_back(c[i]);
		addends[i].push_back(d[i]);

		unsigned int m = floor(log2(addends[i].size()));
		std::vector<int> rhs(1 + m);
		rhs[0] = r[i];
		new_vars(format("$_rhs[$]", label, i), &rhs[1], m);

		for (unsigned int j = 1; j < 1 + m; ++j) {
			addends[i + j].push_back(rhs[j]);
		}

		halfadder(addends[i], rhs);
	}
}

// Circular shift left:
static void rotl(int r[32], int x[32], unsigned int n)
{
	for (unsigned int i = 0; i < 32; ++i)
		r[i] = x[(i + 32 - n) % 32];
}

class sha1 {
public:
	int w[80][32];
	int h_in[5][32];
	int h_out[5][32];

	int a[85][32];

	sha1(unsigned int nr_rounds, std::string name, unsigned equal_toM_bits = 32)
	{
		assert(equal_toM_bits >= 0 && equal_toM_bits <= 32);

		comment("sha1");
		comment(format("parameter nr_rounds = $", nr_rounds));

		for (unsigned int i = 0; i < 16; ++i)
			new_vars(format("w$[$]", name, i), w[i], 32, !config_restrict_branching);

		/* XXX: Fix this later by writing directly to w[i] */
		int wt[80][32];
		for (unsigned int i = 16; i < nr_rounds; ++i) {
			new_vars(format("w$[$]", name, i), wt[i], 32);
		}

		new_vars(format("h$_in0", name), h_in[0], 32);
		new_vars(format("h$_in1", name), h_in[1], 32);
		new_vars(format("h$_in2", name), h_in[2], 32);
		new_vars(format("h$_in3", name), h_in[3], 32);
		new_vars(format("h$_in4", name), h_in[4], 32);

		new_vars(format("h$_out0", name), h_out[0], 32);
		new_vars(format("h$_out1", name), h_out[1], 32);
		new_vars(format("h$_out2", name), h_out[2], 32);
		new_vars(format("h$_out3", name), h_out[3], 32);
		new_vars(format("h$_out4", name), h_out[4], 32);

		for (unsigned int i = 0; i < nr_rounds; ++i) {
			new_vars(format("a[$]", i + 5), a[i + 5], 32);
		}

		for (unsigned int i = 16; i < nr_rounds; ++i) {
			xor4(wt[i], w[i - 3], w[i - 8], w[i - 14], w[i - 16]);
			rotl(w[i], wt[i], 1);
		}

		/* Fix constants */
		int k[4][32];
		new_constant("k[0]", k[0], 0x5a827999);
		new_constant("k[1]", k[1], 0x6ed9eba1);
		new_constant("k[2]", k[2], 0x8f1bbcdc);
		new_constant("k[3]", k[3], 0xca62c1d6);

		constant32(h_in[0], 0x67452301);
		constant32(h_in[1], 0xefcdab89);
		constant32(h_in[2], 0x98badcfe);
		constant32(h_in[3], 0x10325476);
		constant32(h_in[4], 0xc3d2e1f0);

		// a[4] == a == h0:
		rotl(a[4], h_in[0], 32 - 0);
		// a[3] == b == h1:
		rotl(a[3], h_in[1], 32 - 0);
		// a[2] == c << 2 == h2 << 2:
		rotl(a[2], h_in[2], 32 - 30);
		// a[1] == d << 2 == h3 << 2:
		rotl(a[1], h_in[3], 32 - 30);
		// a[0] == r << 2 == h4 << 2:
		rotl(a[0], h_in[4], 32 - 30);

		for (unsigned int i = 0; i < nr_rounds; ++i) {
			// prev_a = a leftrotate 5;
			// if i == 0, prev_a = a[4] << 5 == a << 5;
			// if i == 1, prev_a = a[5] << 5 == old-a << 5;
			int prev_a[32];
			rotl(prev_a, a[i + 4], 5);

			// b == a[i + 3];
			// if i == 0, b = a[3] == h1;
			// if i == 1, b = a[4] == h0 == old-a;
			int b[32];
			rotl(b, a[i + 3], 0);

			// c == a[i + 2] << 30;
			// if i == 0, c = a[2] << 30 == (h2 << 2) << 30 == h2;
			// if i == 1, c = a[3] << 30 == old-b << 30;
			int c[32];
			rotl(c, a[i + 2], 30);

			// d == a[i + 1] << 30;
			// if i == 0, d = a[1] << 30 == (h3 << 2) << 30 == h3;
			// if i == 1, d = a[2] << 30 == (h2 << 2) << 30 == h2;
			int d[32];
			rotl(d, a[i + 1], 30);

			// e == a[i + 0] << 30;
			// if i == 0, e = a[0] << 30 == (h4 << 2) << 30 == h4;
			// if i == 1, e = a[1] << 30 == (h3 << 2) << 30 == h3
			int e[32];
			rotl(e, a[i + 0], 30);

			int f[32];
			new_vars(format("f[$]", i), f, 32);

			if (i >= 0 && i < 20) {
				for (unsigned int j = 0; j < 32; ++j) {
					clause(-f[j], -b[j], c[j]);
					clause(-f[j], b[j], d[j]);
					clause(-f[j], c[j], d[j]);

					clause(f[j], -b[j], -c[j]);
					clause(f[j], b[j], -d[j]);
					clause(f[j], -c[j], -d[j]);
				}
			} else if (i >= 20 && i < 40) {
				xor3(f, b, c, d);
			} else if (i >= 40 && i < 60) {
				for (unsigned int j = 0; j < 32; ++j) {
					clause(-f[j], b[j], c[j]);
					clause(-f[j], b[j], d[j]);
					clause(-f[j], c[j], d[j]);

					clause(f[j], -b[j], -c[j]);
					clause(f[j], -b[j], -d[j]);
					clause(f[j], -c[j], -d[j]);
					//clause(f[j], -b[j], -c[j], -d[j]);
				}
			} else if (i >= 60 && i < 80) {
				xor3(f, b, c, d);
			}

			// Intermediate inversion problem if needed:
      if ((equal_toM_bits < 32) && (i == nr_rounds - 1)) {
			    // 2bitM:
			    // tempW = W[i] << 30;
    			// weakW = tempW >> 30;
			    comment(format("$bitW", equal_toM_bits));
			    int weakW[32];
			    new_vars("weakW", weakW, 32);
			    // Leftmost bits are constant 0s:
			    for (unsigned j = 0; j < 32-equal_toM_bits; j++) {
						constant(weakW[j], false);
			    }
			    // Remaining rightmost bits are equal to message:
			    for (unsigned j = 32-equal_toM_bits; j < 32; j++) {
						// Don't introduce new variables, use the remaining:
						if (config_compact_interm_enc) {
							weakW[j] = w[i][j];
						}
						else {
							eq(&weakW[j], &w[i][j], 1);
						}
			    }
			    add5(format("a[$]", i + 5), a[i + 5], prev_a, f, e, k[i / 20], weakW);
			}
			else {
			    add5(format("a[$]", i + 5), a[i + 5], prev_a, f, e, k[i / 20], w[i]);
			}
		}

		/* Rotate back */
		int c[32];
		rotl(c, a[nr_rounds + 2], 30);

		int d[32];
		rotl(d, a[nr_rounds + 1], 30);

		int e[32];
		rotl(e, a[nr_rounds + 0], 30);

		if (is_incremental_step) {
			add2("h_out", h_out[0], h_in[0], a[nr_rounds + 4]);
			add2("h_out", h_out[1], h_in[1], a[nr_rounds + 3]);
			add2("h_out", h_out[2], h_in[2], c);
			add2("h_out", h_out[3], h_in[3], d);
			add2("h_out", h_out[4], h_in[4], e);
		}
		// If incrementing is turned off, output is just a b c d:
		else {
			eq(h_out[0], a[nr_rounds + 4], 32);
			eq(h_out[1], a[nr_rounds + 3], 32);
			eq(h_out[2], c, 32);
			eq(h_out[3], d, 32);
			eq(h_out[4], e, 32);
		}
	}

};

static uint32_t rotl(uint32_t x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

static void sha1_forward(unsigned int nr_rounds, uint32_t w[80],
                         uint32_t h_out[5], unsigned equal_toM_bits = 0)
{
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	for (unsigned int i = 16; i < nr_rounds; ++i)
		w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	uint32_t a = h0;
	uint32_t b = h1;
	uint32_t c = h2;
	uint32_t d = h3;
	uint32_t e = h4;

	for (unsigned int i = 0; i < nr_rounds; ++i) {
		uint32_t f, k;

		if (i >= 0 && i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if (i >= 20 && i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (i >= 40 && i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else if (i >= 60 && i < 80) {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}

		//uint32_t t = rotl(a, 5) + f + e + k + w[i];
		// Intermediate inversion problem:
		uint32_t tempW = w[i] << equal_toM_bits;
  	uint32_t weakW = tempW >> equal_toM_bits;
		uint32_t t = rotl(a, 5) + f + e + k + weakW;
		e = d;
		d = c;
		c = rotl(b, 30);
		b = a;
		a = t;
	}

	if (is_incremental_step) {
		h_out[0] = h0 + a;
		h_out[1] = h1 + b;
		h_out[2] = h2 + c;
		h_out[3] = h3 + d;
		h_out[4] = h4 + e;
	}
	else {
		h_out[0] = a;
		h_out[1] = b;
		h_out[2] = c;
		h_out[3] = d;
		h_out[4] = e;
	}
}

// By default equal_toM_bits == 0 means that weakM_i == M_i
static void md5_forward(unsigned int nr_rounds, uint32_t M[16],
                        uint32_t h_out[4], unsigned equal_toM_bits = 0)
{
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;

	uint32_t a = h0;
	uint32_t b = h1;
	uint32_t c = h2;
	uint32_t d = h3;

	assert((equal_toM_bits >= 0) && (equal_toM_bits <= 32));

	unsigned M_index = -1;
	for (unsigned i = 0; i < nr_rounds; ++i) {
			uint32_t f = 0;
			if (i >= 0 && i < 16) {
				M_index = i;
				// F = (B and C) or ((not B) and D)
				f = (b & c) | (~b & d);
			} else if (i >= 16 && i < 32) {
				M_index = (5*i + 1) % 16;
				// F = (D and B) or ((not D) and C)
				f = (d & b) | (~d & c);
			} else if (i >= 32 && i < 48) {
				M_index = (3*i + 5) % 16;
				// F(B,C,D) = B xor C xor D: 
				f = b ^ c ^ d;
			} else if (i >= 48 && i < 64) {
				M_index = (7*i) % 16;
				// Func(B,C,D) = C xor (not D or B):
				f = c ^ (~d | b);
			}

			// Intermediate inversion problem:
			uint32_t tempM = M[M_index] << equal_toM_bits;
  		uint32_t weakM = tempM >> equal_toM_bits;

			// a = b + ((a + F(b,c,d) + M[g] + K[i]) <<< s)
			uint32_t new_val = a + f + weakM + MD5_const[i];
			//uint32_t new_val = a + f + M[M_index] + MD5_const[i];
			new_val = b + rotl(new_val, MD5_shifts[i]);
 
			a = d;
			d = c;
			c = b;
			b = new_val;
	}

	if (is_incremental_step) {
		h_out[0] = h0 + a;
		h_out[1] = h1 + b;
		h_out[2] = h2 + c;
		h_out[3] = h3 + d;
	}
	else {
		h_out[0] = a;
		h_out[1] = b;
		h_out[2] = c;
		h_out[3] = d;
	}
}

// Add-on - a class for MD5 hash function:
class md5 {
public:
	int M[16][32];
	int h_in[4][32];
	int h_out[4][32];
	int internal_states[68][32]; // size == number of steps + 4

	md5(unsigned int nr_rounds, unsigned equal_toM_bits = 32)
	{
		comment("md5");
		comment(format("parameter nr_rounds = $", nr_rounds));

		for (unsigned int i = 0; i < 16; ++i)
			new_vars(format("M[$]", i), M[i], 32, !config_restrict_branching);

		new_vars("h_in0", h_in[0], 32);
		new_vars("h_in1", h_in[1], 32);
		new_vars("h_in2", h_in[2], 32);
		new_vars("h_in3", h_in[3], 32);

		new_vars("h_out0", h_out[0], 32);
		new_vars("h_out1", h_out[1], 32);
		new_vars("h_out2", h_out[2], 32);
		new_vars("h_out3", h_out[3], 32);

		// New variables only starting from index 4 because 0..3 are equal to h_in:
		for (unsigned int i = 0; i < nr_rounds; ++i) {
			new_vars(format("internal_states[$]", i + 4), internal_states[i + 4], 32);
		}

		/* Fix constants */

		int k[64][32];
		for (unsigned i = 0; i < nr_rounds; ++i) {
			new_constant(format("k[$]", i), k[i], (int)MD5_const[i]);
		}

		constant32(h_in[0], 0x67452301);
		constant32(h_in[1], 0xEFCDAB89);
		constant32(h_in[2], 0x98BADCFE);
		constant32(h_in[3], 0x10325476);

		for (int j = 0; j < 32; j++) {
			internal_states[0][j] = h_in[0][j];
			internal_states[1][j] = h_in[1][j];
			internal_states[2][j] = h_in[2][j];
			internal_states[3][j] = h_in[3][j];
		}
		unsigned a_intern_index = 0;
		unsigned b_intern_index = 1;
		unsigned c_intern_index = 2;
		unsigned d_intern_index = 3;

		int M_index = -1;
		for (unsigned i = 0; i < nr_rounds; ++i) {
			int a[32];
			int b[32];
			int c[32];
			int d[32];
			// if i == 0:
				//          0 1 2 3
				//	intern: a b c d
				//	reg:    a b c d
			// if i == 1:
				//          0 1    2 3 4
				//	intern: a b    c d new1
				//	reg:    d new1 b c
				//	        3 4    1 2
			// if i == 2:
				//          0 1    2    3 4    5
				//  intern: a b    c    d new1 new2
				//  reg:    c new2 new1 b
				//          2 5    4    1
				// i == 3:
				//  1 6 5 4
				// i == 4:
				//  4 7 6 5
			assert(a_intern_index < i + 4); // i + 3 is the last index
			assert(b_intern_index < i + 4);
			assert(c_intern_index < i + 4);
			assert(d_intern_index < i + 4);
			assert(a_intern_index != b_intern_index);
			assert(a_intern_index != c_intern_index);
			assert(a_intern_index != d_intern_index);
			assert(b_intern_index != c_intern_index);
			assert(b_intern_index != d_intern_index);
			assert(c_intern_index != d_intern_index);
			for (unsigned j = 0; j < 32; j++) {
				a[j] = internal_states[a_intern_index][j];
				b[j] = internal_states[b_intern_index][j];
				c[j] = internal_states[c_intern_index][j];
				d[j] = internal_states[d_intern_index][j];
			}
			
			int f[32];
			new_vars(format("f[$]", i), f, 32);

			if (i >= 0 && i < 16) {
				M_index = i;
				// Bitwise if for (B,C,D): F = (B and C) or ((not B) and D)
				for (unsigned j = 0; j < 32; ++j) {
					clause(-f[j], -b[j], c[j]);
					clause(-f[j], b[j], d[j]);
					clause(-f[j], c[j], d[j]);

					clause(f[j], -b[j], -c[j]);
					clause(f[j], b[j], -d[j]);
					clause(f[j], -c[j], -d[j]);
				}
			}
			else if (i >= 16 && i < 32) {
				M_index = (5*i + 1) % 16;
				// Bitwise if for (D,B,C): F = (D and B) or ((not D) and C)
				for (unsigned j = 0; j < 32; ++j) {
					clause(-f[j], -d[j], b[j]);
					clause(-f[j], d[j], c[j]);
					clause(-f[j], b[j], c[j]);

					clause(f[j], -d[j], -b[j]);
					clause(f[j], d[j], -c[j]);
					clause(f[j], -b[j], -c[j]);
				}
			} 
			else if (i >= 32 && i < 48) {
				M_index = (3*i + 5) % 16;
				// F(B,C,D) = B xor C xor D: 
				xor3(f, b, c, d);
			}
			else if (i >= 48 && i < 64) {
				M_index = (7*i) % 16;
				// Func(B,C,D) = C xor (not D or B):
				for (unsigned j = 0; j < 32; ++j) {
					clause(f[j], b[j], c[j], d[j]);
					clause(f[j], b[j], -c[j], -d[j]);
					clause(f[j], -b[j], c[j], d[j]);
					clause(f[j], -b[j], c[j], -d[j]);
					clause(-f[j], b[j], c[j], -d[j]);
					clause(-f[j], b[j], -c[j], d[j]);
					clause(-f[j], -b[j], -c[j], d[j]);
					clause(-f[j], -b[j], -c[j], -d[j]);
				}
			}

			// a = b + ((a + F(b,c,d) + M[g] + K[i]) <<< s)
			int temp1[32];
			new_vars(format("temp1 on i==$", i), temp1, 32);
			// temp1 = a + F(b,c,d) + M[g] + K[i]
			// Intermediate inversion problem if needed:
      if ((equal_toM_bits < 32) && (i == nr_rounds - 1)) {
			    // 2bitM:
			    // tempW = W[i] << 30;
    			// weakW = tempW >> 30;
			    comment(format("$bitM", equal_toM_bits));
			    int weakM[32];
			    new_vars("weakM", weakM, 32);
			    // Leftmost bits are constant 0s:
			    for (unsigned j = 0; j < 32-equal_toM_bits; j++) {
						constant(weakM[j], false);
			    }
			    // Remaining rightmost bits are equal to message:
			    for (unsigned j = 32-equal_toM_bits; j < 32; j++) {
					if (config_compact_interm_enc) {
						weakM[j] = M[M_index][j];
					}
					else {
						eq(&weakM[j], &M[M_index][j], 1);
					}
			    }
					add4(format("add4 on i==$", i), temp1, a, f, weakM, k[i]);
			}
			else {
					// standard call:
			    add4(format("add4 on i==$", i), temp1, a, f, M[M_index], k[i]);
			}
			int temp2[32];
			new_vars(format("temp2 on i==$", i), temp2, 32);
			rotl(temp2, temp1, MD5_shifts[i]);
			// new internal state to update b:
			assert(i + 4 < 68);
			add2(format("add2 on i==$", i), internal_states[i + 4], b, temp2);
			
			//add2(format("add2 on i==$", i), internal_states[i + 4], M[M_index], b);
 
			// update indicies:
			a_intern_index = d_intern_index;
			d_intern_index = c_intern_index;
			c_intern_index = b_intern_index;
			b_intern_index = i + 4;
		}

		int a[32];
		int b[32];
		int c[32];
		int d[32];
		for (unsigned j = 0; j < 32; j++) {
			a[j] = internal_states[a_intern_index][j];
			b[j] = internal_states[b_intern_index][j];
			c[j] = internal_states[c_intern_index][j];
			d[j] = internal_states[d_intern_index][j];
		}

		// If incrementing is turned on, output is A B C D, where:
		// A = A + AA
		// B = B + BB
		// C = C + CC
		// D = D + DD
		if (is_incremental_step) {
			add2("h_out", h_out[0], a, h_in[0]);
			add2("h_out", h_out[1], b, h_in[1]);
			add2("h_out", h_out[2], c, h_in[2]);
			add2("h_out", h_out[3], d, h_in[3]);
		}
		// If incrementing is turned off, output is just a b c d:
		else {
			eq(h_out[0], a, 32);
			eq(h_out[1], b, 32);
			eq(h_out[2], c, 32);
			eq(h_out[3], d, 32);
		}
	}

};

// Find an MD5's preimage:
static void preimage_md5()
{
	if (config_nr_rounds > 64) {
		config_nr_rounds = 64;
		comment(format("nr_rounds was changed to $", config_nr_rounds));
	}
	//md5 f(config_nr_rounds, "", config_equal_toM_bits);
	md5 f(config_nr_rounds, config_equal_toM_bits);

	/* Generate a known-valid (message, hash)-pair */
	uint32_t M[16];

	if (config_message_file == "") {
		for (unsigned int i = 0; i < 16; ++i)
			M[i] = lrand48();
	}
	else {
		std::ifstream mes_file(config_message_file);
		std::string s;
		unsigned i = 0;
		comment("Message was read from file " + config_message_file);
		comment("Message :");
		while (getline(mes_file, s)) {
			if (s.find("x") != std::string::npos) {
					std::cerr << "Message should be decimal." << '\n';
					exit(1);
			}
			std::istringstream isstream(s);
			uint32_t ui;
			isstream >> ui;
			M[i] = ui;
			comment(format("M[$] = $", i, M[i]));
			i++;
			//std::cout << ui << std::endl;
		}
		assert(i == 16);
	}

	uint32_t h[4];
	md5_forward(config_nr_rounds, M, h, config_equal_toM_bits);
	comment(format("h[0] : $", h[0]));
	comment(format("h[1] : $", h[0]));
	comment(format("h[2] : $", h[0]));
	comment(format("h[3] : $", h[0]));

	/* Fix message bits */
	comment(format("Fix $ message bits", config_nr_message_bits));

	std::vector<unsigned int> message_bits(512);
	for (unsigned int i = 0; i < 512; ++i)
		message_bits[i] = i;

	//std::random_shuffle(message_bits.begin(), message_bits.end());
	for (unsigned int i = 0; i < config_nr_message_bits; ++i) {
		unsigned int r = message_bits[i] / 32; // max(r) == 15
		unsigned int s = message_bits[i] % 32; // max(s) == 31

		constant(f.M[r][s], (M[r] >> s) & 1);
	}

	// Fix hash bits
	if (config_nr_hash_bits > 128) {
		config_nr_hash_bits = 128;
	}

	comment(format("Fix $ hash bits", config_nr_hash_bits));
	std::vector<unsigned int> hash_bits(128);
	for (unsigned int i = 0; i < 128; ++i) {
		hash_bits[i] = i;
	}

	for (unsigned i = 0; i < config_nr_hash_bits; ++i) {
		unsigned r = hash_bits[i] / 32;
		unsigned s = hash_bits[i] % 32;
		assert(r < 4);
		assert(s < 32);
		// If no hash value is given:
		if (config_hash_value == -1) { 
			constant(f.h_out[r][s], (h[r] >> s) & 1);
		}
		else {
			// If config_hash_value == 0 (1), all hash bits are 0 (1):
			assert(config_hash_value == 0 || config_hash_value == 1);
			constant(f.h_out[r][s], (bool)config_hash_value);
		}
	}
}

// Add-on - a class for MD5 hash function:
class md4 {
public:
	int M[16][32];
	int h_in[4][32];
	int h_out[4][32];
	int internal_states[52][32]; // size == number of steps + 4

	md4(unsigned int nr_rounds, unsigned equal_toM_bits = 32)
	{
		comment("md4");
		comment(format("parameter nr_rounds = $", nr_rounds));

		assert(nr_rounds <= 48);

		for (unsigned int i = 0; i < 16; ++i) {
			new_vars(format("M[$]", i), M[i], 32, !config_restrict_branching);
		}

		new_vars("h_in0", h_in[0], 32);
		new_vars("h_in1", h_in[1], 32);
		new_vars("h_in2", h_in[2], 32);
		new_vars("h_in3", h_in[3], 32);

		new_vars("h_out0", h_out[0], 32);
		new_vars("h_out1", h_out[1], 32);
		new_vars("h_out2", h_out[2], 32);
		new_vars("h_out3", h_out[3], 32);

		// New variables only starting from index 4 because 0..3 are equal to h_in:
		for (unsigned int i = 0; i < nr_rounds; ++i) {
			new_vars(format("internal_states[$]", i + 4), internal_states[i + 4], 32);
		}

		// Fix constants:
		int MD4_constants[3][32];
		new_constant("MD4_constants[0]", MD4_constants[0], 0x0);
		new_constant("MD4_constants[1]", MD4_constants[1], 0x5A827999);
		new_constant("MD4_constants[2]", MD4_constants[2], 0x6ED9EBA1);

		// Fix registers' initial value: 
		constant32(h_in[0], 0x67452301);
		constant32(h_in[1], 0xEFCDAB89);
		constant32(h_in[2], 0x98BADCFE);
		constant32(h_in[3], 0x10325476);

		for (int j = 0; j < 32; j++) {
			internal_states[0][j] = h_in[0][j];
			internal_states[1][j] = h_in[1][j];
			internal_states[2][j] = h_in[2][j];
			internal_states[3][j] = h_in[3][j];
		}
		unsigned a_intern_index = 0;
		unsigned b_intern_index = 1;
		unsigned c_intern_index = 2;
		unsigned d_intern_index = 3;

		for (unsigned i = 0; i < nr_rounds; ++i) {
			int a[32];
			int b[32];
			int c[32];
			int d[32];
			assert(a_intern_index < i + 4); // i + 3 is the last index
			assert(b_intern_index < i + 4);
			assert(c_intern_index < i + 4);
			assert(d_intern_index < i + 4);
			assert(a_intern_index != b_intern_index);
			assert(a_intern_index != c_intern_index);
			assert(a_intern_index != d_intern_index);
			assert(b_intern_index != c_intern_index);
			assert(b_intern_index != d_intern_index);
			assert(c_intern_index != d_intern_index);
			for (unsigned j = 0; j < 32; j++) {
				a[j] = internal_states[a_intern_index][j];
				b[j] = internal_states[b_intern_index][j];
				c[j] = internal_states[c_intern_index][j];
				d[j] = internal_states[d_intern_index][j];
			}
			
			int f[32];
			new_vars(format("f[$]", i), f, 32);

			if (i >= 0 && i < 16) {
				// f = (b and c) or ((not b) and d)
				for (unsigned j = 0; j < 32; ++j) {
					clause(-f[j], -b[j], c[j]);
					clause(-f[j], b[j], d[j]);
					clause(-f[j], c[j], d[j]);
					clause(f[j], -b[j], -c[j]);
					clause(f[j], b[j], -d[j]);
					clause(f[j], -c[j], -d[j]);
				}
			}
			else if (i >= 16 && i < 32) {
				// f = (b and c) or (b and d) or (c and d)
				for (unsigned j = 0; j < 32; ++j) {
					clause(-f[j], b[j], c[j]);
					clause(-f[j], b[j], d[j]);
					clause(-f[j], c[j], d[j]);
					clause(f[j], -b[j], -c[j]);
					clause(f[j], -b[j], -d[j]);
					clause(f[j], -c[j], -d[j]);
				}
			} 
			else if (i >= 32 && i < 48) {
				// F(B,C,D) = B xor C xor D: 
				xor3(f, b, c, d);
			}

			// a = b + ((a + F(b,c,d) + M[g] + K[i]) <<< s)
			int sum[32];
			new_vars(format("sum on i==$", i), sum, 32);
			// sum = a + F(b,c,d) + M[g] + K[i]
			// Intermediate inversion problem if needed:
      if ((equal_toM_bits < 32) && (i == nr_rounds - 1)) {
			    // 2bitM:
			    // tempW = W[i] << 30;
    			// weakW = tempW >> 30;
			    comment(format("$bitM", equal_toM_bits));
			    int weakM[32];
			    new_vars("weakM", weakM, 32);
			    // Leftmost bits are constant 0s:
			    for (unsigned j = 0; j < 32-equal_toM_bits; j++) {
						constant(weakM[j], false);
			    }
			    // Remaining rightmost bits are equal to message:
			    for (unsigned j = 32-equal_toM_bits; j < 32; j++) {
					if (config_compact_interm_enc) {
						weakM[j] = M[MD4_M_indicies[i]][j];
					}
					else {
						eq(&weakM[j], &M[MD4_M_indicies[i]][j], 1);
					}
			    }
					add4(format("add4 on i==$", i), sum, a, f, weakM, MD4_constants[i / 16]);
			}
			else {
					// standard call:
			    add4(format("add4 on i==$", i), sum, a, f, M[MD4_M_indicies[i]], MD4_constants[i / 16]);
			}
			// new internal state = sum <<< s:
			rotl(internal_states[i + 4], sum, MD4_shifts[i]);
 
			// update indicies:
			a_intern_index = d_intern_index;
			d_intern_index = c_intern_index;
			c_intern_index = b_intern_index;
			b_intern_index = i + 4;
		}

		int a[32];
		int b[32];
		int c[32];
		int d[32];
		for (unsigned j = 0; j < 32; j++) {
			a[j] = internal_states[a_intern_index][j];
			b[j] = internal_states[b_intern_index][j];
			c[j] = internal_states[c_intern_index][j];
			d[j] = internal_states[d_intern_index][j];
		}

		// If incrementing is turned on, output is A B C D, where:
		// A = A + AA
		// B = B + BB
		// C = C + CC
		// D = D + DD
		if (is_incremental_step) {
			add2("h_out", h_out[0], a, h_in[0]);
			add2("h_out", h_out[1], b, h_in[1]);
			add2("h_out", h_out[2], c, h_in[2]);
			add2("h_out", h_out[3], d, h_in[3]);
		}
		// If incrementing is turned off, output is just a b c d:
		else {
			eq(h_out[0], a, 32);
			eq(h_out[1], b, 32);
			eq(h_out[2], c, 32);
			eq(h_out[3], d, 32);
		}
	}

};

// By default equal_toM_bits == 0 means that weakM_i == M_i
static void md4_forward(unsigned int nr_rounds, uint32_t M[16],
                        uint32_t h_out[4], unsigned equal_toM_bits = 0)
{
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;

	uint32_t a = h0;
	uint32_t b = h1;
	uint32_t c = h2;
	uint32_t d = h3;

	assert((equal_toM_bits >= 0) && (equal_toM_bits <= 32));

	unsigned K = 0x0;

	for (unsigned i = 0; i < nr_rounds; ++i) {
			uint32_t f = 0;
			if (i >= 0 && i < 16) {
				f = (b & c) | (~b & d);
				K = 0x0;
			} else if (i >= 16 && i < 32) {
				f = (b & c) | (b & d) | (c & d);
				K = 0x5A827999;
			} else if (i >= 32 && i < 48) {
				f = b ^ c ^ d;
				K = 0x6ED9EBA1;
			}

			// Intermediate inversion problem:
			uint32_t tempM = M[MD4_M_indicies[i]] << equal_toM_bits;
  		uint32_t weakM = tempM >> equal_toM_bits;

			// a = (a + F(b,c,d) + M[g] + K[i]) <<< s
			uint32_t new_val = a + f + weakM + K;
			new_val = rotl(new_val, MD4_shifts[i]);
 
			a = d;
			d = c;
			c = b;
			b = new_val;
	}

	if (is_incremental_step) {
		h_out[0] = h0 + a;
		h_out[1] = h1 + b;
		h_out[2] = h2 + c;
		h_out[3] = h3 + d;
	}
	else {
		h_out[0] = a;
		h_out[1] = b;
		h_out[2] = c;
		h_out[3] = d;
	}
}

// Find an MD4's preimage:
static void preimage_md4()
{
	if (config_nr_rounds > 48) {
		config_nr_rounds = 48;
		comment(format("nr_rounds was changed to $", config_nr_rounds));
	}
	md4 f(config_nr_rounds, config_equal_toM_bits);

	/* Generate a known-valid (message, hash)-pair */
	uint32_t M[16];

	if (config_message_file == "") {
		for (unsigned int i = 0; i < 16; ++i)
			M[i] = lrand48();
	}
	else {
		std::ifstream mes_file(config_message_file);
		std::string s;
		unsigned i = 0;
		comment("Message was read from file " + config_message_file);
		comment("Message :");
		while (getline(mes_file, s)) {
			if (s.find("x") != std::string::npos) {
					std::cerr << "Message should be decimal." << '\n';
					exit(1);
			}
			std::istringstream isstream(s);
			uint32_t ui;
			isstream >> ui;
			M[i] = ui;
			comment(format("M[$] = $", i, M[i]));
			i++;
			//std::cout << ui << std::endl;
		}
		assert(i == 16);
	}

	uint32_t h[4];
	md4_forward(config_nr_rounds, M, h, config_equal_toM_bits);
	comment(format("h[0] : $", h[0]));
	comment(format("h[1] : $", h[0]));
	comment(format("h[2] : $", h[0]));
	comment(format("h[3] : $", h[0]));

	/* Fix message bits */
	comment(format("Fix $ message bits", config_nr_message_bits));

	std::vector<unsigned int> message_bits(512);
	for (unsigned int i = 0; i < 512; ++i)
		message_bits[i] = i;

	//std::random_shuffle(message_bits.begin(), message_bits.end());
	for (unsigned int i = 0; i < config_nr_message_bits; ++i) {
		unsigned int r = message_bits[i] / 32; // max(r) == 15
		unsigned int s = message_bits[i] % 32; // max(s) == 31

		constant(f.M[r][s], (M[r] >> s) & 1);
	}

	// Fix hash bits
	if (config_nr_hash_bits > 128) {
		config_nr_hash_bits = 128;
	}

	comment(format("Fix $ hash bits", config_nr_hash_bits));
	std::vector<unsigned int> hash_bits(128);
	for (unsigned int i = 0; i < 128; ++i) {
		hash_bits[i] = i;
	}

	for (unsigned i = 0; i < config_nr_hash_bits; ++i) {
		unsigned r = hash_bits[i] / 32;
		unsigned s = hash_bits[i] % 32;
		assert(r < 4);
		assert(s < 32);
		// If no hash value is given:
		if (config_hash_value == -1) { 
			constant(f.h_out[r][s], (h[r] >> s) & 1);
		}
		else {
			// If config_hash_value == 0 (1), all hash bits are 0 (1):
			assert(config_hash_value == 0 || config_hash_value == 1);
			constant(f.h_out[r][s], (bool)config_hash_value);
		}
	}
}

// SHA-1
static void preimage_sha1()
{
	sha1 f(config_nr_rounds, "", config_equal_toM_bits);

	/* Generate a known-valid (message, hash)-pair */
	uint32_t w[80];

	if (config_message_file == "") {
		for (unsigned int i = 0; i < 16; ++i)
			w[i] = lrand48();
	}
	else {
		std::ifstream mes_file(config_message_file);
		std::string s;
		unsigned i = 0;
		comment("Message was read from file " + config_message_file);
		comment("Message :");
		while (getline(mes_file, s)) {
			std::istringstream isstream(s);
			uint32_t ui;
			isstream >> ui;
			w[i] = ui;
			comment(format("w[$] = $", i, w[i]));
			i++;
			//std::cout << ui << std::endl;
		}
		assert(i == 16);
	}

	uint32_t h[5];
	sha1_forward(config_nr_rounds, w, h, config_equal_toM_bits);

	/* Fix message bits */
	comment(format("Fix $ message bits", config_nr_message_bits));

	std::vector<unsigned int> message_bits(512);
	for (unsigned int i = 0; i < 512; ++i)
		message_bits[i] = i;

	//std::random_shuffle(message_bits.begin(), message_bits.end());
	for (unsigned int i = 0; i < config_nr_message_bits; ++i) {
		unsigned int r = message_bits[i] / 32;
		unsigned int s = message_bits[i] % 32;

		constant(f.w[r][s], (w[r] >> s) & 1);
	}

	/* Fix hash bits */
	comment(format("Fix $ hash bits", config_nr_hash_bits));

	std::vector<unsigned int> hash_bits(160);
	for (unsigned int i = 0; i < 160; ++i)
		hash_bits[i] = i;

	//std::random_shuffle(hash_bits.begin(), hash_bits.end());
	for (unsigned int i = 0; i < config_nr_hash_bits; ++i) {
		unsigned int r = hash_bits[i] / 32;
		unsigned int s = hash_bits[i] % 32;

		// If no hash value is give:
		if (config_hash_value == -1) { 
			constant(f.h_out[r][s], (h[r] >> s) & 1);
		}
		else {
			// If config_hash_value == 0 (1), all hash bits are 0 (1):
			assert(config_hash_value == 0 || config_hash_value == 1);
			constant(f.h_out[r][s], (bool)config_hash_value);
		}
	}
}

/* The second preimage differs from the first preimage by flipping one of
 * the message bits. */
static void second_preimage_sha1()
{
	sha1 f(config_nr_rounds, "");

	/* Generate a known-valid (message, hash)-pair */
	uint32_t w[80];
	for (unsigned int i = 0; i < 16; ++i)
		w[i] = lrand48();

	uint32_t h[5];
	sha1_forward(config_nr_rounds, w, h);

	/* Fix message bits */
	comment(format("Fix $ message bits", config_nr_message_bits));

	std::vector<unsigned int> message_bits(512);
	for (unsigned int i = 0; i < 512; ++i)
		message_bits[i] = i;

	std::random_shuffle(message_bits.begin(), message_bits.end());

	/* Flip the first bit */
	if (config_nr_message_bits > 0) {
		unsigned int r = message_bits[0] / 32;
		unsigned int s = message_bits[0] % 32;

		constant(f.w[r][s], !((w[r] >> s) & 1));
	}

	for (unsigned int i = 1; i < config_nr_message_bits; ++i) {
		unsigned int r = message_bits[i] / 32;
		unsigned int s = message_bits[i] % 32;

		constant(f.w[r][s], (w[r] >> s) & 1);
	}

	/* Fix hash bits */
	comment(format("Fix $ hash bits", config_nr_hash_bits));

	std::vector<unsigned int> hash_bits(160);
	for (unsigned int i = 0; i < 160; ++i)
		hash_bits[i] = i;

	//std::random_shuffle(hash_bits.begin(), hash_bits.end());
	for (unsigned int i = 0; i < config_nr_hash_bits; ++i) {
		unsigned int r = hash_bits[i] / 32;
		unsigned int s = hash_bits[i] % 32;

		constant(f.h_out[r][s], (h[r] >> s) & 1);
	}
}

static void collision_sha1()
{
	sha1 f(config_nr_rounds, "0");
	sha1 g(config_nr_rounds, "1");

	if (config_nr_message_bits > 0)
		std::cerr << "warning: collision attacks do not use fixed message bits\n";

	/* Fix message bits (set m != m') */
	comment(format("Fix $ message bits", config_nr_message_bits));

	std::vector<unsigned int> message_bits(512);
	for (unsigned int i = 0; i < 512; ++i)
		message_bits[i] = i;

	std::random_shuffle(message_bits.begin(), message_bits.end());

	/* Flip some random bit */
	{
		unsigned int r = message_bits[0] / 32;
		unsigned int s = message_bits[0] % 32;

		neq(&f.w[r][s], &g.w[r][s], 1);
	}

	/* Fix hash bits (set H = H') */
	comment(format("Fix $ hash bits", config_nr_hash_bits));

	std::vector<unsigned int> hash_bits(160);
	for (unsigned int i = 0; i < 160; ++i)
		hash_bits[i] = i;

	//std::random_shuffle(hash_bits.begin(), hash_bits.end());
	for (unsigned int i = 0; i < config_nr_hash_bits; ++i) {
		unsigned int r = hash_bits[i] / 32;
		unsigned int s = hash_bits[i] % 32;

		eq(&f.h_out[r][s], &g.h_out[r][s], 1);
	}
}

int main(int argc, char *argv[])
{
	unsigned long seed = time(0);

	/* Process command line */
	{
		using namespace boost::program_options;

		options_description options("Options");
		options.add_options()
			("help,h", "Display this information")
		;

		options_description instance_options("Instance options");
		instance_options.add_options()
			("seed", value<unsigned long>(&seed), "Random number seed")
			("attack", value<std::string>(), "Attack type (preimage, second-preimage, collision)")
			("rounds", value<unsigned int>(&config_nr_rounds), "Number of rounds (16-80)")
			("message-bits", value<unsigned int>(&config_nr_message_bits), "Number of fixed message bits (0-512)")
			("message-file", value<std::string>(), "File name with message")
			("hash-bits", value<unsigned int>(&config_nr_hash_bits), "Number of fixed hash bits (0-160)")
			("hash-value", value<int>(&config_hash_value), "Hash value (0 | 1)")
			("equal-toM-bits", value<unsigned int>(&config_equal_toM_bits), "Number of unknown message bits on the last step (0-32)")
			("hash-function", value<std::string>(), "Hash function (sha1 | md5)")
			("incremental-step", value<unsigned int>(&is_incremental_step), "Whether the incremental step is done after the last step")
			("compact-interm-enc", "Compact intermediate preimage attacks encoding")
		;

		options_description format_options("Format options");
		format_options.add_options()
			("cnf", "Generate CNF")
			("opb", "Generate OPB")
			("tseitin-adders", "Use Tseitin encoding of the circuit representation of adders");
		;

		options_description cnf_options("CNF-specific options");
		cnf_options.add_options()
			("xor", "Use XOR clauses")
			("halfadder", "Use half-adder clauses")
			("restrict-branching", "Restrict branching variables to message bits")
		;

		options_description opb_options("OPB-specific options");
		opb_options.add_options()
			("compact-adders", "Use compact adders")
		;

		options_description all_options;
		all_options.add(options);
		all_options.add(instance_options);
		all_options.add(format_options);
		all_options.add(cnf_options);
		all_options.add(opb_options);

		positional_options_description p;
		p.add("input", -1);

		variables_map map;
		store(command_line_parser(argc, argv)
			.options(all_options)
			.positional(p)
			.run(), map);
		notify(map);

		if (map.count("help")) {
			std::cout << all_options;
			return 0;
		}

		if (map.count("attack") == 1) {
			config_attack = map["attack"].as<std::string>();
		} else if (map.count("attack") > 1) {
			std::cerr << "Can only specify --attack once\n";
			return EXIT_FAILURE;
		}
		if (config_attack != "preimage" && config_attack != "second-preimage" && config_attack != "collision") {
			std::cerr << "Invalid --attack\n";
			return EXIT_FAILURE;
		}

		if (map.count("message-file") == 1) {
			config_message_file = map["message-file"].as<std::string>();
		} else if (map.count("message-file") > 1) {
			std::cerr << "Can only specify --message-file once\n";
			return EXIT_FAILURE;
		}

		if (map.count("hash-function") == 1) {
			config_hash_function = map["hash-function"].as<std::string>();
		} else if (map.count("hash-function") > 1) {
			std::cerr << "Can only specify --hash-function once\n";
			return EXIT_FAILURE;
		}

		if (config_hash_function != "sha1" && 
		    config_hash_function != "md5" &&
		    config_hash_function != "md4") {
			std::cerr << "Invalid --hash-function\n";
			return EXIT_FAILURE;
		}

		if (map.count("compact-interm-enc"))
			config_compact_interm_enc = true;

		if (map.count("cnf"))
			config_cnf = true;

		if (map.count("opb"))
			config_opb = true;

		if (map.count("tseitin-adders"))
			config_use_tseitin_adders = true;

		if (map.count("xor"))
			config_use_xor_clauses = true;

		if (map.count("halfadder"))
			config_use_halfadder_clauses = true;

		if (map.count("restrict-branching"))
			config_restrict_branching = true;

		if (map.count("compact-adders"))
			config_use_compact_adders = true;
	}

	assert(is_incremental_step == 0 || is_incremental_step == 1);

	if (!config_cnf && !config_opb) {
		std::cerr << "Must specify either --cnf or --opb\n";
		return EXIT_FAILURE;
	}

	if (config_use_xor_clauses && !config_cnf) {
		std::cerr << "Cannot specify --xor without --cnf\n";
		return EXIT_FAILURE;
	}

	if (config_use_halfadder_clauses && !config_cnf) {
		std::cerr << "Cannot specify --halfadder without --cnf\n";
		return EXIT_FAILURE;
	}

	if (config_use_compact_adders && !config_opb) {
		std::cerr << "Cannot specify --compact-adders without --opb\n";
		return EXIT_FAILURE;
	}

	comment("");
	comment("Instance generated by sha1-sat");
	comment("");

	/* Include command line in instance */
	{
		std::ostringstream ss;

		ss << argv[0];

		for (int i = 1; i < argc; ++i) {
			ss << " ";
			ss << argv[i];
		}

		comment(format("command line: $", ss.str()));
	}

	comment(format("parameter seed = $", seed));
	srand(seed);
	srand48(rand());

	if (config_attack == "preimage") {
		if (config_hash_function == "sha1") {
			preimage_sha1();
		}
		else if (config_hash_function == "md5") {
			preimage_md5();
		}
		else if (config_hash_function == "md4") {
			preimage_md4();
		}
	} else if (config_attack == "second-preimage") {
		second_preimage_sha1();
	} else if (config_attack == "collision") {
		collision_sha1();
	}	

	if (config_cnf) {
		std::cout
			<< format("p cnf $ $\n", nr_variables, nr_clauses)
			<< cnf.str();
	}

	if (config_opb) {
		std::cout
			<< format("* #variable= $ #constraint= $\n", nr_variables, nr_constraints)
			<< opb.str();
	}

	return 0;
}
