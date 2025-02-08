/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dns_rules.h"
#include "gtest/gtest.h"

#include <map>

class DomainRules : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DomainRules, order)
{
	struct dns_domain_rule *domain_rule = domain_rule_new(1);
	ASSERT_NE(domain_rule, nullptr);

	std::map<int, struct dns_rule *> rules;
	for (int i = 0; i < DOMAIN_RULE_MAX; ++i) {
		struct dns_rule *rule = (struct dns_rule *)_new_dns_rule((enum domain_rule)i);
		EXPECT_NE(rule, nullptr);
		rules[i] = rule;
		EXPECT_EQ(domain_rule_set(domain_rule, (enum domain_rule)i, rule), i == DOMAIN_RULE_FLAGS ? -1 : 0);
	}

	EXPECT_EQ(domain_rule_get(domain_rule, DOMAIN_RULE_FLAGS), nullptr);
	for (int i = 1; i < DOMAIN_RULE_MAX; ++i) {
		EXPECT_EQ(domain_rule_get(domain_rule, (enum domain_rule)i), rules[i]);
	}

	struct dns_rule_flags *rule_flags = domain_rule_get_or_insert_flags(domain_rule);
	EXPECT_NE(rule_flags, nullptr);
	EXPECT_EQ(rule_flags->flags, 0);
}
