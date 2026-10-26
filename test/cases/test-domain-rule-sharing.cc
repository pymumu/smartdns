/* Configuration ownership regressions: edits must affect only their target. */
#include "gtest/gtest.h"
#include "dns_conf/domain_rule.h"
#include "dns_conf/dns_conf_group.h"
#include <string>

extern "C" { extern struct dns_conf_group_info *dns_conf_current_group_info; }

class DomainRuleSharing : public ::testing::Test {
protected:
	dns_conf_group group{};
	dns_conf_group_info info{};
	dns_conf_group_info *previous = nullptr;
	void SetUp() override {
		previous = _config_current_group();
		info.rule = &group;
		art_tree_init(&group.domain_rule.tree);
		_config_set_current_group(&info);
	}
	void reset() {
		art_iter(&group.domain_rule.tree, _config_domain_iter_free, nullptr);
		art_tree_destroy(&group.domain_rule.tree);
		_config_domain_rule_pool_clear();
		art_tree_init(&group.domain_rule.tree);
	}
	void TearDown() override { reset(); art_tree_destroy(&group.domain_rule.tree); dns_conf_current_group_info = previous; }
	dns_rule_flags *flags(const std::string &name) {
		return static_cast<dns_rule_flags *>(dns_conf_get_domain_rule(name.c_str(), DOMAIN_RULE_FLAGS));
	}
};

TEST_F(DomainRuleSharing, BulkOverridesGrowthRemovalAndDeletionRemainIndependent)
{
	for (int i = 0; i < 257; i++) {
		auto name = "block" + std::to_string(i) + ".test";
		ASSERT_EQ(_config_domain_rule_flag_set(name.c_str(), DOMAIN_FLAG_ADDR_SOA, 0), 0);
		ASSERT_EQ(_config_domain_rule_flag_set(name.c_str(), DOMAIN_FLAG_ADDR_SOA, 0), 0); // overlapping lists
	}
	ASSERT_EQ(_config_domain_rule_flag_set("block0.test", DOMAIN_FLAG_ADDR_SOA, 1), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("block0.test", DOMAIN_FLAG_NO_CACHE, 0), 0);
	auto ttl = static_cast<dns_ttl_rule *>(_new_dns_rule(DOMAIN_RULE_TTL));
	ASSERT_NE(ttl, nullptr);
	ttl->ttl = 123;
	EXPECT_EQ(_config_domain_rule_add("block1.test", DOMAIN_RULE_TTL, ttl), 0);
	_dns_rule_put(&ttl->head);
	ASSERT_NE(dns_conf_get_domain_rule("block1.test", DOMAIN_RULE_TTL), nullptr);
	EXPECT_EQ(_config_domain_rule_remove("block1.test", DOMAIN_RULE_TTL), 0);
	// Removing a missing high-numbered type must not read past a sparse leaf.
	EXPECT_EQ(_config_domain_rule_remove("block2.test", DOMAIN_RULE_TTL), 0);
	EXPECT_EQ(_config_domain_rule_remove("block3.test", DOMAIN_RULE_FLAGS), 0);
	EXPECT_EQ(_config_domain_rule_delete("block4.test"), 0);
	EXPECT_EQ(dns_conf_get_domain_rule("block3.test", DOMAIN_RULE_FLAGS), nullptr);
	EXPECT_EQ(dns_conf_get_domain_rule("block4.test", DOMAIN_RULE_FLAGS), nullptr);
	ASSERT_NE(flags("block0.test"), nullptr);
	EXPECT_EQ(flags("block0.test")->flags, static_cast<unsigned>(DOMAIN_FLAG_NO_CACHE));
	EXPECT_EQ(flags("block0.test")->is_flag_set, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA | DOMAIN_FLAG_NO_CACHE));
	for (int i = 1; i < 257; i++) {
		if (i == 3 || i == 4) continue;
		auto name = "block" + std::to_string(i) + ".test";
		ASSERT_NE(flags(name), nullptr);
		EXPECT_EQ(flags(name)->flags, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA)) << name;
		EXPECT_EQ(flags(name)->is_flag_set, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA)) << name;
		EXPECT_EQ(dns_conf_get_domain_rule(name.c_str(), DOMAIN_RULE_TTL), nullptr);
	}
}

TEST_F(DomainRuleSharing, ExplicitClearAndUnsetAndWildcardScopesStayDistinct)
{
	ASSERT_EQ(_config_domain_rule_flag_set("clear.test", DOMAIN_FLAG_ADDR_SOA, 1), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("unset.test", 0, 0), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("*.sub.test", DOMAIN_FLAG_ADDR_SOA, 0), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("-.root.test", DOMAIN_FLAG_ADDR_SOA, 0), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("plain.test", DOMAIN_FLAG_ADDR_SOA, 0), 0);
	ASSERT_EQ(_config_domain_rule_flag_set("plain.test", DOMAIN_FLAG_ADDR_IGN, 0), 0);
	ASSERT_NE(flags("clear.test"), nullptr);
	ASSERT_NE(flags("unset.test"), nullptr);
	EXPECT_EQ(flags("clear.test")->flags, 0U);
	EXPECT_EQ(flags("clear.test")->is_flag_set, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA));
	EXPECT_EQ(flags("unset.test")->flags, 0U);
	EXPECT_EQ(flags("unset.test")->is_flag_set, 0U);
	ASSERT_NE(flags("*.sub.test"), nullptr);
	ASSERT_NE(flags("-.root.test"), nullptr);
	EXPECT_EQ(flags("*.sub.test")->head.sub_only, 1);
	EXPECT_EQ(flags("*.sub.test")->head.root_only, 0);
	EXPECT_EQ(flags("-.root.test")->head.root_only, 1);
	EXPECT_EQ(flags("-.root.test")->head.sub_only, 0);
	EXPECT_EQ(flags("*.sub.test")->flags, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA));
	EXPECT_EQ(flags("-.root.test")->flags, static_cast<unsigned>(DOMAIN_FLAG_ADDR_SOA));
}

TEST_F(DomainRuleSharing, BoundedPoolFallbackPreservesEveryDistinctValueAcrossTeardown)
{
	for (int cycle = 0; cycle < 3; cycle++) {
		for (unsigned i = 0; i < 2048; i++) {
			auto name = "distinct" + std::to_string(i) + ".test";
			ASSERT_EQ(_config_domain_rule_flag_set(name.c_str(), i, 0), 0);
		}
		for (unsigned i = 0; i < 2048; i += 7) {
			auto name = "distinct" + std::to_string(i) + ".test";
			ASSERT_EQ(_config_domain_rule_flag_set(name.c_str(), DOMAIN_FLAG_ADDR_IPV4_IGN, 1), 0);
		}
		for (unsigned i = 0; i < 2048; i++) {
			auto name = "distinct" + std::to_string(i) + ".test";
			ASSERT_NE(flags(name), nullptr);
			unsigned mask = i % 7 == 0 ? DOMAIN_FLAG_ADDR_IPV4_IGN : 0;
			EXPECT_EQ(flags(name)->flags, i & ~mask);
			EXPECT_EQ(flags(name)->is_flag_set, i | mask);
		}
		reset();
	}
}

