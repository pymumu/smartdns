/* Inherited flags are shared until their value or explicit-set mask changes. */
#include "gtest/gtest.h"
#include "include/utils.h"
#include <iostream>
#include <unistd.h>
#include "dns_conf/domain_rule.h"
#include "dns_conf/dns_conf_group.h"

namespace {
void CheckInheritance()
{
	smartdns::TempFile file;
	if (!file.Write("bind 127.0.0.1:60053\nserver 127.0.0.1:61053\naddress /blocked.example/#\n"
		"group-begin child -inherit default\ngroup-end\n")) _exit(2);
	if (dns_server_load_conf(file.GetPath().c_str()) != 0) _exit(3);
	file.Close();
	dns_conf_group_info parent_info{};
	parent_info.rule = dns_server_get_default_rule_group();
	if (!parent_info.rule) _exit(8);
	_config_set_current_group(&parent_info);
	auto initial = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	if (!initial || !(initial->flags & DOMAIN_FLAG_ADDR_SOA)) _exit(9);
	dns_conf_group_info child{};
	child.rule = dns_server_get_rule_group("child");
	if (!child.rule) _exit(4);
	_config_set_current_group(&child);
	if (_config_domain_rule_flag_set("blocked.example", DOMAIN_FLAG_ADDR_SOA, 1) != 0) _exit(5);
	auto changed = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	if (!changed || (changed->flags & DOMAIN_FLAG_ADDR_SOA)) _exit(6);
	_config_set_current_group(&parent_info);
	auto parent = static_cast<dns_rule_flags *>(dns_conf_get_domain_rule("blocked.example", DOMAIN_RULE_FLAGS));
	std::cerr << "INHERITED_PARENT_FLAGS=" << (parent ? parent->flags : 0) << std::endl;
	const bool preserved = parent && (parent->flags & DOMAIN_FLAG_ADDR_SOA);
	dns_server_load_exit();
	_exit(preserved ? 0 : 7);
}
}

TEST(DomainRuleInheritance, ChildFlagValueChangePreservesParent)
{
	ASSERT_EXIT(CheckInheritance(), ::testing::ExitedWithCode(0), "");
}
