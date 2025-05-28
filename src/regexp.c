/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#define _GNU_SOURCE
#include "smartdns/regexp.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/tlog.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

// 从 regexp.h 移到此处，因为这是实现文件
// #include "../utils/bloom.h" // 应通过 regexp.h 包含

/* regexp list */
struct dns_regexp_head {
	struct list_head regexp_list;
	int num;
};

static struct dns_regexp_head dns_regexp_head;

// 全局布隆过滤器实例
bloom_filter_t *g_regexp_bloom_filter = NULL;

// 默认布隆过滤器参数 (可根据需要调整或设为可配置)
#define DEFAULT_BLOOM_FILTER_SIZE (1024 * 8) // 1KB 位数组
#define DEFAULT_BLOOM_FILTER_HASHES 7

int dns_regexp_bloom_filter_init(size_t size, size_t num_hashes) {
    if (g_regexp_bloom_filter != NULL) {
        // 已经初始化，可能需要先释放或返回错误
        tlog(TLOG_WARN, "Bloom filter already initialized.");
        return 0; // 或者返回错误码
    }
    size_t bf_size = (size > 0) ? size : DEFAULT_BLOOM_FILTER_SIZE;
    size_t bf_hashes = (num_hashes > 0) ? num_hashes : DEFAULT_BLOOM_FILTER_HASHES;

    g_regexp_bloom_filter = bloom_filter_new(bf_size, bf_hashes);
    if (g_regexp_bloom_filter == NULL) {
        tlog(TLOG_ERROR, "Failed to initialize regexp bloom filter.");
        return -1;
    }
    tlog(TLOG_INFO, "Regexp bloom filter initialized (size: %zu bits, hashes: %zu).", bf_size, bf_hashes);
    return 0;
}

void dns_regexp_bloom_filter_free(void) {
    if (g_regexp_bloom_filter != NULL) {
        bloom_filter_free(g_regexp_bloom_filter);
        g_regexp_bloom_filter = NULL;
        tlog(TLOG_INFO, "Regexp bloom filter freed.");
    }
}

void dns_regexp_bloom_filter_add_pattern(const char *pattern) {
    if (g_regexp_bloom_filter != NULL && pattern != NULL) {
        bloom_filter_add(g_regexp_bloom_filter, pattern, strlen(pattern));
        // tlog(TLOG_DEBUG, "Added pattern to bloom filter: %s", pattern);
    }
}

int dns_regexp_bloom_filter_check_domain(const char *domain) {
    if (g_regexp_bloom_filter != NULL && domain != NULL) {
        return bloom_filter_check(g_regexp_bloom_filter, domain, strlen(domain));
    }
    return 1; // 如果过滤器未初始化或输入无效，保守地返回可能匹配
}

int dns_regexp_init(void)
{
	INIT_LIST_HEAD(&dns_regexp_head.regexp_list);
	dns_regexp_head.num=0;
    // 初始化布隆过滤器
    if (dns_regexp_bloom_filter_init(0, 0) != 0) { // 使用默认大小和哈希数
        // 处理初始化失败的情况，可能记录错误日志或阻止启动
        tlog(TLOG_ERROR, "Failed to initialize bloom filter during regexp_init.");
        // 根据项目错误处理策略，这里可能需要返回错误
    }
	return 0;
}

__attribute__((unused)) struct dns_regexp *_dns_regexp_last(void)
{
	return list_last_entry(&dns_regexp_head.regexp_list, struct dns_regexp, list);
}

void _dns_regexp_delete(struct dns_regexp *dns_regexp)
{
	list_del_init(&dns_regexp->list);
	free(dns_regexp);
}

void dns_regexp_release(struct dns_regexp *dns_regexp)
{
	if (dns_regexp == NULL) {
		return;
	}

	_dns_regexp_delete(dns_regexp);
}

int has_regexp(void)
{
      return (dns_regexp_head.num>0?1:0);
}

int _dns_regexp_insert(char *regexp, struct list_head *head)
{
	struct dns_regexp *dns_regexp = NULL;

	dns_regexp = malloc(sizeof(*dns_regexp));
	if (dns_regexp == NULL) {
		goto errout;
	}

	memset(dns_regexp, 0, sizeof(*dns_regexp));
	/*
	int reti=regcomp(&dns_regexp->regex,regexp,REG_EXTENDED |REG_NOSUB);
	if ( reti != REG_NOERROR) {
		char msgbuf[100];
		regerror(reti, &dns_regexp->regex, msgbuf, sizeof(msgbuf));
		tlog(TLOG_ERROR, "compile regexp: %s, error %s", regexp, msgbuf);
	    regfree(&dns_regexp->regex);
	    goto errout;
	}
	*/

	dns_regexp->opt = cre2_opt_new();
	cre2_opt_set_perl_classes(dns_regexp->opt, 1);
  	dns_regexp->rex = cre2_new(regexp, strlen(regexp), dns_regexp->opt);
	int err = cre2_error_code(dns_regexp->rex);
    if (err) {
		tlog(TLOG_ERROR, "compile regexp: %s error=%s", regexp, cre2_error_string(dns_regexp->rex));
		cre2_delete(dns_regexp->rex);
		cre2_opt_delete(dns_regexp->opt);
      	goto errout;
	}
	
	//tlog(TLOG_INFO, "compile regexp: %s", regexp);
	safe_strncpy(dns_regexp->regexp, regexp, DNS_MAX_REGEXP_LEN);
	list_add_tail(&dns_regexp->list, head);

    // 将模式添加到布隆过滤器
    dns_regexp_bloom_filter_add_pattern(regexp);
	
	return 0;
errout:
	if (dns_regexp) {
		free(dns_regexp);
	}

	return -1;
}

int dns_regexp_insert(char *regexp)
{
	if (regexp == NULL) {
		return -1;
	}

	if (dns_regexp_head.num>=DNS_MAX_REGEXP_NUM) {
		return -1;
	}

	if (_dns_regexp_insert(regexp, &dns_regexp_head.regexp_list)==0) {
	     dns_regexp_head.num++;
	     return 0;
	}
	
	return -1;
}

int dns_regexp_match(const char *domain, char *regexp)
{
	struct dns_regexp *dns_regexp_entry = NULL;
	struct dns_regexp *tmp = NULL;

	if (domain == NULL || regexp == NULL) { // Check domain as well
		return -1; // Invalid arguments
	}

    // 使用布隆过滤器进行初筛
    if (g_regexp_bloom_filter != NULL && dns_regexp_head.num > 0) { // 仅当有正则且过滤器已初始化时检查
        if (!dns_regexp_bloom_filter_check_domain(domain)) {
            // tlog(TLOG_DEBUG, "Bloom filter: domain %s likely NOT in regexp set.", domain);
            return -1; // 布隆过滤器指示不匹配，可以提前返回
        }
        // tlog(TLOG_DEBUG, "Bloom filter: domain %s MAY BE in regexp set.", domain);
    }

	list_for_each_entry_safe(dns_regexp_entry, tmp, &dns_regexp_head.regexp_list, list) {
		cre2_string_t	match_details; // Renamed from 'match' to avoid conflict if any
    	int	nmatch = 1;
    	int e = cre2_match(dns_regexp_entry->rex, domain, strlen(domain), 0, strlen(domain), CRE2_UNANCHORED, &match_details, nmatch);
		switch (e) {
			case 1: // Match
				safe_strncpy(regexp, dns_regexp_entry->regexp, DNS_MAX_REGEXP_LEN);
				tlog(TLOG_INFO, "domain %s match regexp: %s", domain, dns_regexp_entry->regexp);
				return 0; // Success (matched)

			case 0: // No match
				break;

			default: // Error
				if (cre2_error_code(dns_regexp_entry->rex)) {
					tlog(TLOG_ERROR, "domain %s match regexp: %s, error %s", domain, dns_regexp_entry->regexp, 
									cre2_error_string(dns_regexp_entry->rex));							
				}
		}
	}
	
	return -1; // No match found after iterating all regexps
}

void dns_regexp_destroy(void)
{
	struct dns_regexp *dns_regexp_entry = NULL;
	struct dns_regexp *tmp = NULL;

    // 释放布隆过滤器
    dns_regexp_bloom_filter_free();

	list_for_each_entry_safe(dns_regexp_entry, tmp, &dns_regexp_head.regexp_list, list)
	{
	    //regfree(&dns_regexp->regex);
		cre2_delete(dns_regexp_entry->rex);
		cre2_opt_delete(dns_regexp_entry->opt);
		_dns_regexp_delete(dns_regexp_entry); // _dns_regexp_delete already calls list_del_init and free
	}
    dns_regexp_head.num = 0; // Reset count after clearing
}
