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

#ifndef _SMARTDNS_REGEXP_H
#define _SMARTDNS_REGEXP_H
#include "smartdns/dns.h"
#include "smartdns/lib/list.h"
#include <stdlib.h>
#include <time.h>
//#include <regex.h>
#include <cre2.h>
#include "smartdns/bloom.h"

#ifdef __cpluscplus
extern "C" {
#endif

#define DNS_MAX_REGEXP_LEN  256
#define DNS_MAX_REGEXP_NUM 200

struct dns_regexp {	
    struct list_head list;
    char  regexp[DNS_MAX_REGEXP_LEN];
    //regex_t regex;
    cre2_regexp_t *rex;
    cre2_options_t *opt;
};

extern bloom_filter_t *g_regexp_bloom_filter;

// 初始化正则表达式布隆过滤器
int dns_regexp_bloom_filter_init(size_t size, size_t num_hashes);

// 释放正则表达式布隆过滤器
void dns_regexp_bloom_filter_free(void);

// 将正则表达式模式添加到布隆过滤器
void dns_regexp_bloom_filter_add_pattern(const char *pattern);

// 检查域名是否可能匹配布隆过滤器中的任何模式
// 返回1表示可能匹配，0表示绝对不匹配
int dns_regexp_bloom_filter_check_domain(const char *domain);

int dns_regexp_init(void);

__attribute__((unused)) struct dns_regexp *_dns_regexp_last(void);

void _dns_regexp_delete(struct dns_regexp *dns_regexp);

void dns_regexp_release(struct dns_regexp *dns_regexp);

int has_regexp(void);

int _dns_regexp_insert(char *regexp, struct list_head *head);

int dns_regexp_insert(char *regexp);

int dns_regexp_match(const char *string, char *matched_pattern);

void dns_regexp_destroy(void);

#ifdef __cpluscplus
}
#endif
#endif // !_SMARTDNS_REGEXP_H