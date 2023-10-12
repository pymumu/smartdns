
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
#include "regexp.h"
#include "stringutil.h"
#include "tlog.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

/* regexp list */
struct dns_regexp_head {
	struct list_head regexp_list;
	int num;
};

static struct dns_regexp_head dns_regexp_head;

int dns_regexp_init(void)
{
	INIT_LIST_HEAD(&dns_regexp_head.regexp_list);
	dns_regexp_head.num=0;
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
	
	//tlog(TLOG_WARN, "compile regexp: %s", regexp);
	safe_strncpy(dns_regexp->regexp, regexp, DNS_MAX_REGEXP_LEN);
	list_add_tail(&dns_regexp->list, head);
	
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
	struct dns_regexp *dns_regexp = NULL;
	struct dns_regexp *tmp = NULL;

	if (regexp == NULL) {
		return -1;
	}

	list_for_each_entry_safe(dns_regexp, tmp, &dns_regexp_head.regexp_list, list) {
		/*
		regmatch_t match;
		int reti = regexec(&dns_regexp->regex, domain, 1, &match,0);
		if (reti==REG_NOERROR) {
			safe_strncpy(regexp, dns_regexp->regexp, DNS_MAX_REGEXP_LEN);
			tlog(TLOG_DEBUG, "domain %s match regexp: %s", domain, dns_regexp->regexp);
			return 0;
		}
		else if (reti == REG_NOMATCH) {
			//tlog(TLOG_DEBUG, "domain %s not match regexp: %s", domain, dns_regexp->regexp);
		}
		else {
		    char msgbuf[100];
			regerror(reti, &dns_regexp->regex, msgbuf, sizeof(msgbuf));
			tlog(TLOG_ERROR, "domain %s match regexp: %s, error %s", domain, dns_regexp->regexp, msgbuf);							
		}
		*/

		cre2_string_t	match;
    	int	nmatch = 1;
    	int e = cre2_match(dns_regexp->rex, domain, strlen(domain), 0, strlen(domain), CRE2_UNANCHORED, &match, nmatch);
		switch (e) {
			case 1:
				safe_strncpy(regexp, dns_regexp->regexp, DNS_MAX_REGEXP_LEN);
				tlog(TLOG_INFO, "domain %s match regexp: %s", domain, dns_regexp->regexp);
				return 0;

			case 0:
				//tlog(TLOG_INFO, "domain %s not match regexp: %s", domain, dns_regexp->regexp);
				break;

			default:
				if (cre2_error_code(dns_regexp->rex)) {
					tlog(TLOG_ERROR, "domain %s match regexp: %s, error %s", domain, dns_regexp->regexp, 
									cre2_error_string(dns_regexp->rex));							
				}
		}
	}
	
	return -1;
}

void dns_regexp_destroy(void)
{
	struct dns_regexp *dns_regexp = NULL;
	struct dns_regexp *tmp = NULL;

	list_for_each_entry_safe(dns_regexp, tmp, &dns_regexp_head.regexp_list, list)
	{
	    //regfree(&dns_regexp->regex);
		cre2_delete(dns_regexp->rex);
		cre2_opt_delete(dns_regexp->opt);
		_dns_regexp_delete(dns_regexp);
	}
}
