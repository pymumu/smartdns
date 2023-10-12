## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS		= -I meta/autotools
AUTOMAKE_OPTIONS	= foreign
EXTRA_DIST		= INSTALL
dist_doc_DATA		= README COPYING LICENSE.re2
AM_CPPFLAGS		= -I$(top_srcdir)/src
AM_CFLAGS		= $(MMUX_CFLAGS)
AM_CXXFLAGS		= $(MMUX_CXXFLAGS)
CLEANFILES		=

AM_DISTCHECK_CONFIGURE_FLAGS	= CC="$(CC)" CXX="$(CXX)"

## --------------------------------------------------------------------

nodist_pkgconfig_DATA	= meta/scripts/cre2.pc


#### documentation

EXTRA_DIST		+= doc/cre2.style.css
CLEANFILES		+= doc/cre2.css

AM_MAKEINFOFLAGS	= --no-split
AM_MAKEINFOHTMLFLAGS	= --split=node -c WORDS_IN_PAGE=0 --css-ref=cre2.css \
	-c PRE_BODY_CLOSE="<p>This document describes version <tt>$(PACKAGE_VERSION)</tt> of <em>$(PACKAGE_NAME)</em>.</p>"

info_TEXINFOS		= doc/cre2.texi
doc_cre2_TEXINFOS	= \
	doc/macros.texi			\
	doc/overview-linking.texi	\
	doc/fdl-1.3.texi

## --------------------------------------------------------------------

doc/cre2.html/$(am__dirstamp): doc/$(am__dirstamp)
	@$(MKDIR_P) doc/cre2.html/
	@: > doc/cre2.html/$(am__dirstamp)

doc/cre2.html/cre2.css: doc/cre2.style.css doc/cre2.html/$(am__dirstamp)
	$(INSTALL) -m 0444 "$(top_srcdir)/doc/cre2.style.css" "$(builddir)/doc/cre2.html/cre2.css"

## --------------------------------------------------------------------

html-local: doc/cre2.html/cre2.css

install-html-local:
	$(MKDIR_P) "$(DESTDIR)$(htmldir)/cre2.html/"
	$(INSTALL) -m 0444 $(builddir)/doc/cre2.html/cre2.css "$(DESTDIR)$(htmldir)/cre2.html/"


#### libraries

cre2_CURRENT		= @cre2_VERSION_INTERFACE_CURRENT@
cre2_REVISION		= @cre2_VERSION_INTERFACE_REVISION@
cre2_AGE		= @cre2_VERSION_INTERFACE_AGE@
cre2_LINKER_VERSION	= -version-info $(cre2_CURRENT):$(cre2_REVISION):$(cre2_AGE)

include_HEADERS		= src/cre2.h

lib_LTLIBRARIES		= libcre2.la
libcre2_la_CPPFLAGS	= $(AM_CPPFLAGS)
libcre2_la_CFLAGS	= $(AM_CFLAGS)   $(PTHREAD_CFLAGS) $(RE2_CFLAGS)
libcre2_la_CXXFLAGS	= $(AM_CXXFLAGS) $(PTHREAD_CFLAGS) $(RE2_CFLAGS)
libcre2_la_LDFLAGS	= $(cre2_LINKER_VERSION) $(AM_LDFLAGS) $(PTHREAD_LIBS) $(RE2_LIBS)
libcre2_la_SOURCES	= src/cre2.cpp


#### tests

check_PROGRAMS		= \
	tests/test-version			\
	tests/test-options			\
	tests/test-rex-alloc			\
	tests/test-matching			\
	tests/test-easy-matching		\
	tests/test-full-match			\
	tests/test-partial-match		\
	tests/test-consume-match		\
	tests/test-capture-names-iter		\
	tests/test-find-and-consume-match	\
	tests/test-replace			\
	tests/test-set				\
	tests/test-misc

TESTS			= $(check_PROGRAMS)

## --------------------------------------------------------------------

cre2_common_sources			= tests/cre2-test.h
cre2_common_cflags			= $(AM_CFLAGS)
cre2_common_ldadd			= $(AM_LDFLAGS) libcre2.la

## --------------------------------------------------------------------

tests_test_version_SOURCES		= tests/test-version.c $(cre2_common_sources)
tests_test_version_CFLAGS		= $(cre2_common_cflags)
tests_test_version_LDADD		= $(cre2_common_ldadd)

tests_test_options_SOURCES		= tests/test-options.c $(cre2_common_sources)
tests_test_options_CFLAGS		= $(cre2_common_cflags)
tests_test_options_LDADD		= $(cre2_common_ldadd)

tests_test_rex_alloc_SOURCES		= tests/test-rex-alloc.c $(cre2_common_sources)
tests_test_rex_alloc_CFLAGS		= $(cre2_common_cflags)
tests_test_rex_alloc_LDADD		= $(cre2_common_ldadd)

tests_test_matching_SOURCES		= tests/test-matching.c $(cre2_common_sources)
tests_test_matching_CFLAGS		= $(cre2_common_cflags)
tests_test_matching_LDADD		= $(cre2_common_ldadd)

tests_test_easy_matching_SOURCES	= tests/test-easy-matching.c $(cre2_common_sources)
tests_test_easy_matching_CFLAGS		= $(cre2_common_cflags)
tests_test_easy_matching_LDADD		= $(cre2_common_ldadd)

tests_test_full_match_SOURCES		= tests/test-full-match.c $(cre2_common_sources)
tests_test_full_match_CFLAGS		= $(cre2_common_cflags)
tests_test_full_match_LDADD		= $(cre2_common_ldadd)

tests_test_partial_match_SOURCES	= tests/test-partial-match.c $(cre2_common_sources)
tests_test_partial_match_CFLAGS		= $(cre2_common_cflags)
tests_test_partial_match_LDADD		= $(cre2_common_ldadd)

tests_test_consume_match_SOURCES	= tests/test-consume-match.c $(cre2_common_sources)
tests_test_consume_match_CFLAGS		= $(cre2_common_cflags)
tests_test_consume_match_LDADD		= $(cre2_common_ldadd)

tests_test_capture_names_iter_SOURCES	= tests/test-capture-names-iter.c $(cre2_common_sources)
tests_test_capture_names_iter_CFLAGS	= $(cre2_common_cflags)
tests_test_capture_names_iter_LDADD	= $(cre2_common_ldadd)

tests_test_find_and_consume_match_SOURCES = tests/test-find-and-consume-match.c $(cre2_common_sources)

tests_test_find_and_consume_match_CFLAGS= $(cre2_common_cflags)
tests_test_find_and_consume_match_LDADD	= $(cre2_common_ldadd)

tests_test_replace_SOURCES		= tests/test-replace.c $(cre2_common_sources)
tests_test_replace_CFLAGS		= $(cre2_common_cflags)
tests_test_replace_LDADD		= $(cre2_common_ldadd)

tests_test_set_SOURCES			= tests/test-set.c $(cre2_common_sources)
tests_test_set_CFLAGS			= $(cre2_common_cflags)
tests_test_set_LDADD			= $(cre2_common_ldadd)

tests_test_misc_SOURCES			= tests/test-misc.c $(cre2_common_sources)
tests_test_misc_CFLAGS			= $(cre2_common_cflags)
tests_test_misc_LDADD			= $(cre2_common_ldadd)

## --------------------------------------------------------------------

installcheck-local: $(check_PROGRAMS)
	for f in $(check_PROGRAMS); do $$f; done


#### common rules

include $(top_srcdir)/meta/automake/mmux-makefile-rules

### end of file
