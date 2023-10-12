package unpack

import (
	"github.com/urlesistiana/v2dat/mlog"
	"github.com/urlesistiana/v2dat/v2data"
	"path/filepath"
	"strings"
)

var logger = mlog.L()

func splitAttrs(s string) (string, map[string]struct{}) {
	tag, attrs, ok := strings.Cut(s, "@")
	if ok {
		m := make(map[string]struct{})
		for _, attr := range strings.Split(attrs, "@") {
			m[attr] = struct{}{}
		}
		return tag, m
	}
	return s, nil
}

// filterAttrs filter entries that do not have any of given attrs.
// If no attr was given, filterAttrs returns in.
func filterAttrs(in []*v2data.Domain, attrs map[string]struct{}) []*v2data.Domain {
	if len(attrs) == 0 {
		return in
	}
	out := make([]*v2data.Domain, 0)
	for _, d := range in {
		hasAttr := false
		for _, attr := range d.Attribute {
			if _, ok := attrs[attr.Key]; ok {
				hasAttr = true
				break
			}
		}
		if !hasAttr {
			continue
		}
		out = append(out, d)
	}
	return out
}

func fileName(f string) string {
	f = filepath.Base(f)
	if i := strings.LastIndexByte(f, '.'); i == -1 {
		return f
	} else {
		return f[:i]
	}
}
