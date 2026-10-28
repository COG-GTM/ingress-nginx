/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

var wildcardLabelRegex = regexp.MustCompile(`^[\w-]+$`)

// normalizeServerName lowercases a non-regex server name and strips a trailing dot,
// mirroring how nginx compares server_name values.
func normalizeServerName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "~") {
		return name
	}
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// hasDomainSuffix reports whether name equals suffix or ends with ".<suffix>".
func hasDomainSuffix(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// isSingleLabelUnder reports whether name is exactly one label under parent, the set of
// names matched by the regex buildServerName renders for a "*.<parent>" host.
func isSingleLabelUnder(name, parent string) bool {
	label, rest, found := strings.Cut(name, ".")
	return found && rest == parent && wildcardLabelRegex.MatchString(label)
}

// aliasConflictsWithHost reports whether nginx could route a request for a name served by
// the Ingress host to a server block that has alias in its server_name. host must be an
// Ingress rule host (exact name or "*.<domain>"); alias may use any nginx server_name form.
func aliasConflictsWithHost(alias, host string) bool {
	alias = normalizeServerName(alias)
	host = normalizeServerName(host)
	if alias == "" || host == "" || host == defServerName {
		return false
	}

	wildcardParent, hostIsWildcard := strings.CutPrefix(host, "*.")

	switch {
	case strings.HasPrefix(alias, "~"):
		// Regex names rank below exact and wildcard names, so they can only take over
		// hosts that are themselves rendered as regexes.
		if !hostIsWildcard {
			return false
		}
		return regexMatchesWildcardHost(alias[1:], wildcardParent)

	case strings.HasPrefix(alias, "."):
		// ".example.com" matches "example.com" and every name under it.
		suffix := alias[1:]
		if hostIsWildcard {
			return hasDomainSuffix(wildcardParent, suffix) || isSingleLabelUnder(suffix, wildcardParent)
		}
		return hasDomainSuffix(host, suffix)

	case strings.HasPrefix(alias, "*."):
		suffix := alias[2:]
		if hostIsWildcard {
			return hasDomainSuffix(wildcardParent, suffix)
		}
		return strings.HasSuffix(host, "."+suffix)

	case strings.HasSuffix(alias, ".*"):
		prefix := alias[:len(alias)-2]
		if hostIsWildcard {
			_, rest, found := strings.Cut(prefix, ".")
			return !found || strings.HasPrefix(wildcardParent, rest+".")
		}
		return strings.HasPrefix(host, prefix+".")

	default:
		if hostIsWildcard {
			return alias == host || isSingleLabelUnder(alias, wildcardParent)
		}
		return alias == host
	}
}

// regexMatchesWildcardHost reports whether a regex server name could match a name exactly
// one label under parent. A regex can only be proven harmless when every match must end
// with a literal suffix that no such name ends with; anything else is treated as a conflict.
func regexMatchesWildcardHost(pattern, parent string) bool {
	suffixes, ok := regexLiteralSuffixes(pattern)
	if !ok {
		return true
	}
	for _, suffix := range suffixes {
		if suffixMatchesSingleLabelUnder(suffix, parent) {
			return true
		}
	}
	return false
}

// suffixMatchesSingleLabelUnder reports whether some "<label>.<parent>" name ends with suffix.
func suffixMatchesSingleLabelUnder(suffix, parent string) bool {
	tail := "." + parent
	if len(suffix) <= len(tail) {
		return strings.HasSuffix(tail, suffix)
	}
	label, found := strings.CutSuffix(suffix, tail)
	return found && wildcardLabelRegex.MatchString(label)
}

// regexLiteralSuffixes returns, for each top-level alternative of pattern, the lowercase
// literal text every match must end with. ok is false when some alternative is not
// anchored with "$" or has no literal suffix.
func regexLiteralSuffixes(pattern string) ([]string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// nginx uses PCRE, which accepts syntax Go does not (e.g. backreferences).
		suffix := textualLiteralSuffix(pattern)
		return []string{suffix}, suffix != "" && !strings.Contains(pattern, "|")
	}
	re = re.Simplify()

	alternatives := []*syntax.Regexp{re}
	if re.Op == syntax.OpAlternate {
		alternatives = re.Sub
	}

	suffixes := make([]string, 0, len(alternatives))
	for _, alt := range alternatives {
		suffix := anchoredLiteralSuffix(alt)
		if suffix == "" {
			return nil, false
		}
		suffixes = append(suffixes, suffix)
	}
	return suffixes, true
}

func anchoredLiteralSuffix(re *syntax.Regexp) string {
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[len(re.Sub)-1].Op != syntax.OpEndText {
		return ""
	}

	var suffix string
	for i := len(re.Sub) - 2; i >= 0 && re.Sub[i].Op == syntax.OpLiteral; i-- {
		suffix = string(re.Sub[i].Rune) + suffix
	}
	return strings.ToLower(suffix)
}

// textualLiteralSuffix extracts the literal characters immediately before a trailing,
// unescaped "$" without parsing the pattern.
func textualLiteralSuffix(pattern string) string {
	if !strings.HasSuffix(pattern, "$") || precedingBackslashes(pattern, len(pattern)-1)%2 == 1 {
		return ""
	}

	var suffix []byte
	for i := len(pattern) - 2; i >= 0; {
		c := pattern[i]
		if precedingBackslashes(pattern, i)%2 == 1 {
			if c != '.' && c != '-' {
				break
			}
			suffix = append([]byte{c}, suffix...)
			i -= 2
			continue
		}
		if !isLiteralHostChar(c) {
			break
		}
		suffix = append([]byte{c}, suffix...)
		i--
	}
	return strings.ToLower(string(suffix))
}

func precedingBackslashes(s string, i int) int {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n
}

func isLiteralHostChar(c byte) bool {
	return c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// conflictingHost returns the first host that alias would take over, if any.
func conflictingHost(alias string, hosts []string) (string, bool) {
	for _, host := range hosts {
		if aliasConflictsWithHost(alias, host) {
			return host, true
		}
	}
	return "", false
}
