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
	"strings"
)

var (
	wildcardLabelRegex = regexp.MustCompile(`^[\w-]+$`)
	regexLiteralRegex  = regexp.MustCompile(`[a-z0-9_-]+`)
	regexProbeLabels   = []string{"a", "x", "0", "www", "test-1", "_"}
)

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

// regexMatchesWildcardHost probes a regex server name against sample names under parent.
// Patterns that Go cannot compile are treated as conflicting.
func regexMatchesWildcardHost(pattern, parent string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return true
	}

	labels := append([]string{}, regexProbeLabels...)
	labels = append(labels, regexLiteralRegex.FindAllString(strings.ToLower(pattern), -1)...)
	for _, label := range labels {
		if re.MatchString(label + "." + parent) {
			return true
		}
	}
	return false
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
