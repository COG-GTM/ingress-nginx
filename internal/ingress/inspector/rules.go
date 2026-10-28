/*
Copyright 2022 The Kubernetes Authors.

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

package inspector

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	invalidAliasDirective = regexp.MustCompile(`(?s)\s*alias\s*.*;`)
	invalidRootDirective  = regexp.MustCompile(`(?s)\s*root\s*.*;`)
	invalidEtcDir         = regexp.MustCompile(`/etc/(passwd|shadow|group|nginx|ingress-controller)`)
	invalidSecretsDir     = regexp.MustCompile(`/var/run/secrets`)
	invalidByLuaDirective = regexp.MustCompile(`.*_by_lua.*`)

	// validPathType enforces alphanumeric, -, _ and / characters.
	// The field (?i) turns this regex case insensitive
	// The remaining regex says that the string must start with a "/" (^/)
	// the group [[:alnum:]\_\-\/]* says that any amount of characters (A-Za-z0-9), _, - and /
	// are accepted until the end of the line
	// Nothing else is accepted.
	validPathType = regexp.MustCompile(`(?i)^/[[:alnum:]\_\-/]*$`)

	// invalidPathCharacters matches characters that are part of the nginx configuration
	// syntax (token separators, quotes, comments, statement and block delimiters) and
	// therefore must never be part of an Ingress path, regardless of its pathType.
	invalidPathCharacters = regexp.MustCompile("[ \\x00-\\x1f\\x7f;\"'`#]")

	// regexQuantifier matches a regular expression repetition like {3}, {3,} or {3,5}.
	// These are the only places where braces are accepted in a path.
	regexQuantifier = regexp.MustCompile(`\{\d+(,\d*)?\}`)

	invalidRegex = []regexp.Regexp{}
)

func init() {
	invalidRegex = []regexp.Regexp{
		*invalidAliasDirective,
		*invalidRootDirective,
		*invalidEtcDir,
		*invalidSecretsDir,
		*invalidByLuaDirective,
	}
}

// CheckRegex receives a value/configuration and validates if it matches with one of the
// forbidden regexes.
func CheckRegex(value string) error {
	for i := range invalidRegex {
		if invalidRegex[i].MatchString(value) {
			return fmt.Errorf("invalid value found: %s", value)
		}
	}
	return nil
}

// CheckPath validates that an Ingress path does not contain characters that could
// terminate the nginx token, directive or block it is rendered into.
func CheckPath(path string) error {
	if invalidPathCharacters.MatchString(path) {
		return fmt.Errorf("path %q contains invalid characters", path)
	}
	if strings.ContainsAny(regexQuantifier.ReplaceAllString(path, ""), "{}") {
		return fmt.Errorf("path %q contains braces that are not part of a regex quantifier", path)
	}
	return nil
}
