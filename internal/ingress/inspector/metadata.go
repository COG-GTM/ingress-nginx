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

package inspector

import (
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

var uidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidateObjectMeta checks that the uid, namespace and name of an object have the
// shape the API server would give them. Objects received by the admission webhook
// come straight from the request body, and these fields end up in the nginx
// configuration (mirror locations, rate limit zones), so they cannot be trusted.
func ValidateObjectMeta(meta *metav1.ObjectMeta) error {
	if meta.UID != "" && !uidRegex.MatchString(string(meta.UID)) {
		return fmt.Errorf("invalid metadata.uid %q: must be a UUID", meta.UID)
	}

	if meta.Namespace != "" {
		if errs := validation.IsDNS1123Label(meta.Namespace); len(errs) > 0 {
			return fmt.Errorf("invalid metadata.namespace %q: %s", meta.Namespace, strings.Join(errs, "; "))
		}
	}

	if meta.Name != "" {
		if errs := validation.IsDNS1123Subdomain(meta.Name); len(errs) > 0 {
			return fmt.Errorf("invalid metadata.name %q: %s", meta.Name, strings.Join(errs, "; "))
		}
	}

	return nil
}
