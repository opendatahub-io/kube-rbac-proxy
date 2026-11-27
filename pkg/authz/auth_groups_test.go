/*
Copyright 2026 The kube-rbac-proxy Authors.

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

package authz

import (
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func attrs(name string, groups ...string) authorizer.Attributes {
	return authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name:   name,
			Groups: groups,
		},
	}
}

// TestStaticAuthorizerGroupMatching verifies that user.groups configured in a
// static authorization rule is actually enforced. A group-only rule (name
// empty, groups set) previously matched every authenticated user because
// Matches never compared the Groups field (RHAI-22813).
func TestStaticAuthorizerGroupMatching(t *testing.T) {
	tests := []struct {
		name   string
		config StaticAuthorizationConfig
		attrs  authorizer.Attributes
		want   bool
	}{
		{
			name: "group-only rule matches user in group",
			config: StaticAuthorizationConfig{
				User: UserConfig{Groups: []string{"trusted"}},
			},
			attrs: attrs("alice", "trusted", "system:authenticated"),
			want:  true,
		},
		{
			name: "group-only rule does not match user outside group",
			config: StaticAuthorizationConfig{
				User: UserConfig{Groups: []string{"trusted"}},
			},
			attrs: attrs("mallory", "untrusted", "system:authenticated"),
			want:  false,
		},
		{
			name: "name and groups both set: both must match",
			config: StaticAuthorizationConfig{
				User: UserConfig{Name: "alice", Groups: []string{"trusted"}},
			},
			attrs: attrs("alice", "trusted"),
			want:  true,
		},
		{
			name: "name matches but group does not: no match",
			config: StaticAuthorizationConfig{
				User: UserConfig{Name: "alice", Groups: []string{"trusted"}},
			},
			attrs: attrs("alice", "untrusted"),
			want:  false,
		},
		{
			name: "group matches but name does not: no match",
			config: StaticAuthorizationConfig{
				User: UserConfig{Name: "alice", Groups: []string{"trusted"}},
			},
			attrs: attrs("bob", "trusted"),
			want:  false,
		},
		{
			name: "no user restriction: matches anyone",
			config: StaticAuthorizationConfig{
				Path: "/metrics",
			},
			attrs: authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: "anyone", Groups: []string{"anygroup"}},
				Path: "/metrics",
			},
			want: true,
		},
		{
			name: "group-only rule does not match nil user",
			config: StaticAuthorizationConfig{
				User: UserConfig{Groups: []string{"trusted"}},
			},
			attrs: authorizer.AttributesRecord{},
			want:  false,
		},
		{
			name: "multiple configured groups: any one suffices",
			config: StaticAuthorizationConfig{
				User: UserConfig{Groups: []string{"admins", "operators"}},
			},
			attrs: attrs("carol", "operators"),
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.config.Matches(tc.attrs)
			if got != tc.want {
				t.Fatalf("Matches(%v) = %v, want %v", tc.attrs.GetUser(), got, tc.want)
			}
		})
	}
}
