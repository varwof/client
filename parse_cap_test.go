// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestParseCapToken(t *testing.T) {
	cases := []struct {
		tok    string
		scheme string
		cap    string
		params string // expected params string, "" for none
		ok     bool
	}{
		{"varwof/core:cert:issue", "varwof/core", "cert:issue", "", true},
		{"std/database-v1:query:SELECT", "std/database-v1", "query:SELECT", "", true},
		{`std/database-v1:query:SELECT:{"tables":["customers"],"limit":{"max":500}}`,
			"std/database-v1", "query:SELECT", `{"tables":["customers"],"limit":{"max":500}}`, true},
		{`varwof/llm:chat{"model":["deepseek-chat"]}`, "varwof/llm", "chat", `{"model":["deepseek-chat"]}`, true},
		{"bare", "", "", "", false},
		// Params must be bracketed JSON; without '{'/'[' the tail is part of
		// the capability id and is rejected later by registry validation.
		{"std/database-v1:query:SELECT:500", "std/database-v1", "query:SELECT:500", "", true},
	}
	for _, c := range cases {
		scheme, capID, params, err := parseCapToken(c.tok)
		if (err == nil) != c.ok {
			t.Errorf("%q: ok=%v want %v (err=%v)", c.tok, err == nil, c.ok, err)
			continue
		}
		if !c.ok {
			continue
		}
		if scheme != c.scheme || capID != c.cap {
			t.Errorf("%q: got %q/%q, want %q/%q", c.tok, scheme, capID, c.scheme, c.cap)
		}
		gotParams := ""
		if len(params) > 0 {
			gotParams = string(params)
		}
		if gotParams != c.params {
			t.Errorf("%q: params %q, want %q", c.tok, gotParams, c.params)
		}
	}
}

func TestClaimsToCapTokens(t *testing.T) {
	data := []byte(`[
	  {"scheme_id":"std/database-v1","capability":"query:SELECT",
	   "parameters":{"tables":["customers"],"limit":{"max":500}},
	   "rationale":"read customers"},
	  {"scheme_id":"varwof/llm","capability":"chat"}
	]`)
	tokens, digest, err := claimsToCapTokens(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatalf("tokens = %v", tokens)
	}
	if tokens[0] != `std/database-v1:query:SELECT:{"limit":{"max":500},"tables":["customers"]}` {
		t.Fatalf("token0 = %s", tokens[0])
	}
	if tokens[1] != "varwof/llm:chat" {
		t.Fatalf("token1 = %s", tokens[1])
	}
	if len(digest) != 64 {
		t.Fatalf("digest length = %d", len(digest))
	}
	// Missing scheme_id/capability rejected.
	if _, _, err := claimsToCapTokens([]byte(`[{"scheme_id":"x"}]`)); err == nil {
		t.Fatal("missing capability must be rejected")
	}
}
