// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from the kubernetes project.
 *
 * Copyright 2022 The Kubernetes Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package triemap_test

import (
	"net/netip"
	"testing"

	"github.com/dpeckett/network/internal/triemap"
	"github.com/stretchr/testify/require"
)

var testPrefixes = map[string][]netip.Prefix{
	"eu-west-3": {
		netip.MustParsePrefix("35.180.0.0/16"),
		netip.MustParsePrefix("52.93.127.17/32"),
		netip.MustParsePrefix("52.93.127.172/31"),
	},
	"us-east-1": {
		netip.MustParsePrefix("52.93.127.173/32"),
	},
	"us-west-2": {
		netip.MustParsePrefix("2600:1f01:4874::/47"),
		netip.MustParsePrefix("52.94.76.0/22"),
	},
	"ap-northeast-1": {
		netip.MustParsePrefix("52.93.127.174/32"),
		netip.MustParsePrefix("52.93.127.175/32"),
		netip.MustParsePrefix("52.93.127.176/32"),
		netip.MustParsePrefix("52.93.127.177/32"),
		netip.MustParsePrefix("52.93.127.178/32"),
		netip.MustParsePrefix("52.93.127.179/32"),
	},
	"ap-southeast-3": {
		netip.MustParsePrefix("2400:6500:0:9::2/128"),
	},
}

var testCases = []struct {
	Addr          netip.Addr
	ExpectedValue string
}{
	{Addr: netip.MustParseAddr("35.180.1.1"), ExpectedValue: "eu-west-3"},
	{Addr: netip.MustParseAddr("35.250.1.1"), ExpectedValue: ""},
	{Addr: netip.MustParseAddr("35.0.1.1"), ExpectedValue: ""},
	{Addr: netip.MustParseAddr("52.94.76.1"), ExpectedValue: "us-west-2"},
	{Addr: netip.MustParseAddr("52.94.77.1"), ExpectedValue: "us-west-2"},
	{Addr: netip.MustParseAddr("52.93.127.172"), ExpectedValue: "eu-west-3"},
	// ipv6
	{Addr: netip.MustParseAddr("2400:6500:0:9::2"), ExpectedValue: "ap-southeast-3"},
	{Addr: netip.MustParseAddr("2400:6500:0:9::1"), ExpectedValue: ""},
	{Addr: netip.MustParseAddr("2400:6500:0:9::3"), ExpectedValue: ""},
	{Addr: netip.MustParseAddr("2600:1f01:4874::47"), ExpectedValue: "us-west-2"},
}

func TestTrieMap(t *testing.T) {
	trieMap := triemap.New[string]()
	for value, prefixes := range testPrefixes {
		for _, prefix := range prefixes {
			trieMap.Insert(prefix, value)
		}
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.Addr.String(), func(t *testing.T) {
			t.Parallel()
			// NOTE: we set region == "" for no-contains
			expectedContains := tc.ExpectedValue != ""
			ip := tc.Addr
			value, contains := trieMap.Get(ip)
			require.Equal(t, expectedContains, contains)
			require.Equal(t, tc.ExpectedValue, value)
		})
	}
}

func TestTrieMapEmpty(t *testing.T) {
	trieMap := triemap.New[string]()
	v, contains := trieMap.Get(netip.MustParseAddr("127.0.0.1"))
	if contains || v != "" {
		t.Fatalf("empty TrieMap should not contain anything")
	}
	v, contains = trieMap.Get(netip.MustParseAddr("::1"))
	if contains || v != "" {
		t.Fatalf("empty TrieMap should not contain anything")
	}
}

func TestTrieMapSlashZero(t *testing.T) {
	// test the ??? case that we insert into the root with a /0
	trieMap := triemap.New[string]()
	trieMap.Insert(netip.MustParsePrefix("0.0.0.0/0"), "all-ipv4")
	trieMap.Insert(netip.MustParsePrefix("::/0"), "all-ipv6")
	v, contains := trieMap.Get(netip.MustParseAddr("127.0.0.1"))
	if !contains || v != "all-ipv4" {
		t.Fatalf("TrieMap failed to match IPv4 with all IPs in one /0")
	}
	v, contains = trieMap.Get(netip.MustParseAddr("::1"))
	if !contains || v != "all-ipv6" {
		t.Fatalf("TrieMap failed to match IPv6 with all IPs in one /0")
	}
}

func TestTrieMapRemove(t *testing.T) {
	trieMap := triemap.New[string]()
	for value, prefixes := range testPrefixes {
		for _, prefix := range prefixes {
			trieMap.Insert(prefix, value)
		}
	}

	// Remove a prefix that exists (with more than one reference to the key)
	removed := trieMap.Remove(netip.MustParsePrefix("52.94.76.0/22"))
	require.True(t, removed)

	// Make sure the prefix was removed
	_, contains := trieMap.Get(netip.MustParseAddr("52.94.76.1"))
	require.False(t, contains)

	// Make sure other references to the key still exist
	value, contains := trieMap.Get(netip.MustParseAddr("2600:1f01:4874::1"))
	require.True(t, contains)

	require.Equal(t, "us-west-2", value)

	// Attempt to remove a prefix that does not exist
	removed = trieMap.Remove(netip.MustParsePrefix("64.63.22.0/24"))
	require.False(t, removed)

	// Remove a prefix that exists (with only one reference to the key)
	removed = trieMap.Remove(netip.MustParsePrefix("2400:6500:0:9::2/128"))
	require.True(t, removed)

	// Make sure the prefix was removed
	_, contains = trieMap.Get(netip.MustParseAddr("2400:6500:0:9::2"))
	require.False(t, contains)
}

func TestTrieMapIPv4(t *testing.T) {
	trieMap := triemap.New[string]()

	trieMap.Insert(netip.MustParsePrefix("192.168.4.0/24"), "a")
	trieMap.Insert(netip.MustParsePrefix("192.168.4.4/32"), "b")
	trieMap.Insert(netip.MustParsePrefix("192.168.0.0/16"), "c")
	trieMap.Insert(netip.MustParsePrefix("192.95.5.64/27"), "d")
	trieMap.Insert(netip.MustParsePrefix("192.95.5.65/27"), "c")
	trieMap.Insert(netip.MustParsePrefix("0.0.0.0/0"), "e")
	trieMap.Insert(netip.MustParsePrefix("64.15.112.0/20"), "f")
	trieMap.Insert(netip.MustParsePrefix("64.15.123.211/25"), "g")
	trieMap.Insert(netip.MustParsePrefix("10.0.0.0/25"), "a")
	trieMap.Insert(netip.MustParsePrefix("10.0.0.128/25"), "b")
	trieMap.Insert(netip.MustParsePrefix("10.1.0.0/30"), "a")
	trieMap.Insert(netip.MustParsePrefix("10.1.0.4/30"), "b")
	trieMap.Insert(netip.MustParsePrefix("10.1.0.8/29"), "c")
	trieMap.Insert(netip.MustParsePrefix("10.1.0.16/29"), "d")

	value, _ := trieMap.Get(netip.MustParseAddr("192.168.4.20"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.168.4.0"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.168.4.4"))
	require.Equal(t, "b", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.168.200.182"))
	require.Equal(t, "c", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.95.5.68"))
	require.Equal(t, "c", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.95.5.96"))
	require.Equal(t, "e", value)

	value, _ = trieMap.Get(netip.MustParseAddr("64.15.116.26"))
	require.Equal(t, "f", value)

	value, _ = trieMap.Get(netip.MustParseAddr("64.15.127.3"))
	require.Equal(t, "f", value)

	trieMap.Insert(netip.MustParsePrefix("1.0.0.0/32"), "a")
	trieMap.Insert(netip.MustParsePrefix("64.0.0.0/32"), "a")
	trieMap.Insert(netip.MustParsePrefix("128.0.0.0/32"), "a")
	trieMap.Insert(netip.MustParsePrefix("192.0.0.0/32"), "a")
	trieMap.Insert(netip.MustParsePrefix("255.0.0.0/32"), "a")

	value, _ = trieMap.Get(netip.MustParseAddr("1.0.0.0"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("64.0.0.0"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("128.0.0.0"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.0.0.0"))
	require.Equal(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("255.0.0.0"))
	require.Equal(t, "a", value)

	trieMap.RemoveValue("a")

	value, _ = trieMap.Get(netip.MustParseAddr("1.0.0.0"))
	require.NotEqual(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("64.0.0.0"))
	require.NotEqual(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("128.0.0.0"))
	require.NotEqual(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("192.0.0.0"))
	require.NotEqual(t, "a", value)

	value, _ = trieMap.Get(netip.MustParseAddr("255.0.0.0"))
	require.NotEqual(t, "a", value)

	trieMap.RemoveValue("a")
	trieMap.RemoveValue("b")
	trieMap.RemoveValue("c")
	trieMap.RemoveValue("d")
	trieMap.RemoveValue("e")
	trieMap.RemoveValue("f")
	trieMap.RemoveValue("g")

	require.True(t, trieMap.Empty())

	trieMap.Insert(netip.MustParsePrefix("192.168.0.0/16"), "a")
	trieMap.Insert(netip.MustParsePrefix("192.168.0.0/24"), "a")

	trieMap.RemoveValue("a")

	_, contains := trieMap.Get(netip.MustParseAddr("192.168.0.1"))
	require.False(t, contains)
}

func TestTrieMapIPv6(t *testing.T) {
	trieMap := triemap.New[string]()

	trieMap.Insert(netip.MustParsePrefix("2607:5300:6000:6b00::c05f:543/128"), "d")
	trieMap.Insert(netip.MustParsePrefix("2607:5300:6000:6b00::/64"), "c")
	trieMap.Insert(netip.MustParsePrefix("::/0"), "e")
	trieMap.Insert(netip.MustParsePrefix("::/0"), "f")
	trieMap.Insert(netip.MustParsePrefix("2404:6800::/32"), "g")
	trieMap.Insert(netip.MustParsePrefix("2404:6800:4004:800:dead:beef:dead:beef/64"), "h")
	trieMap.Insert(netip.MustParsePrefix("2404:6800:4004:800:dead:beef:dead:beef/128"), "a")
	trieMap.Insert(netip.MustParsePrefix("2444:6800:40e4:800:deae:beef:def:beef/128"), "c")
	trieMap.Insert(netip.MustParsePrefix("2444:6800:f0e4:800:eeae:beef::/98"), "b")

	value, _ := trieMap.Get(netip.MustParseAddr("2607:5300:6000:6b00::c05f:543"))
	require.Equal(t, "d", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2607:5300:6000:6b00::c02e:1ee"))
	require.Equal(t, "c", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2607:5300:6000:6b01::"))
	require.Equal(t, "f", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:806::1006"))
	require.Equal(t, "g", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:806:0:1234:0:5678"))
	require.Equal(t, "g", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:67ff:4004:806:0:1234:0:5678"))
	require.Equal(t, "f", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6801:4004:806:0:1234:0:5678"))
	require.Equal(t, "f", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:800:0:1234:0:5678"))
	require.Equal(t, "h", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:800::"))
	require.Equal(t, "h", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:800:1010:1010:1010:1010"))
	require.Equal(t, "h", value)

	value, _ = trieMap.Get(netip.MustParseAddr("2404:6800:4004:800:dead:beef:dead:beef"))
	require.Equal(t, "a", value)
}
