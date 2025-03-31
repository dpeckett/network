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

package triemap

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/dpeckett/network/internal/uint128"
)

// TrieMap contains an efficient trie structure of netip.Prefix that can
// match a netip.Addr to the associated Prefix if any and return the value
// associated with it of type V.
//
// # Use NewTrieMap to instantiate
//
// Currently this is a simple TrieMap, in the future it may have compression.
//
// See: https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux
type TrieMap[V comparable] struct {
	mu sync.RWMutex
	// This is the real triemap, but it only maps netip.Prefix / netip.Addr : int
	// see: https://planetscale.com/blog/generics-can-make-your-go-code-slower
	// The maps below map from int in this trie to generic value type V
	//
	// This is also cheaper in many cases because int will be smaller than V
	// so we can store V only once in the map here, and int indexes into those
	// maps in the trie structure, given than many trie nodes will map to the same
	// V, as our target use-case is CIDR-to-cloud-region
	trieMap trieMap

	// simple inline bimap of int keys to V values
	//
	// the inner trie stores an int key index into keyToValue
	//
	// valueToKey is to cheapen checking if we've already inserted a given V
	// and use the same key
	keyToValue map[int]V
	valueToKey map[V]int
}

// New[V] returns a new, properly allocated TrieMap[V]
func New[V comparable]() *TrieMap[V] {
	return &TrieMap[V]{
		keyToValue: make(map[int]V),
		valueToKey: make(map[V]int),
	}
}

// Insert inserts value into TrieMap by index prefix.
// You can later match a netip.Addr to value with Get().
func (t *TrieMap[V]) Insert(prefix netip.Prefix, value V) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key, alreadyHave := t.valueToKey[value]
	if !alreadyHave {
		key = len(t.keyToValue)
		t.valueToKey[value] = key
		t.keyToValue[key] = value
	}
	t.trieMap.insert(prefix, key)
}

// Get returns the associated value for the matching prefix if any with
// contains=true, or else the default value of V and contains=false.
func (t *TrieMap[V]) Get(addr netip.Addr) (value V, contains bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, contains := t.trieMap.get(addr)
	if contains {
		value = t.keyToValue[key]
	}
	return
}

// Remove removes the prefix from the TrieMap.
// Returns true if the prefix was removed, false if it was not found.
func (t *TrieMap[V]) Remove(prefix netip.Prefix) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	key, removed := t.trieMap.remove(prefix)
	// If there are no more references to the key, remove the value.
	if removed && t.trieMap.keyRefs[key] == 0 {
		delete(t.keyToValue, key)
		delete(t.valueToKey, t.keyToValue[key])
	}
	return removed
}

// RemoveValue removes all prefixes with the given value from the TrieMap.
func (t *TrieMap[V]) RemoveValue(value V) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key, contains := t.valueToKey[value]
	if !contains {
		return
	}
	t.trieMap.removeAll(key)
	delete(t.keyToValue, key)
	delete(t.valueToKey, value)
}

// Empty returns true if the TrieMap is empty.
func (t *TrieMap[V]) Empty() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ipv4Root := t.trieMap.ipv4Root
	ipv6Root := t.trieMap.ipv6Root

	return (ipv4Root == nil || (ipv4Root.child0 == nil && ipv4Root.child1 == nil && ipv4Root.value == nil)) &&
		(ipv6Root == nil || (ipv6Root.child0 == nil && ipv6Root.child1 == nil && ipv6Root.value == nil))
}

// trieMap is the core implementation but it only stores netip.Prefix : int.
type trieMap struct {
	ipv4Root *trieNode
	ipv6Root *trieNode
	keyRefs  map[int]int
}

type trieNode struct {
	child0, child1 *trieNode
	value          *nodeValue
}

type nodeValue struct {
	prefix netip.Prefix
	key    int
}

func (t *trieMap) get(addr netip.Addr) (key int, contains bool) {
	root := t.getRootNode(addr)
	if root == nil {
		return -1, false
	}
	curr := root

	// Maybe the root node matches.
	var longestMatchLength int = -1
	if curr.value != nil && curr.value.prefix.Contains(addr) {
		longestMatchLength = curr.value.prefix.Bits()
		key = curr.value.key
		contains = true
	}

	ip, totalBits := addrToUint128(addr)
	for i := totalBits - 1; i >= 0; i-- {
		if ip.Bit(i) {
			if curr.child1 != nil {
				curr = curr.child1
			} else {
				break
			}
		} else {
			if curr.child0 != nil {
				curr = curr.child0
			} else {
				break
			}
		}

		// check for a match in the current node.
		if curr.value != nil && curr.value.prefix.Contains(addr) {
			if curr.value.prefix.Bits() > longestMatchLength {
				longestMatchLength = curr.value.prefix.Bits()
				key = curr.value.key
				contains = true
			}
		}
	}

	return
}

// insert handles inserting keys into the trie based on prefix.
func (t *trieMap) insert(prefix netip.Prefix, key int) {
	root := t.getRootNode(prefix.Addr())
	if root == nil {
		if prefix.Addr().Unmap().Is4() {
			t.ipv4Root = &trieNode{}
			root = t.ipv4Root
		} else {
			t.ipv6Root = &trieNode{}
			root = t.ipv6Root
		}
	}
	curr := root
	ip, totalBits := addrToUint128(prefix.Addr())
	bits := prefix.Bits()
	for i := totalBits - 1; i >= totalBits-bits; i-- {
		if ip.Bit(i) {
			if curr.child1 == nil {
				curr.child1 = &trieNode{}
			}
			curr = curr.child1
		} else {
			if curr.child0 == nil {
				curr.child0 = &trieNode{}
			}
			curr = curr.child0
		}
	}

	if curr.value != nil {
		t.keyRefs[curr.value.key]--
	}
	if t.keyRefs == nil {
		t.keyRefs = make(map[int]int)
	}
	t.keyRefs[key]++

	curr.value = &nodeValue{prefix: prefix, key: key}
}

// remove handles removing keys from the trie based on prefix.
func (t *trieMap) remove(prefix netip.Prefix) (int, bool) {
	var stack []*trieNode
	root := t.getRootNode(prefix.Addr())
	if root == nil {
		return -1, false
	}
	curr := root
	bits := prefix.Bits()
	ip, totalBits := addrToUint128(prefix.Addr())
	for i := totalBits - 1; i >= totalBits-bits; i-- {
		stack = append(stack, curr)
		if ip.Bit(i) {
			curr = curr.child1
		} else {
			curr = curr.child0
		}
		if curr == nil {
			return -1, false
		}
	}
	stack = append(stack, curr)
	if curr.value != nil && curr.value.prefix == prefix {
		key := curr.value.key
		curr.value = nil
		t.keyRefs[key]--
		if t.keyRefs[key] == 0 {
			delete(t.keyRefs, key)
		}
		prune(stack)
		return key, true
	}
	return -1, false
}

// removeAll removes all nodes with the given key.
func (t *trieMap) removeAll(key int) {
	var prefixes []netip.Prefix

	// Traverse the trie to find all prefixes with the given key.
	var stack []*trieNode
	if t.ipv4Root != nil {
		stack = append(stack, t.ipv4Root)
	}
	if t.ipv6Root != nil {
		stack = append(stack, t.ipv6Root)
	}
	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if curr.value != nil && curr.value.key == key {
			prefixes = append(prefixes, curr.value.prefix)
		}
		if curr.child0 != nil {
			stack = append(stack, curr.child0)
		}
		if curr.child1 != nil {
			stack = append(stack, curr.child1)
		}
	}

	for _, prefix := range prefixes {
		t.remove(prefix)
	}
}

// getRootNode selects the root node based on the IP type.
func (t *trieMap) getRootNode(addr netip.Addr) *trieNode {
	if addr.Unmap().Is4() {
		return t.ipv4Root
	} else {
		return t.ipv6Root
	}
}

// prune checks nodes from the bottom up to remove any that are no longer needed.
func prune(stack []*trieNode) {
	for i := len(stack) - 1; i >= 0; i-- {
		node := stack[i]
		if node.child0 == nil && node.child1 == nil && node.value == nil {
			if i > 0 { // Check if not root
				parent := stack[i-1]
				if parent.child0 == node {
					parent.child0 = nil
				} else {
					parent.child1 = nil
				}
			}
		} else {
			break
		}
	}
}

// addrToUint128 converts a netip.Addr into a uint128.Uint128 for easy bit manipulation.
// It returns the uint128 and the total number of bits for the given address type.
func addrToUint128(addr netip.Addr) (uint128.Uint128, int) {
	if addr.Unmap().Is4() {
		ip4 := addr.As4()
		return uint128.From64(uint64(binary.BigEndian.Uint32(ip4[:]))), 32
	}
	ip6 := addr.As16()
	return uint128.New(binary.BigEndian.Uint64(ip6[8:]), binary.BigEndian.Uint64(ip6[:8])), 128
}
