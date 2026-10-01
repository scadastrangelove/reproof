# object — Mach-O exports-trie infinite loop (unbounded Vec growth / hang)

- **Crate:** `object` 0.39.1 (also master). **Class:** infinite loop + unbounded alloc → DoS (memory-safe). CWE-835 / CWE-674.
- **Severity:** Medium (availability); reachable via the **secondary** public API `LinkeditDataCommand::exports_trie()`, NOT `File::parse` / `Object::exports()` (which walks the dysymtab, not the trie). Affects callers that enumerate Mach-O exports via the trie.
- **Reproducer:** a **52-byte** Mach-O (`poc.bin`, generator `make_poc.py`) + driver `trie_driver.rs`.

## Root cause (code-confirmed)

`NodeIterator` (`src/read/macho/exports_trie.rs`) follows child edges by absolute offset:
`self.offset = child_offset as usize;` (line 189), where `child_offset` is an attacker uleb128, with
**no forward-progress check, no visited-set, and no depth/stack cap** (verified: no such guard tokens in
the file). A node whose single child edge points back to its own offset makes `push_node()` re-read the
same node and push a new `Frame` every iteration; since the node is non-terminal (`terminal_size==0`),
`ExportsTrieIterator::next()` never yields and never returns — an infinite loop with `Vec<Frame>` growing
until OOM.

## Empirically confirmed

`trie_driver` (parses the Mach-O, walks load commands, calls `exports_trie()`, iterates) on the 52-byte
`poc.bin`:

```
entering exports_trie iteration...
<hangs> → killed by `timeout 8`, exit 124
```

The 4-byte trie `[0x00, 0x01, 0x00, 0x00]` = terminal_size 0, children_count 1, empty edge string,
child_offset 0 → the root's only child edge points back to the root.

## Suggested fix

Add a visited-set or a strictly-increasing-offset / depth cap to the trie DFS (child_offset must advance
past the current node), or bound the total node count against the trie data length.
