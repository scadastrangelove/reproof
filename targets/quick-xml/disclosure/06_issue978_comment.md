# Comment on #978 — the missing recursion-depth cap also needs to cover `deserialize_seq` and the enum path

Ran a variant sweep for other recursion cycles in `de/` that share this issue's "no depth cap" root cause
(the `Deserializer` struct has no depth field; only `event_buffer_size`/`limit`, which bounds the
overlapped-lists skip buffer, not call-stack depth). Two more cycles reproduce the same uncatchable
`stack overflow, aborting` abort as the one already reported here, through **different** serde entry
points — worth folding into whatever fix lands for this issue, since a cap added only to the
`deserialize_struct` → `next_value_seed` cycle this issue describes would not cover them.

**1. `deserialize_seq` cycle** (a `Vec<Self>` field — the natural shape for a list of same-typed nested
elements): `deserialize_seq` (`de/map.rs:607`) → `visit_seq(MapValueSeqAccess)` → `next_element_seed`
(`map.rs:954`) → `ElementDeserializer::deserialize_struct` (`map.rs:1137`) →
`visitor.visit_map(ElementMapAccess::new(..))` (`map.rs:1146`) → back into `next_value_seed` →
`deserialize_seq`. One frame per nesting level.

```rust
#[derive(serde::Deserialize)]
struct Node { #[serde(default, rename = "Node")] node: Vec<Node> }

fn main() {
    let xml = "<Node>".repeat(10_000) + &"</Node>".repeat(10_000);
    let _: Result<Node, _> = quick_xml::de::from_str(&xml);
}
```
Depth 1,000 returns cleanly; depth 10,000 (~70 KB) → `thread 'main' has overflowed its stack / fatal
runtime error: stack overflow, aborting`.

**2. Enum `newtype_variant`/`struct_variant`/`tuple_variant` cycle**: `deserialize_enum`
(`de/mod.rs:3295`) → `EnumAccess::variant_seed` (`de/var.rs:39`) →
`VariantAccess::newtype_variant_seed` (`de/var.rs:105`, `seed.deserialize(self.de)`) → re-enters
`deserialize_enum`. `deserialize_any` (hence `serde_json::Value`-shaped targets) routes through the same
enum/struct/seq machinery with **no recursive user type required**.

```rust
#[derive(serde::Deserialize)]
enum E { Leaf(bool), Wrap(Box<E>) }

fn main() {
    let xml = "<Wrap>".repeat(10_000) + &"</Wrap>".repeat(10_000);
    let _: Result<E, _> = quick_xml::de::from_str(&xml);
}
```
Same abort as above.

Both confirmed on `master`, release build. Whatever depth-tracking mechanism ends up fixing the struct/map
cycle in this issue, it'll need to live somewhere shared (e.g. on the `Deserializer` itself, checked at
the top of `deserialize_struct`, `deserialize_seq`, *and* `deserialize_enum`) so it catches all three
re-entry points rather than just the one this issue was filed against.

Found with the [rust-in-peace](https://github.com/scadastrangelove/rust-in-peace) security pipeline.
