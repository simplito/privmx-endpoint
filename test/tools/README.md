# Key-tree conformance check

The client and the bridge each implement the same array-indexed left-balanced binary tree arithmetic. **They
must agree exactly.** The server performs the same computation to decide which nodes a member removal is obliged
to refresh; if the two disagree, the server either rejects valid removals or — the dangerous direction — accepts
one that leaves a removed member holding a current node key.

Two independent codebases with the same required behaviour is exactly the situation that drifts, so the check is
a diff of generated vectors rather than a promise.

## Running it

```bash
# endpoint side
cmake --build <build-dir> --target keytree_conformance_dump
<build-dir>/test/keytree_conformance_dump > /tmp/endpoint.txt

# bridge side
cd <privmx-bridge>
npm run build
node out/service/cloud/keytree/conformanceDump.js > /tmp/bridge.txt

diff /tmp/bridge.txt /tmp/endpoint.txt && echo "conformant"
```

Coverage, 6674 lines in total:

- **tree** — every leaf count from 1 to 64 and, for each, every leaf position and every node: level, parent,
  sibling, children, direct path and copath. Includes all the truncated right-edge cases that break naive
  implementations.
- **ladder** — rung sets, skip targets and unit-rung obligation for 200 epochs under two era floors; descent
  plans and their bounds for ten distance pairs; descent floors; and twelve rung-set validation cases covering
  every rejection reason.

## Whole-state conformance

The arithmetic diff above proves the two implementations compute the same *topology*. It does not prove the
client builds a **state the server accepts**: that also depends on which edges are submitted, which generations
they name, and what a removal or an addition is allowed to change. Those rules live in two places — this side
constructs the state, `src/service/cloud/keytree/TreeValidator.ts` on the bridge decides whether it is
well-formed — and a divergence between them would pass both codebases' own unit tests while leaving a client
unable to remove anyone.

`keytree_state_dump` closes that gap. It runs the real plans with real EC keys and real ECIES, and emits the
resulting complete states as JSON. The bridge's test suite then runs its **production validator** over them
(`src/test/service/cloud/keytree/TreeStateConformance.test.ts`).

```bash
cmake --build <build-dir> --target keytree_state_dump
<build-dir>/test/keytree_state_dump > <privmx-bridge>/src/test/fixtures/keytree-states.json

cd <privmx-bridge> && npm run build && npx q2-test out/test/service/cloud/keytree
```

Regenerate the fixture whenever `TreeWire`, `TreeKeys` or the wire format changes; a failure afterwards means the
two sides disagree about what a well-formed state is, which is precisely what this is for. Wrapped blobs are
truncated in the dump on purpose — the validator checks that an edge carries a ciphertext, never what is in one,
because the server cannot decrypt anything.

Coverage: creation for twelve leaf counts (including truncated trees), removal at every position of five sizes
with the rungs each publishes, and additions both into a blank left by a removal and appended so the tree grows
and re-parents an existing leaf.

## Without a full build

The arithmetic depends on nothing but `<cstdint>` and `<vector>`, so it compiles standalone:

```bash
clang++ -std=c++20 -I endpoint/group/include \
    endpoint/group/src/keytree/TreeMath.cpp test/tools/keytree_conformance_dump.cpp -o /tmp/dump
```

The same holds for the unit tests, which need only GTest:

```bash
clang++ -std=c++20 -I endpoint/group/include -I/opt/homebrew/include -L/opt/homebrew/lib \
    -lgtest -lgtest_main \
    endpoint/group/src/keytree/TreeMath.cpp test/tests/unit/TreeMathTest.cpp -o /tmp/treemath_test && /tmp/treemath_test
```

That independence is deliberate: a unit test for pure arithmetic should not require Poco, OpenSSL or a running
bridge, and the CMake target reflects it by compiling `TreeMath.cpp` into the test rather than linking
`privmxendpointgroup`.
