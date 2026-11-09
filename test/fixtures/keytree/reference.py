#!/usr/bin/env python3
"""
Independent reference for the key tree's shared test vectors, straight from the spec (stdlib only).

Both the Endpoint (C++) and the Bridge (TypeScript) read the vectors this writes, so neither implementation is the
source of the other's expectations. Change a layout here first, from the spec, then make both sides agree.

    H = sha256; u8/u32/u64 big-endian; lp(s) = u32(len) || s; a domain tag ends in NUL
    PH = H("pmx-group-policy\\0" || lp(creator) || lp(update) || lp(rotateKeys) || lp(updatePolicy)
           || lp(ownerCanBeRemovedFromManagers))          each field resolved against the frozen v3 defaults
    SB = "pmx-tree-commit\\0" || lp(groupId) || u32(treeVersion) || u64(seq) || lp(prevDigest) || u8(op) || u64(date)
         || u64(keyVersion) || lp(groupPubKey) || u64(rosterVersion) || RH || TH || PH || lp(committer)
         || lp(committerPubKey) || u32(committerSeat) || u32(#path) || (u32(v) || u32(gen) || lp(pk) || CH)*
         || list(addedUsers) || list(addedManagers) || list(removed)        list(l) = u32(#l) || lp(x)*

Usage:
    reference.py                 write keytree-vectors.json next to this script
    reference.py --check PATH    regenerate in memory and fail unless PATH is byte-identical
    reference.py --self-test     the domain tags are distinct, NUL-terminated and prefix-free
"""

import hashlib
import json
import os
import struct
import sys

# Every domain tag of the key tree, in one place. Later branches append theirs.
TAGS = [
    b"pmx-tree-commit\0",
    b"pmx-group-policy\0",
]

OP_CODES = {"create": 1, "add": 2, "remove": 3, "selfUpdate": 4, "rotate": 5, "policy": 6}

# Frozen with the v3 format: NOT the bridge's context defaults.
V3_POLICY_DEFAULTS = {
    "update": "manager",
    "rotateKeys": "manager",
    "updatePolicy": "manager",
    "ownerCanBeRemovedFromManagers": "yes",
}
SIGNED_POLICY_FIELDS = ["update", "rotateKeys", "updatePolicy", "ownerCanBeRemovedFromManagers"]


def u8(v):
    return struct.pack(">B", v)


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def lp(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return u32(len(b)) + b


def tag(name):
    t = name.encode("utf-8") + b"\0"
    assert t in TAGS, name
    return t


def resolve(policy, field):
    value = policy.get(field)
    return V3_POLICY_DEFAULTS[field] if value in (None, "inherit", "default") else value


def policy_hash(policy, creator):
    pre = tag("pmx-group-policy") + lp(creator)
    for field in SIGNED_POLICY_FIELDS:
        pre += lp(resolve(policy, field))
    return hashlib.sha256(pre).hexdigest()


def signed_bytes(s):
    b = tag("pmx-tree-commit")
    b += lp(s["groupId"]) + u32(s["treeVersion"]) + u64(s["seq"]) + lp(bytes.fromhex(s["prevDigest"]))
    b += u8(OP_CODES[s["op"]]) + u64(s["date"]) + u64(s["keyVersion"]) + lp(s["groupPubKey"])
    b += u64(s["rosterVersion"]) + bytes.fromhex(s["rosterHash"]) + bytes.fromhex(s["treeHash"])
    b += bytes.fromhex(s["policyHash"])
    b += lp(s["committer"]) + lp(s["committerPubKey"]) + u32(s["committerSeat"])
    b += u32(len(s["path"]))
    for e in s["path"]:
        b += u32(e["nodeIndex"]) + u32(e["generation"]) + lp(e["publicKey"]) + bytes.fromhex(e["subtreeHash"])
    for name in ("addedUsers", "addedManagers", "removed"):
        b += u32(len(s[name]))
        for x in s[name]:
            b += lp(x)
    return b


EXPLICIT = {"update": "user", "rotateKeys": "manager,owner", "updatePolicy": "owner", "ownerCanBeRemovedFromManagers": "no"}

POLICIES = [
    ({}, "alice"),
    ({f: "inherit" for f in SIGNED_POLICY_FIELDS}, "alice"),
    ({f: "default" for f in SIGNED_POLICY_FIELDS}, "alice"),
    (dict(EXPLICIT), "alice"),
    # Fields the statements do not sign: same hash as the explicit set above.
    (dict(EXPLICIT, get="all", delete="none", sendCustomNotification="user", item={"get": "user"}), "alice"),
    (dict(EXPLICIT), "bob"),
]

# rosterHash({carol, alice}, {bob}) and the tiny tree of TreeCommitsTest.cpp (themselves vectors there).
REMOVAL = {
    "groupId": "grp-1", "treeVersion": 2, "seq": 7, "prevDigest": "22" * 32, "op": "remove",
    "date": 1760000000000, "keyVersion": 4, "groupPubKey": "GPK", "rosterVersion": 9,
    "rosterHash": "d42481d52a260799898e5b45a151ab0cfc6e8ebca9ecc8c87b3f87a7c6783a9d",
    "treeHash": "b4db5638b91886d6a97283612ab5a836890e362e279f43dc77f8e059dc17598d",
    "policyHash": policy_hash({}, "alice"),
    "committer": "alice", "committerPubKey": "APK", "committerSeat": 0,
    "path": [{"nodeIndex": 3, "generation": 2, "publicKey": "pk3", "subtreeHash": "11" * 32}],
    "addedUsers": [], "addedManagers": [], "removed": ["bob"],
}

POLICY_CHANGE = dict(
    REMOVAL, seq=8, prevDigest="33" * 32, op="policy", date=1760000000001, policyHash=policy_hash(EXPLICIT, "alice"),
    path=[], removed=[], policy=dict(EXPLICIT),
)


def vectors():
    return {
        "signedBytes": [
            {"statement": s, "expectedHex": signed_bytes(s).hex()} for s in (REMOVAL, POLICY_CHANGE)
        ],
        "policyHash": [
            {"policy": p, "creator": c, "expectedHex": policy_hash(p, c)} for p, c in POLICIES
        ],
    }


def render():
    return json.dumps(vectors(), indent=2) + "\n"


def self_test():
    assert len(set(TAGS)) == len(TAGS), "duplicate tag"
    for t in TAGS:
        assert t.endswith(b"\0") and t.count(b"\0") == 1, t
    for a in TAGS:
        for b in TAGS:
            assert a == b or not b.startswith(a), (a, b)
    # The unsigned fields really are unsigned, and the creator really is signed.
    hashes = [v["expectedHex"] for v in vectors()["policyHash"]]
    assert hashes[0] == hashes[1] == hashes[2] and hashes[3] == hashes[4] and hashes[3] != hashes[5]


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    if argv[1:2] == ["--self-test"]:
        self_test()
        print("ok")
        return 0
    if argv[1:2] == ["--check"]:
        with open(argv[2], "r", encoding="utf-8") as f:
            if f.read() != render():
                print(f"{argv[2]} differs from the reference", file=sys.stderr)
                return 1
        print("ok")
        return 0
    with open(os.path.join(here, "keytree-vectors.json"), "w", encoding="utf-8") as f:
        f.write(render())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
