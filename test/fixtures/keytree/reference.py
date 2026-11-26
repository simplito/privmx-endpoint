#!/usr/bin/env python3
"""
Independent reference for the key tree's shared test vectors, straight from the spec (stdlib only).

Both the Endpoint (C++) and the Bridge (TypeScript) read the vectors this writes, so neither implementation is the
source of the other's expectations. Change a layout here first, from the spec, then make both sides agree.

    H = sha256; u8/u32/u64 big-endian; lp(s) = u32(len) || s; a domain tag ends in NUL
    PH = H("pmx-group-rules-v1\\0" || lp(creator) || lp(addMembers) || lp(removeMembers) || lp(replaceMemberKeys)
           || lp(changeRoles) || lp(changeRules) || lp(changeVisibility) || lp(trimHistory) || lp(editPublicMeta)
           || lp(editPrivateMeta))     the rules object holds exactly these nine, each "managers", "members" or "nobody"
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
    b"pmx-group-rules-v1\0",
    b"pmx-space-id\0",
    b"pmx-space-recipients\0",
    b"pmx-space-key\0",
    b"pmx-space-statement\0",
    b"pmx-space-via\0",
]

OP_CODES = {"create": 1, "add": 2, "remove": 3, "selfUpdate": 4, "rotate": 5, "policy": 6, "roles": 7, "reseat": 8}

WHO = ("managers", "members", "nobody")
RULE_FIELDS = [
    "addMembers", "removeMembers", "replaceMemberKeys", "changeRoles", "changeRules", "changeVisibility", "trimHistory",
    "editPublicMeta", "editPrivateMeta",
]
ALL_MANAGERS = {field: "managers" for field in RULE_FIELDS}


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


def rules_hash(rules, creator):
    assert set(rules) == set(RULE_FIELDS), rules
    pre = tag("pmx-group-rules-v1") + lp(creator)
    for field in RULE_FIELDS:
        assert rules[field] in WHO, (field, rules[field])
        pre += lp(rules[field])
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


EXPLICIT = dict(
    ALL_MANAGERS, addMembers="members", removeMembers="nobody", replaceMemberKeys="members", trimHistory="nobody",
    editPublicMeta="members",
)
IMMUTABLE = dict(ALL_MANAGERS, addMembers="nobody", removeMembers="nobody", changeRoles="nobody", changeRules="nobody")

# The first five are the Bridge's own conformance vectors.
RULES = [
    (dict(ALL_MANAGERS), "alice"),
    (dict(ALL_MANAGERS), "bob"),
    (dict(EXPLICIT), "alice"),
    ({field: "members" for field in RULE_FIELDS}, "alice"),
    (dict(ALL_MANAGERS, changeRoles="nobody", changeRules="nobody", changeVisibility="members", editPrivateMeta="members"),
     "alice"),
    (dict(IMMUTABLE), "alice"),
]

# Rules objects both sides refuse: a field missing, one unknown, a value outside the field's set, the old grammar.
INVALID_RULES = [
    {k: v for k, v in ALL_MANAGERS.items() if k != "trimHistory"},
    dict(ALL_MANAGERS, history="shared"),
    dict(ALL_MANAGERS, manage="managers"),
    dict(ALL_MANAGERS, addMembers="manager"),
    dict(ALL_MANAGERS, removeMembers="manager,owner"),
    dict(ALL_MANAGERS, editPublicMeta="all"),
    dict(ALL_MANAGERS, editPrivateMeta=""),
    dict(ALL_MANAGERS, addMembers=1),
    {},
]

# rosterHash({carol, alice}, {bob}) and the tiny tree of TreeCommitsTest.cpp (themselves vectors there).
REMOVAL = {
    "groupId": "grp-1", "treeVersion": 2, "seq": 7, "prevDigest": "22" * 32, "op": "remove",
    "date": 1760000000000, "keyVersion": 4, "groupPubKey": "GPK", "rosterVersion": 9,
    "rosterHash": "d42481d52a260799898e5b45a151ab0cfc6e8ebca9ecc8c87b3f87a7c6783a9d",
    "treeHash": "b4db5638b91886d6a97283612ab5a836890e362e279f43dc77f8e059dc17598d",
    "policyHash": rules_hash(ALL_MANAGERS, "alice"),
    "committer": "alice", "committerPubKey": "APK", "committerSeat": 0,
    "path": [{"nodeIndex": 3, "generation": 2, "publicKey": "pk3", "subtreeHash": "11" * 32}],
    "addedUsers": [], "addedManagers": [], "removed": ["bob"],
}

POLICY_CHANGE = dict(
    REMOVAL, seq=8, prevDigest="33" * 32, op="policy", date=1760000000001, policyHash=rules_hash(EXPLICIT, "alice"),
    path=[], removed=[], policy=dict(EXPLICIT),
)

# bob becomes a manager, carol a user: no node, no epoch, the roster version moves.
ROLES = dict(
    REMOVAL, seq=9, prevDigest="44" * 32, op="roles", date=1760000000002, rosterVersion=10,
    path=[], removed=[], addedManagers=["bob"], addedUsers=["carol"],
)

# A removal's statement in every field but the op: `removed` names who was reseated.
RESEAT = dict(REMOVAL, seq=10, prevDigest="55" * 32, op="reseat", date=1760000000003, keyVersion=5, rosterVersion=11)


# -- a Space's statements (proposals/space-log-format.md) ------------------------------------------------

SPACE_OPS = {"create": 1, "add": 2, "remove": 3, "rotate": 4}


def space_recipients_hash(groups, users):
    b = tag("pmx-space-recipients") + u32(len(groups))
    for g in sorted(groups, key=lambda g: g["groupId"].encode("utf-8")):
        b += lp(g["groupId"]) + lp(g["role"]) + u64(g["groupKeyVersion"]) + lp(g["groupPubKey"])
    b += u32(len(users))
    for u in sorted(users, key=lambda u: u["userId"].encode("utf-8")):
        b += lp(u["userId"]) + lp(u["pubKey"]) + lp(u["role"])
    return hashlib.sha256(b).digest()


def space_key_commit(space_id, key_version, key_hex):
    return hashlib.sha256(tag("pmx-space-key") + lp(space_id) + u64(key_version) + bytes.fromhex(key_hex)).hexdigest()


def space_signed_bytes(s):
    prev = bytes.fromhex(s["prevDigest"])
    assert len(prev) == (0 if s["seq"] == 1 else 32)
    key_commit = bytes.fromhex(s["keyCommit"])
    assert len(key_commit) == 32
    return (
        tag("pmx-space-statement") + u8(1) + lp(s["spaceId"]) + lp(s["contextId"]) + u64(s["seq"]) + lp(prev)
        + u8(SPACE_OPS[s["op"]]) + u64(s["date"]) + u64(s["keyVersion"]) + key_commit
        + space_recipients_hash(s["groups"], s["users"]) + lp(s["signer"]) + lp(s["signerPubKey"]) + lp(s["via"])
    )


def space_via_bytes(s):
    return tag("pmx-space-via") + hashlib.sha256(space_signed_bytes(s)).digest()


SPACE_ID = "5a" * 32
SPACE_KEY = "11" * 32
SPACE_GROUPS = [
    {"groupId": "sales", "role": "manager", "groupKeyVersion": 3, "groupPubKey": "SALES-PK"},
    {"groupId": "Support", "role": "user", "groupKeyVersion": 1, "groupPubKey": "SUPPORT-PK"},
]
SPACE_USERS = [
    {"userId": "bob", "pubKey": "BOB-PK", "role": "user"},
    {"userId": "alice", "pubKey": "ALICE-PK", "role": "manager"},
]
SPACE_CREATE = {
    "spaceId": SPACE_ID, "contextId": "ctx-1", "seq": 1, "prevDigest": "", "op": "create", "date": 1760000000000,
    "keyVersion": 1, "keyCommit": space_key_commit(SPACE_ID, 1, SPACE_KEY), "groups": SPACE_GROUPS,
    "users": SPACE_USERS, "signer": "alice", "signerPubKey": "ALICE-PK", "via": "",
}
SPACE_ROTATE_VIA_GROUP = dict(
    SPACE_CREATE, seq=2, prevDigest="33" * 32, op="rotate", keyVersion=2,
    keyCommit=space_key_commit(SPACE_ID, 2, "22" * 32), signer="carol", signerPubKey="CAROL-PK", via="sales",
)
SPACE_REMOVE = dict(
    SPACE_ROTATE_VIA_GROUP, seq=3, prevDigest="44" * 32, op="remove", keyVersion=3,
    keyCommit=space_key_commit(SPACE_ID, 3, "33" * 32), groups=SPACE_GROUPS[:1], users=[],
)
SPACE_ADD = dict(SPACE_REMOVE, seq=4, prevDigest="55" * 32, op="add", users=SPACE_USERS[:1])


def vectors():
    return {
        "signedBytes": [
            {"statement": s, "expectedHex": signed_bytes(s).hex()} for s in (REMOVAL, POLICY_CHANGE, ROLES, RESEAT)
        ],
        "policyHash": [
            {"policy": p, "creator": c, "expectedHex": rules_hash(p, c)} for p, c in RULES
        ],
        "invalidRules": INVALID_RULES,
        "spaceStatement": [
            {
                "statement": st,
                "recipientsHashHex": space_recipients_hash(st["groups"], st["users"]).hex(),
                "signedBytesHex": space_signed_bytes(st).hex(),
                "viaBytesHex": space_via_bytes(st).hex(),
            }
            for st in (SPACE_CREATE, SPACE_ROTATE_VIA_GROUP, SPACE_REMOVE, SPACE_ADD)
        ],
        "spaceKeyCommit": [
            {"spaceId": SPACE_ID, "keyVersion": v, "keyHex": k, "expectedHex": space_key_commit(SPACE_ID, v, k)}
            for v, k in ((1, SPACE_KEY), (2, SPACE_KEY), (1, "22" * 32))
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
    # The creator is signed, and the fields are positional.
    hashes = [v["expectedHex"] for v in vectors()["policyHash"]]
    assert len(set(hashes)) == len(hashes)


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
