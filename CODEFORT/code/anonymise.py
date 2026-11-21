#!/usr/bin/env python3
"""
STAGE 2: hide identities before the data goes anywhere else.

Reads   data/sessions.jsonl   (and data/labels.json for the grader)
Writes  data/sessions_anon.jsonl, data/labels_anon.json, data/anon_report.json

What it does to every event:
  1. src_ip      -> a scrambled code like "host-3fa91c0b"  (same address, same code, always)
  2. src_port    -> removed (temporary number, no intelligence value)
  3. IP addresses hiding inside commands or links -> the same scrambled code
  4. usernames / passwords -> kept only if COMMON (seen in many visits);
                              rare ones become "masked-xxxxxx"
  Everything else (commands, web links, file fingerprints, timing) is kept,
  because that is the evidence our reports need.

The scrambling uses a SECRET KEY (secret.key). Without the key nobody can turn a code
back into an address. The key must stay inside the lab: never upload or share it.

Usage:  python3 anonymise.py --data data
"""
import argparse
import hashlib
import hmac
import json
import os
import re
from collections import Counter

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
COMMON_THRESHOLD = 5  # a username/password seen in fewer visits than this counts as "rare"


def load_key(path):
    """Use the saved secret key, or create one the first time."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(os.urandom(32).hex())
        os.chmod(path, 0o600)
        print(f"created new secret key: {path}  (keep it inside the lab)")
    return open(path).read().strip().encode()


class Scrambler:
    def __init__(self, key):
        self.key = key
        self.seen = {}  # code -> original, only used to detect two addresses sharing one code

    def _h(self, text, n):
        return hmac.new(self.key, text.encode(), hashlib.sha256).hexdigest()[:n]

    def ip(self, ip):
        code = "host-" + self._h(ip, 8)
        if self.seen.setdefault(code, ip) != ip:
            raise RuntimeError(f"two different addresses got the same code: {code}")
        return code

    def mask(self, value):
        return "masked-" + self._h(value, 6)

    def scrub_text(self, text):
        """Replace any IP address that appears inside a free-text field."""
        return IPV4.sub(lambda m: self.ip(m.group(0)), text)


def find_common_credentials(events):
    """A username or password is 'common' if many different visits used it."""
    users, pwds = {}, {}
    for e in events:
        if "username" in e:
            users.setdefault(e["username"], set()).add(e["session"])
        if "password" in e:
            pwds.setdefault(e["password"], set()).add(e["session"])
    cu = {u for u, s in users.items() if len(s) >= COMMON_THRESHOLD}
    cp = {p for p, s in pwds.items() if len(s) >= COMMON_THRESHOLD}
    return cu, cp


def anonymise(events, scr):
    common_users, common_pwds = find_common_credentials(events)
    stats = Counter()
    out = []
    for e in events:
        a = dict(e)
        a["src_ip"] = scr.ip(a["src_ip"])
        stats["addresses_scrambled"] += 1
        if "src_port" in a:
            del a["src_port"]
            stats["ports_removed"] += 1
        if "username" in a and a["username"] not in common_users:
            a["username"] = scr.mask(a["username"])
            stats["rare_usernames_masked"] += 1
        if "password" in a and a["password"] not in common_pwds:
            a["password"] = scr.mask(a["password"])
            stats["rare_passwords_masked"] += 1
        for field in ("input", "url"):
            if field in a:
                new = scr.scrub_text(a[field])
                if new != a[field]:
                    stats["addresses_scrubbed_from_text"] += 1
                a[field] = new
        out.append(a)
    return out, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--key", default="secret.key")
    a = ap.parse_args()

    scr = Scrambler(load_key(a.key))
    events = [json.loads(l) for l in open(os.path.join(a.data, "sessions.jsonl"))]
    anon, stats = anonymise(events, scr)

    with open(os.path.join(a.data, "sessions_anon.jsonl"), "w") as f:
        for e in anon:
            f.write(json.dumps(e) + "\n")

    # The answer key is for grading only, but it must use the same codes to line up.
    labels = json.load(open(os.path.join(a.data, "labels.json")))
    for lab in labels:
        lab["src_ip"] = scr.ip(lab["src_ip"])
    json.dump(labels, open(os.path.join(a.data, "labels_anon.json"), "w"), indent=1)

    report = {"events_in": len(events), "events_out": len(anon),
              "distinct_addresses": len(scr.seen), **dict(stats)}
    json.dump(report, open(os.path.join(a.data, "anon_report.json"), "w"), indent=1)
    for k, v in report.items():
        print(f"  {k:32s} {v}")


if __name__ == "__main__":
    main()
