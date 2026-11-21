"""
Turn each visit (a list of events) into a row of numbers a classifier can learn from.

Reads ONLY the cleaned footage (sessions_anon.jsonl). It never touches the answer key.
"""
import json
from collections import defaultdict
from datetime import datetime

# Commands people type to look around a machine.
LOOK_AROUND = {"whoami", "uname -a", "cat /proc/cpuinfo", "ls -la", "id", "w",
               "cat /etc/passwd", "free -m", "df -h", "ps aux", "ifconfig",
               "cat /etc/os-release", "uptime", "ls /home", "crontab -l"}

FEATURE_NAMES = [
    "duration_s",            # how long the visit lasted
    "n_events",              # total things recorded
    "n_failed_logins",       # wrong guesses
    "n_successful_logins",   # guesses that worked
    "failed_logins_per_s",   # how fast they guessed
    "n_distinct_passwords",  # variety of guesses
    "mean_login_gap_s",      # average pause between guesses (-1 if fewer than 2)
    "n_commands",            # things typed after getting in
    "mean_command_gap_s",    # average pause between commands (-1 if fewer than 2)
    "min_command_gap_s",     # shortest pause between commands (-1 if fewer than 2)
    "n_look_around_cmds",    # commands from the "look around" list
    "n_downloads",           # files downloaded
    "has_fetch_command",     # typed wget / curl
    "has_run_command",       # typed chmod or ./something
    "has_cleanup_command",   # typed rm -rf (covering tracks)
    "is_ssh",                # 1 = remote login door, 0 = the older telnet door
]


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _gaps(times):
    return [(b - a).total_seconds() for a, b in zip(times, times[1:])]


def _mean(xs):
    return sum(xs) / len(xs) if xs else -1.0


def load_sessions(path):
    by = defaultdict(list)
    for line in open(path):
        e = json.loads(line)
        by[e["session"]].append(e)
    for evs in by.values():
        evs.sort(key=lambda e: e["timestamp"])
    return by


def session_features(evs):
    t = [_ts(e["timestamp"]) for e in evs]
    duration = (t[-1] - t[0]).total_seconds()
    fails = [e for e in evs if e["eventid"] == "login.failed"]
    oks = [e for e in evs if e["eventid"] == "login.success"]
    cmds = [e for e in evs if e["eventid"] == "command.input"]
    downloads = [e for e in evs if e["eventid"] == "file.download"]
    text = [c["input"] for c in cmds]
    cmd_gaps = _gaps([_ts(c["timestamp"]) for c in cmds])
    login_gaps = _gaps([_ts(f["timestamp"]) for f in fails])
    connect = next((e for e in evs if e["eventid"] == "session.connect"), {})
    return [
        duration,
        len(evs),
        len(fails),
        len(oks),
        len(fails) / max(duration, 0.1),
        len({f["password"] for f in fails}),
        _mean(login_gaps),
        len(cmds),
        _mean(cmd_gaps),
        min(cmd_gaps) if cmd_gaps else -1.0,
        sum(1 for c in text if c in LOOK_AROUND),
        len(downloads),
        int(any(c.startswith(("wget", "curl", "busybox wget")) for c in text)),
        int(any(c.startswith(("chmod", "./")) for c in text)),
        int(any(c.startswith("rm -rf") for c in text)),
        int(connect.get("protocol") == "ssh"),
    ]
