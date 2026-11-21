"""
STAGE 4a: the report WRITERS.

A writer reads ONE cleaned visit and returns a report in a fixed format:

  {
    "attack_type": "scan" | "brute_force" | "dropper" | "recon",
    "summary":     plain-English sentences,
    "behaviors":   names from BEHAVIORS below,
    "evidence":    {addresses, urls, file_hashes, commands, credentials}
  }

Four writers share this format, so the checker never cares which one wrote the report:
  - FaithfulWriter   : fills a template straight from the footage (never invents anything)
  - MistakeWriter    : the faithful report with ONE known mistake slipped in on purpose
                       (so we can measure whether the checker catches it)
  - OllamaWriter     : a language model running on your own laptop
  - GroqWriter       : a language model on Groq's free cloud service (cleaned data only)

Privacy guard: before any text goes to a language model, we refuse to send it if it
contains anything shaped like a real IP address.
"""
import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from datetime import datetime

from features import LOOK_AROUND

ATTACK_TYPES = ["scan", "brute_force", "dropper", "recon"]

# behavior name -> (standard catalogue id, standard catalogue name)
BEHAVIORS = {
    "scanning": ("T1595", "Active Scanning"),
    "password_guessing": ("T1110", "Brute Force"),
    "tool_download": ("T1105", "Ingress Tool Transfer"),
    "run_downloaded_file": ("T1059", "Command and Scripting Interpreter"),
    "system_discovery": ("T1082", "System Information Discovery"),
}
BEHAVIOR_HELP = {
    "scanning": "connected and left without trying to log in much and without typing commands",
    "password_guessing": "made 3 or more failed login attempts",
    "tool_download": "typed a command that fetches a file from the internet (wget or curl)",
    "run_downloaded_file": "typed a command that makes a file runnable or runs it (chmod or ./file)",
    "system_discovery": "typed look-around commands such as whoami, uname -a, ls",
}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>;,)]+")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
HOST_RE = re.compile(r"\bhost-[0-9a-f]{8}\b")
FETCH = ("wget", "curl", "busybox wget")
RUN = ("chmod", "./")


def find_urls(text):
    """Web links in a piece of text, ignoring the full stop or comma that ends a sentence."""
    return [u.rstrip(".,:;!?") for u in URL_RE.findall(text)]


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _dedupe(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ------------------------------------------------------------ facts from the footage
def session_facts(events):
    """Everything a report may truthfully mention, computed straight from the footage."""
    fails = [e for e in events if e["eventid"] == "login.failed"]
    oks = [e for e in events if e["eventid"] == "login.success"]
    cmds = [e["input"] for e in events if e["eventid"] == "command.input"]
    dls = [e for e in events if e["eventid"] == "file.download"]
    urls = []
    for c in cmds:
        urls += find_urls(c)
    urls += [d["url"] for d in dls]
    connect = next((e for e in events if e["eventid"] == "session.connect"), {})
    return {
        "address": events[0]["src_ip"],
        "protocol": connect.get("protocol", "unknown"),
        "n_failed": len(fails),
        "n_success": len(oks),
        "commands": cmds,
        "urls": _dedupe(urls),
        "hashes": _dedupe([d["shasum"] for d in dls]),
        "logins": [(e["username"], e["password"]) for e in fails + oks],
        "success_logins": [(e["username"], e["password"]) for e in oks],
    }


def supported_behaviors(f):
    """The rules both the faithful writer and the checker use to decide what the footage supports."""
    s, cmds = set(), f["commands"]
    if f["n_failed"] >= 3:
        s.add("password_guessing")
    if any(c.startswith(FETCH) for c in cmds):
        s.add("tool_download")
    if any(c.startswith(RUN) for c in cmds):
        s.add("run_downloaded_file")
    if any(c in LOOK_AROUND for c in cmds):
        s.add("system_discovery")
    if f["n_success"] == 0 and not cmds and f["n_failed"] < 3:
        s.add("scanning")
    return s


def empty_report():
    return {"attack_type": "scan", "summary": "",
            "behaviors": [],
            "evidence": {"addresses": [], "urls": [], "file_hashes": [], "commands": [], "credentials": []}}


def normalise(raw):
    """Make whatever a language model returned fit the fixed format (without 'fixing' its content)."""
    r = empty_report()
    if not isinstance(raw, dict):
        return r
    r["attack_type"] = str(raw.get("attack_type", ""))
    r["summary"] = str(raw.get("summary", ""))
    b = raw.get("behaviors", [])
    r["behaviors"] = [str(x) for x in b] if isinstance(b, list) else []
    ev = raw.get("evidence", {})
    if isinstance(ev, dict):
        for k in r["evidence"]:
            v = ev.get(k, [])
            r["evidence"][k] = [str(x) for x in v] if isinstance(v, list) else []
    return r


# ------------------------------------------------------------ transcript for a language model
def transcript(events, max_failed=8):
    t0 = _ts(events[0]["timestamp"])
    lines, shown, hidden, last_failed_idx = [], 0, 0, None
    for e in events:
        dt = (_ts(e["timestamp"]) - t0).total_seconds()
        k = e["eventid"]
        if k == "login.failed":
            if shown >= max_failed:
                hidden += 1
                continue
            shown += 1
            text = f'login FAILED  user={e["username"]} password={e["password"]}'
        elif k == "login.success":
            text = f'login SUCCESS user={e["username"]} password={e["password"]}'
        elif k == "command.input":
            text = f'command typed: {e["input"]}'
        elif k == "file.download":
            text = f'file downloaded: url={e["url"]} fingerprint={e["shasum"]}'
        elif k == "session.connect":
            text = f'connect over {e["protocol"]} from {e["src_ip"]}'
        elif k == "client.version":
            text = f'client software: {e["version"]}'
        elif k == "session.closed":
            text = "disconnect"
        else:
            continue
        lines.append(f"[{dt:6.2f}s] {text}")
        if k == "login.failed":
            last_failed_idx = len(lines) - 1
    if hidden and last_failed_idx is not None:
        lines.insert(last_failed_idx + 1, f"         ({hidden} more similar failed logins not shown)")
    return "\n".join(lines)


SYSTEM_PROMPT = f"""You write short security reports about ONE visit to a decoy computer.
Use ONLY facts that appear in the facts and transcript you are given. Never invent addresses, web links,
file fingerprints, commands or numbers. Copy evidence exactly as it appears. If unsure, leave it out.

Return JSON with exactly these keys:
  attack_type: one of {ATTACK_TYPES}
  summary: 1-3 plain-English sentences a shop owner could understand
  behaviors: a list using ONLY these names:
{chr(10).join(f"    - {k}: {v}" for k, v in BEHAVIOR_HELP.items())}
  evidence: object with lists: addresses, urls, file_hashes, commands, credentials
            (credentials written as username/password)
attack_type meanings: scan = knocked and left; brute_force = guessed passwords; dropper = fetched or planted
a program; recon = looked around the machine."""

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "attack_type": {"type": "string", "enum": ATTACK_TYPES},
        "summary": {"type": "string"},
        "behaviors": {"type": "array", "items": {"type": "string", "enum": list(BEHAVIORS)}},
        "evidence": {"type": "object", "properties": {
            k: {"type": "array", "items": {"type": "string"}}
            for k in ["addresses", "urls", "file_hashes", "commands", "credentials"]}},
    },
    "required": ["attack_type", "summary", "behaviors", "evidence"],
}


def build_messages(events):
    f = session_facts(events)
    user = (f"Facts counted by our program: failed logins={f['n_failed']}, successful logins={f['n_success']}, "
            f"commands typed={len(f['commands'])}, files downloaded={len(f['hashes'])}.\n"
            f"Visitor code: {f['address']}\n\nTranscript:\n{transcript(events)}")
    # PRIVACY GUARD: nothing shaped like a real address may ever reach a language model.
    if IPV4.search(SYSTEM_PROMPT + user):
        raise RuntimeError("refusing to send: text contains an IP-address-shaped string "
                           "(was the data anonymised?)")
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


# ------------------------------------------------------------ writer 1: faithful template
class FaithfulWriter:
    name = "faithful"

    def write(self, events):
        f = session_facts(events)
        sup = supported_behaviors(f)
        cmds = f["commands"]
        if "tool_download" in sup:
            atype = "dropper"
        elif cmds:
            atype = "recon"
        elif f["n_failed"] >= 3:
            atype = "brute_force"
        else:
            atype = "scan"

        parts = [f"Visitor {f['address']} connected over {f['protocol']}."]
        if f["n_failed"]:
            parts.append(f"It made {f['n_failed']} failed login attempts.")
        if f["success_logins"]:
            u, p = f["success_logins"][0]
            parts.append(f"It then logged in successfully as {u}/{p}.")
        if cmds:
            parts.append(f"After that it typed {len(cmds)} commands.")
        if f["urls"]:
            parts.append(f"It tried to fetch files from {f['urls'][0]}.")
        if not (f["n_failed"] or cmds):
            parts.append("It disconnected without doing anything else.")

        notable = [c for c in _dedupe(cmds) if c.startswith(FETCH + RUN + ("rm -rf",)) or c in LOOK_AROUND]
        creds = _dedupe([f"{u}/{p}" for u, p in f["success_logins"]] + [f"{u}/{p}" for u, p in f["logins"]])[:6]
        rep = empty_report()
        rep.update({"attack_type": atype, "summary": " ".join(parts),
                    "behaviors": [b for b in BEHAVIORS if b in sup]})
        rep["evidence"] = {"addresses": [f["address"]], "urls": f["urls"], "file_hashes": f["hashes"],
                           "commands": notable[:12], "credentials": creds}
        return rep, {}


# ------------------------------------------------------------ writer 2: faithful + one planted mistake
MISTAKE_KINDS = [
    "fake_url",             # invents a web link
    "fake_hash",            # invents a file fingerprint
    "fake_command",         # invents a command nobody typed
    "wrong_count",          # states the wrong number of failed logins
    "extra_behavior",       # claims a behavior the footage does not support
    "fake_address",         # names a visitor that is not this one
    "fake_credential",      # invents a username/password pair
    "other_visit_url",      # a REAL link, but from a different visit (plausible-looking, wrong)
    "other_visit_hash",     # a REAL fingerprint, but from a different visit
    "wrong_attack_type",    # labels the visit with the wrong type (NOT an evidence error)
]


class MistakeWriter:
    name = "mistakes"

    def __init__(self, rate=0.5, seed=0, pool_urls=(), pool_hashes=()):
        self.rate, self.rng = rate, random.Random(seed)
        self.pool_urls, self.pool_hashes = list(pool_urls), list(pool_hashes)
        self.base = FaithfulWriter()

    def write(self, events):
        rep, _ = self.base.write(events)
        meta = {"injected": []}
        if self.rng.random() < self.rate:
            kind = self.rng.choice(MISTAKE_KINDS)
            kind = self._inject(kind, rep, events)
            meta["injected"].append(kind)
        return rep, meta

    def _inject(self, kind, rep, events):
        rng, f = self.rng, session_facts(events)
        ev, sup = rep["evidence"], supported_behaviors(f)
        if kind == "other_visit_url":
            c = [u for u in self.pool_urls if u not in f["urls"]]
            if c:
                u = rng.choice(c)
                ev["urls"].append(u)
                rep["summary"] += f" It also contacted {u}."
                return kind
            kind = "fake_url"
        if kind == "other_visit_hash":
            c = [h for h in self.pool_hashes if h not in f["hashes"]]
            if c:
                ev["file_hashes"].append(rng.choice(c))
                return kind
            kind = "fake_hash"
        if kind == "fake_url":
            u = f"http://evil-site-{rng.randint(1, 99)}.example.invalid/payload.sh"
            ev["urls"].append(u)
            rep["summary"] += f" It downloaded a script from {u}."
        elif kind == "fake_hash":
            ev["file_hashes"].append("%064x" % rng.getrandbits(256))
        elif kind == "fake_command":
            cands = [c for c in ["cat /etc/shadow", "rm -rf /", "iptables -F"] if c not in f["commands"]]
            ev["commands"].append(rng.choice(cands))
        elif kind == "wrong_count":
            wrong = f["n_failed"] + rng.choice([5, 11, 23, 40])
            if f["n_failed"]:
                rep["summary"] = rep["summary"].replace(f"{f['n_failed']} failed login attempts",
                                                        f"{wrong} failed login attempts")
            else:
                rep["summary"] += f" It made {wrong} failed login attempts."
        elif kind == "extra_behavior":
            cands = [b for b in BEHAVIORS if b not in sup]
            if cands:
                rep["behaviors"].append(rng.choice(cands))
            else:
                return self._inject("fake_url", rep, events)
        elif kind == "fake_address":
            ev["addresses"].append("host-deadbeef")
            rep["summary"] += " The same group was also seen from host-deadbeef."
        elif kind == "fake_credential":
            ev["credentials"].append("root/hunter2")
        elif kind == "wrong_attack_type":
            rep["attack_type"] = rng.choice([t for t in ATTACK_TYPES if t != rep["attack_type"]])
        return kind


# ------------------------------------------------------------ writers 3 and 4: real language models
def _parse_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?|```$", "", text).strip()
    return json.loads(text)


class OllamaWriter:
    """Language model running on YOUR laptop through Ollama. Nothing leaves the machine."""
    name = "ollama"

    def __init__(self, model="llama3.2:3b", host="http://localhost:11434", timeout=600):
        self.model, self.host, self.timeout = model, host, timeout

    def write(self, events):
        payload = {"model": self.model, "messages": build_messages(events), "stream": False,
                   "format": REPORT_SCHEMA, "options": {"temperature": 0}}
        last = None
        for _ in range(2):
            try:
                req = urllib.request.Request(self.host + "/api/chat", json.dumps(payload).encode(),
                                             {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    content = json.loads(r.read())["message"]["content"]
                return normalise(_parse_json(content)), {}
            except (urllib.error.URLError, ValueError, KeyError) as e:
                last = e
        raise RuntimeError(f"Ollama call failed ({last}). Is the Ollama app running and the model pulled?")


class GroqWriter:
    """Language model on Groq's free cloud tier. Cleaned data only. Needs GROQ_API_KEY."""
    name = "groq"

    def __init__(self, model="openai/gpt-oss-120b", pause=2.2):
        self.model, self.pause = model, pause
        self.key = os.environ.get("GROQ_API_KEY")
        if not self.key:
            raise RuntimeError("Set the GROQ_API_KEY environment variable first.")

    def write(self, events):
        payload = {"model": self.model, "messages": build_messages(events), "temperature": 0,
                   "response_format": {"type": "json_object"}}
        for attempt in range(4):
            try:
                req = urllib.request.Request(
                    "https://api.groq.com/openai/v1/chat/completions", json.dumps(payload).encode(),
                    {"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
                with urllib.request.urlopen(req, timeout=120) as r:
                    content = json.loads(r.read())["choices"][0]["message"]["content"]
                time.sleep(self.pause)  # stay under the free plan's requests-per-minute limit
                return normalise(_parse_json(content)), {}
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    time.sleep(10 * (attempt + 1))
                    continue
                raise
            except (ValueError, KeyError):
                continue
        raise RuntimeError("Groq call failed after several tries.")
