"""
STAGE 4b: the EVIDENCE CHECKER (our main selling point).

Takes a report and the ORIGINAL cleaned footage for that visit, and checks every claim:

  - each address, web link, file fingerprint, command, username/password pair must literally appear
  - each behavior must be supported by what the footage shows
  - web links, fingerprints, visitor codes and counts mentioned inside the summary must match too
  - the attack type must be one of the allowed types

Anything that fails is REMOVED from the final record. Nothing unverified gets through.
A report whose attack type disagrees with the sorter gets a soft WARNING (not a failed claim).
"""
import copy
import re

from reports import (ATTACK_TYPES, BEHAVIORS, HASH_RE, HOST_RE, IPV4, find_urls,
                     session_facts, supported_behaviors)

COUNT_RE = re.compile(r"(\d+)\s+(?:failed\s+)?(?:login|password)\s+(?:attempts|guesses|tries)", re.I)
WITHHELD = "[summary withheld: it contained claims that could not be verified]"


def verify(events, report, classifier_type=None):
    f = session_facts(events)
    ev = report.get("evidence", {})
    summary = report.get("summary", "")
    sup = supported_behaviors(f)
    pairs = set(f["logins"])
    cmd_set = {c.strip() for c in f["commands"]}
    claims = []

    def add(kind, value, ok, reason, in_summary=False):
        claims.append({"kind": kind, "value": value, "ok": bool(ok),
                       "reason": "" if ok else reason, "in_summary": in_summary})

    at = report.get("attack_type")
    add("attack_type", at, at in ATTACK_TYPES, "not one of the allowed attack types")

    for a in ev.get("addresses", []):
        add("address", a, a == f["address"], "not the visitor recorded in the footage")
    for u in ev.get("urls", []):
        add("url", u, u in f["urls"], "this web link never appears in the footage")
    for h in ev.get("file_hashes", []):
        add("file_hash", h, h in f["hashes"], "no file with this fingerprint was downloaded")
    for c in ev.get("commands", []):
        add("command", c, c.strip() in cmd_set, "this command was never typed")
    for cr in ev.get("credentials", []):
        user, _, pwd = cr.partition("/")
        add("credential", cr, (user, pwd) in pairs, "this username/password pair was never tried")
    for b in report.get("behaviors", []):
        if b not in BEHAVIORS:
            add("behavior", b, False, "not a recognised behavior name")
        else:
            add("behavior", b, b in sup, "the footage does not support this behavior")

    # things mentioned inside the free-text summary
    for u in find_urls(summary):
        add("url", u, u in f["urls"], "web link in the summary never appears in the footage", True)
    for h in HASH_RE.findall(summary):
        add("file_hash", h, h in f["hashes"], "fingerprint in the summary was never downloaded", True)
    for h in HOST_RE.findall(summary):
        add("address", h, h == f["address"], "visitor code in the summary is not this visitor", True)
    for raw in IPV4.findall(summary):
        add("address", raw, False, "raw address-shaped text in the summary (data must stay anonymised)", True)
    for n in COUNT_RE.findall(summary):
        add("count", n, int(n) == f["n_failed"],
            f"summary says {n} failed logins but the footage shows {f['n_failed']}", True)

    failed = [c for c in claims if not c["ok"]]
    warnings = []
    if classifier_type and at in ATTACK_TYPES and at != classifier_type:
        warnings.append(f"report says '{at}' but the sorter says '{classifier_type}'")

    # ---- clean the report: drop every failed claim
    clean = copy.deepcopy(report)
    bad = {(c["kind"], c["value"]) for c in failed}
    for key, kind in [("addresses", "address"), ("urls", "url"), ("file_hashes", "file_hash"),
                      ("commands", "command"), ("credentials", "credential")]:
        clean["evidence"][key] = [v for v in ev.get(key, []) if (kind, v) not in bad]
    clean["behaviors"] = [b for b in report.get("behaviors", []) if ("behavior", b) not in bad]
    if any(c["in_summary"] for c in failed):
        clean["summary"] = WITHHELD
    if at not in ATTACK_TYPES:
        clean["attack_type"] = classifier_type or "unknown"

    return {"claims": claims, "n_claims": len(claims), "n_failed": len(failed), "failed": failed,
            "approved": not failed, "warnings": warnings, "cleaned": clean}


def danger_level(behaviors):
    if {"tool_download", "run_downloaded_file"} & set(behaviors):
        return "red"
    if {"password_guessing", "system_discovery"} & set(behaviors):
        return "yellow"
    return "green"


def final_record(session_id, verdict, classifier_type=None):
    """The record that leaves the pipeline. Contains only verified claims."""
    c = verdict["cleaned"]
    return {
        "session": session_id,
        "visitor": c["evidence"]["addresses"][0] if c["evidence"]["addresses"] else None,
        "attack_type": c["attack_type"],
        "classifier_type": classifier_type,
        "types_agree": (classifier_type == c["attack_type"]) if classifier_type else None,
        "danger_level": danger_level(c["behaviors"]),
        "summary": c["summary"],
        "behaviors": [{"name": b, "framework_id": BEHAVIORS[b][0], "technique": BEHAVIORS[b][1]}
                      for b in c["behaviors"]],
        "evidence": c["evidence"],
        "verification": {"claims_checked": verdict["n_claims"], "claims_removed": verdict["n_failed"],
                         "approved_as_written": verdict["approved"], "warnings": verdict["warnings"]},
    }
