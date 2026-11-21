#!/usr/bin/env python3
"""
STAGE 4c: run the whole report pipeline and print the SCOREBOARD.

For a sample of visits:  writer -> report -> evidence checker -> final record.

Writers:
  faithful   template writer (never invents anything)            -> proves the checker raises no false alarms
  mistakes   faithful + one planted mistake in about half        -> measures how many mistakes the checker catches
  ollama     language model on your laptop                       -> the real thing (needs Ollama running)
  groq       language model on Groq's free cloud tier            -> the real thing, cleaned data only

Usage:
  python3 run_reports.py --data data --writer mistakes --n 400
  python3 run_reports.py --data data --writer ollama --model llama3.2:3b --n 40
"""
import argparse
import json
import os
import random
from collections import Counter, defaultdict

from checker import final_record, verify
from reports import (FaithfulWriter, GroqWriter, MistakeWriter, OllamaWriter, session_facts)
from features import load_sessions


def pct(a, b):
    return round(a / b, 4) if b else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--writer", choices=["faithful", "mistakes", "ollama", "groq"], default="mistakes")
    ap.add_argument("--model", default=None)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--error-rate", type=float, default=0.5)
    a = ap.parse_args()

    sessions = load_sessions(os.path.join(a.data, "sessions_anon.jsonl"))
    labels = {l["session"]: l for l in json.load(open(os.path.join(a.data, "labels_anon.json")))}
    pred_path = os.path.join(a.data, "predictions.json")
    preds = {p["session"]: p["predicted"] for p in json.load(open(pred_path))} if os.path.exists(pred_path) else {}

    ids = sorted(sessions)
    sample = random.Random(a.seed).sample(ids, min(a.n, len(ids)))

    # pools of REAL links/fingerprints from other visits (for plausible-looking wrong claims)
    pool_u, pool_h = set(), set()
    for s in ids:
        f = session_facts(sessions[s])
        pool_u.update(f["urls"])
        pool_h.update(f["hashes"])

    if a.writer == "faithful":
        writer = FaithfulWriter()
    elif a.writer == "mistakes":
        writer = MistakeWriter(a.error_rate, a.seed, sorted(pool_u), sorted(pool_h))
    elif a.writer == "ollama":
        writer = OllamaWriter(a.model or "llama3.2:3b")
    else:
        writer = GroqWriter(a.model or "openai/gpt-oss-120b")

    rows, records = [], []
    for i, sid in enumerate(sample, 1):
        events = sessions[sid]
        report, meta = writer.write(events)
        verdict = verify(events, report, preds.get(sid))
        rec = final_record(sid, verdict, preds.get(sid))
        # safety net: the FINAL record must itself pass the checker with zero failures
        recheck = verify(events, verdict["cleaned"], preds.get(sid))
        rows.append({"session": sid, "report": report, "injected": meta.get("injected", []),
                     "approved": verdict["approved"], "failed": verdict["failed"],
                     "warnings": verdict["warnings"], "slipped_through": recheck["n_failed"]})
        records.append(rec)
        if a.writer in ("ollama", "groq") and i % 10 == 0:
            print(f"  ...{i}/{len(sample)} reports written")

    n = len(rows)
    M = {"writer": a.writer, "model": getattr(writer, "model", None), "reports": n}

    # ---- 1. headline numbers: how often was a report wrong, and did anything unverified get out?
    flagged = [r for r in rows if not r["approved"]]
    M["reports_with_unverifiable_claims"] = len(flagged)
    M["rate_reports_with_unverifiable_claims"] = pct(len(flagged), n)
    M["claims_checked_total"] = sum(len(r["report"]["evidence"]["urls"]) + len(r["report"]["evidence"]["file_hashes"])
                                    + len(r["report"]["evidence"]["commands"]) + len(r["report"]["evidence"]["credentials"])
                                    + len(r["report"]["evidence"]["addresses"]) + len(r["report"]["behaviors"]) + 1
                                    for r in rows)
    M["claims_removed_total"] = sum(len(r["failed"]) for r in rows)
    M["unverified_claims_in_final_records"] = sum(r["slipped_through"] for r in rows)

    # ---- 2. catch rate (only meaningful when we know which mistakes were planted)
    if a.writer == "mistakes":
        inj = [r for r in rows if r["injected"]]
        clean = [r for r in rows if not r["injected"]]
        by_kind = defaultdict(lambda: [0, 0, 0])  # planted, caught by hard check, caught incl. warning
        for r in inj:
            k = r["injected"][0]
            by_kind[k][0] += 1
            by_kind[k][1] += (not r["approved"])
            by_kind[k][2] += (not r["approved"]) or bool(r["warnings"])
        M["mistakes_planted"] = len(inj)
        M["caught_by_evidence_check"] = sum(v[1] for v in by_kind.values())
        M["caught_incl_sorter_disagreement_warning"] = sum(v[2] for v in by_kind.values())
        M["catch_rate_evidence_check"] = pct(M["caught_by_evidence_check"], len(inj))
        M["catch_rate_incl_warning"] = pct(M["caught_incl_sorter_disagreement_warning"], len(inj))
        M["false_alarms_on_untouched_reports"] = sum(1 for r in clean if not r["approved"])
        M["untouched_reports"] = len(clean)
        M["by_mistake_kind"] = {k: {"planted": v[0], "caught_by_check": v[1], "caught_incl_warning": v[2]}
                                for k, v in sorted(by_kind.items())}

    # ---- 3. quality of the final records against the answer key (works for any writer)
    type_ok = beh_tp = beh_fp = beh_fn = ev_tp = ev_fn = 0
    agree = 0
    for r, rec in zip(rows, records):
        lab = labels[r["session"]]
        type_ok += rec["attack_type"] == lab["label"]
        truth_b = set(lab["behaviors"])
        got_b = {b["name"] for b in rec["behaviors"]}
        beh_tp += len(truth_b & got_b)
        beh_fp += len(got_b - truth_b)
        beh_fn += len(truth_b - got_b)
        truth_e = set(lab["evidence"]["urls"]) | set(lab["evidence"]["hashes"])
        got_e = set(rec["evidence"]["urls"]) | set(rec["evidence"]["file_hashes"])
        ev_tp += len(truth_e & got_e)
        ev_fn += len(truth_e - got_e)
        agree += bool(rec["types_agree"])
    M["quality_vs_answer_key"] = {
        "attack_type_accuracy": pct(type_ok, n),
        "behavior_precision": pct(beh_tp, beh_tp + beh_fp),
        "behavior_recall": pct(beh_tp, beh_tp + beh_fn),
        "evidence_recall_links_and_fingerprints": pct(ev_tp, ev_tp + ev_fn),
        "report_type_agrees_with_sorter": pct(agree, n) if preds else None,
    }
    M["danger_levels"] = dict(Counter(rec["danger_level"] for rec in records))

    # ---- save
    tag = a.writer
    with open(os.path.join(a.data, f"reports_{tag}.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(a.data, f"intel_records_{tag}.jsonl"), "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    json.dump(M, open(os.path.join(a.data, f"report_metrics_{tag}.json"), "w"), indent=1)

    # ---- print scoreboard
    print(f"\nSCOREBOARD  writer={a.writer} model={M['model']}  reports={n}")
    print(f"  reports containing at least one unverifiable claim : {len(flagged)} ({M['rate_reports_with_unverifiable_claims']:.1%})")
    print(f"  claims removed by the checker                      : {M['claims_removed_total']}")
    print(f"  unverified claims that reached final records       : {M['unverified_claims_in_final_records']}")
    if a.writer == "mistakes":
        print(f"  planted mistakes                                   : {M['mistakes_planted']}")
        print(f"  caught by the evidence check                       : {M['caught_by_evidence_check']} ({M['catch_rate_evidence_check']:.1%})")
        print(f"  caught incl. sorter-disagreement warning           : {M['caught_incl_sorter_disagreement_warning']} ({M['catch_rate_incl_warning']:.1%})")
        print(f"  false alarms on untouched reports                  : {M['false_alarms_on_untouched_reports']} of {M['untouched_reports']}")
        print("  by kind of mistake:")
        for k, v in M["by_mistake_kind"].items():
            print(f"    {k:20s} planted {v['planted']:3d}   caught by check {v['caught_by_check']:3d}   incl. warning {v['caught_incl_warning']:3d}")
    q = M["quality_vs_answer_key"]
    print("  quality of final records vs the answer key:")
    for k, v in q.items():
        print(f"    {k:42s} {v}")
    print(f"  danger levels: {M['danger_levels']}")


if __name__ == "__main__":
    main()
