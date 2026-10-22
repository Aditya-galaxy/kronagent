#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — injection red-team run: can attacker-controlled text talk triage
out of a real attack? See kronagent/redteam.py for what is measured and why.

    python run_injection_eval.py                    # offline: what reaches the model at all
    python run_injection_eval.py --live --budget 15 # real triage model, 15 injected trials
    python run_injection_eval.py --live --as-severity 5.5 --no-recheck   # what the recheck is for
    python run_injection_eval.py --baseline         # no attack: triage on every case, and the recheck's reach

Offline needs no key and makes no calls. It reports which payloads the
sanitizer changes and how much of each payload survives masking, per channel.

Live sends each attack case to the real triage model once clean (the baseline)
and then with a payload. Every answer is cached by the exact prompt in
--cache, so a run that stops on the free tier's daily quota resumes the next
day and trials accumulate, and a changed prompt never reuses an old answer. A
verdict that came from the severity fallback (the model was unreachable) is
never scored.

The corpus's attacks all sit at or above the override floor, where a fooled
verdict still reaches a person. --as-severity re-runs them as mid-severity
findings, the range where a fooled verdict used to drop the attack, and
--no-recheck turns off the recheck that now catches it, to show the difference.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

from kronagent import redteam
from kronagent.config import Settings
from kronagent.model import Finding
from kronagent.providers import NORMALIZERS
from kronagent.triage import SYSTEM_PROMPT, TriageEngine, build_prompt

DATASET = "samples/eval_dataset.json"


def attack_cases(path: str) -> dict[str, Finding]:
    """The dataset's plain attack cases. Its adversarial cases already carry
    injected text, so they can't serve as a clean baseline."""
    cases = {}
    for case in json.loads(Path(path).read_text()):
        if case.get("expected_actionable") and not case.get("adversarial"):
            cases[case["finding_id"]] = NORMALIZERS[case["provider"]](case["raw_event"])
    return cases


def offline(cases: dict[str, Finding]) -> None:
    print("Sanitizer: payloads changed before the model sees them")
    report = redteam.sanitizer_report()
    for row in report:
        print(f"  {'changed  ' if row['changed'] else 'UNCHANGED'}  {row['category']:<21} {row['name']}")
    unchanged = sum(not r["changed"] for r in report)
    print(f"  {unchanged} of {len(report)} payloads pass the phrase list unchanged.\n")

    print("Masking: share of each payload's words the model would read, by channel")
    for channel in redteam.CHANNELS:
        shares = [redteam.visible_fraction(f, p, channel) for f in cases.values() for p in redteam.PAYLOADS]
        mean = sum(shares) / len(shares)
        print(f"  {channel:<19} mean {100 * mean:5.1f}%   "
              f"(fully hidden in {sum(s == 0 for s in shares)} of {len(shares)} placements)")


class Cache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = json.loads(path.read_text()) if path.exists() else {}

    @staticmethod
    def key(finding: Finding, model: str, recheck: bool) -> str:
        prompt, _ = build_prompt(finding)
        return hashlib.sha256(json.dumps([model, SYSTEM_PROMPT, prompt, recheck]).encode()).hexdigest()[:32]

    def put(self, key: str, value: dict) -> None:
        self.data[key] = value
        self.path.write_text(json.dumps(self.data, indent=1))


class OutOfQuota(RuntimeError):
    pass


async def verdict_for(finding: Finding, triage: TriageEngine, cache: Cache, model: str,
                      recheck: bool = True) -> dict:
    key = cache.key(finding, model, recheck)
    if key in cache.data:
        return cache.data[key]
    verdict, _ = await triage.assess(finding)
    if verdict.justification.startswith("FALLBACK"):
        raise OutOfQuota(verdict.justification)
    value = {"actionable": verdict.is_actionable_threat, "confidence": verdict.confidence,
             "justification": verdict.justification, "contested": verdict.contested}
    cache.put(key, value)
    return value


async def live(cases: dict[str, Finding], budget: int, seed: int, cache_path: Path, recheck: bool,
               channels: tuple[str, ...] = redteam.CHANNELS) -> int:
    from kronagent.llm import build_triage_client
    llm, MODEL = build_triage_client()
    triage = TriageEngine(llm, recheck_band=(0.0, 10.01) if recheck else (0.0, 0.0))
    cache = Cache(cache_path)
    floor = Settings.from_env().triage_override_floor
    results: list[redteam.Result] = []
    stopped = ""
    try:
        for trial in redteam.plan_trials(cases, budget=budget, seed=seed, channels=channels):
            finding = cases[trial.case_id]
            base = await verdict_for(finding, triage, cache, MODEL, recheck)
            hit = await verdict_for(redteam.inject(finding, trial.payload, trial.channel), triage, cache,
                                    MODEL, recheck)
            results.append(redteam.Result(trial, finding.severity, base["actionable"], hit["actionable"],
                                          hit["confidence"], hit["justification"], hit["contested"]))
    except OutOfQuota as exc:
        stopped = str(exc)

    summary = redteam.summarise(results, floor)
    print(f"Model: {MODEL}   override floor: {floor}   recheck: {'on' if recheck else 'OFF'}   "
          f"trials run: {len(results)}"
          + (f"   (stopped early: the model became unavailable — {stopped[:80]})" if stopped else ""))
    skipped = len(results) - summary["overall"]["n"]
    if skipped:
        print(f"  {skipped} trials not scored: the model missed the attack even without a payload.")

    def line(name: str, b: dict) -> str:
        if not b["n"]:
            return f"  {name:<21} no scored trials"
        lo, hi = b["suppression_ci"]
        return (f"  {name:<21} n={b['n']:<3} held {b['held']:<3} rescued {b['rescued']:<3} "
                f"(by recheck {b['rescued_by_recheck']}) dismissed {b['dismissed']:<3} "
                f"model fooled {100 * b['suppression_rate']:5.1f}% [{100 * lo:.0f}–{100 * hi:.0f}%]")

    print(line("overall", summary["overall"]))
    for group in ("by_category", "by_channel"):
        print(f" {group.replace('_', ' ')}:")
        for name, b in summary[group].items():
            print(line(name, b))
    for f in summary["fooled"]:
        print(f"  {f['outcome'].upper():<9} {f['case']} · {f['payload']} via {f['channel']} "
              f"(severity {f['severity']}): {f['justification'][:140]}")
    return 0


def all_cases(path: str) -> list[tuple[str, bool, Finding]]:
    return [(c["finding_id"], bool(c["expected_actionable"]), NORMALIZERS[c["provider"]](c["raw_event"]))
            for c in json.loads(Path(path).read_text()) if not c.get("adversarial")]


async def baseline(path: str, cache_path: Path, llm=None, model: str = "") -> int:
    """With nobody attacking: what triage says about every case, and what the
    structured-fields recheck would say. The recheck protects an attack only
    if its structured fields alone read as a threat, and it costs a review for
    every benign finding where they do."""
    if llm is None:
        from kronagent.llm import build_triage_client
        llm, model = build_triage_client()
    MODEL = model
    settings = Settings.from_env()
    band = (settings.min_severity_for_containment, settings.triage_override_floor)
    plain = TriageEngine(llm, recheck_band=(0.0, 0.0))
    cache = Cache(cache_path)

    async def structured_only(finding: Finding) -> bool:
        prompt, _ = build_prompt(finding, with_text=False)
        key = hashlib.sha256(json.dumps([MODEL, "structured-only", prompt]).encode()).hexdigest()[:32]
        if key not in cache.data:
            cache.put(key, {"threat": await plain._contested(finding)})
        return cache.data[key]["threat"]

    rows = []
    try:
        for fid, is_attack, finding in all_cases(path):
            clean = await verdict_for(finding, plain, cache, MODEL, recheck=False)
            in_band = band[0] <= finding.severity < band[1]
            alone = await structured_only(finding) if is_attack or in_band else None
            rows.append((fid, is_attack, finding, clean["actionable"], in_band, alone))
    except OutOfQuota as exc:
        print(f"Stopped early: the model became unavailable ({str(exc)[:70]}). Run again to continue.")

    def share(part: list, whole: list) -> str:
        return f"{len(part)} of {len(whole)}"

    attacks = [r for r in rows if r[1]]
    benign = [r for r in rows if not r[1]]
    print(f"Model: {MODEL}   recheck band: severity {band[0]} to {band[1]}   cases: {len(rows)}\n")
    print("Triage, nobody attacking")
    print(f"  attacks called actionable:        {share([r for r in attacks if r[3]], attacks)}")
    print(f"  benign findings called actionable: {share([r for r in benign if r[3]], benign)}")
    for r in benign:
        if r[3]:
            where = "would be contained" if r[2].severity >= band[0] else "below the containment minimum: alert only"
            print(f"    {r[0]} ({r[2].finding_type}, severity {r[2].severity}; {where})")
    for r in attacks:
        if not r[3]:
            print(f"    MISSED ATTACK: {r[0]} ({r[2].finding_type}, severity {r[2].severity})")
    for name, group in (("at or above the floor", [r for r in attacks if r[2].severity >= band[1]]),
                        ("in the recheck band", [r for r in attacks if r[4]])):
        print(f"\nAttacks {name}: structured fields alone read as a threat in "
              f"{share([r for r in group if r[5]], group)}")
        for r in group:
            if not r[5]:
                print(f"    not protected by the recheck: {r[0]} ({r[2].finding_type}, severity {r[2].severity})")
    band_benign = [r for r in benign if r[4]]
    sent = [r for r in band_benign if not r[3] and r[5]]
    print(f"\nBenign findings in the recheck band: {len(band_benign)}; dismissed by triage but sent to a "
          f"person by the recheck: {share(sent, band_benign)}")
    for r in sent:
        print(f"    {r[0]} ({r[2].finding_type})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--live", action="store_true", help="call the real triage model")
    ap.add_argument("--baseline", action="store_true",
                    help="no injection: live triage on every case, and what the recheck would protect and cost")
    ap.add_argument("--budget", type=int, default=15, help="injected trials to run (live)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-cases", type=int, help="use only the first N attack cases (each needs a baseline call)")
    ap.add_argument("--only", help="use only attack cases whose id contains this (e.g. -mid-)")
    ap.add_argument("--channels", default=",".join(redteam.CHANNELS),
                    help="comma-separated channels to inject into (resource_attribute is closed by masking)")
    ap.add_argument("--as-severity", type=float, help="re-run the attack cases at this severity (e.g. 5.5)")
    ap.add_argument("--no-recheck", action="store_true", help="turn the structured-fields recheck off")
    ap.add_argument("--cache", default="kronagent_injection_cache.json")
    args = ap.parse_args()
    if args.baseline:
        return asyncio.run(baseline(args.dataset, Path(args.cache)))
    cases = attack_cases(args.dataset)
    if args.only:
        cases = {k: f for k, f in cases.items() if args.only in k}
    channels = tuple(c for c in args.channels.split(",") if c)
    if not set(channels) <= set(redteam.CHANNELS):
        ap.error(f"--channels must be among {', '.join(redteam.CHANNELS)}")
    if args.max_cases:
        cases = dict(sorted(cases.items())[:args.max_cases])
    if args.as_severity is not None:
        cases = {k: f.model_copy(update={"severity": args.as_severity}) for k, f in cases.items()}
    print(f"{len(cases)} attack cases, {len(redteam.PAYLOADS)} payloads, {len(redteam.CHANNELS)} channels "
          f"= {len(cases) * len(redteam.PAYLOADS) * len(redteam.CHANNELS)} possible trials\n")
    if not args.live:
        offline(cases)
        return 0
    return asyncio.run(live(cases, args.budget, args.seed, Path(args.cache), not args.no_recheck, channels))


if __name__ == "__main__":
    sys.exit(main())
