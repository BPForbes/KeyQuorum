#!/usr/bin/env python3
"""Report CodeQL findings the way the review rules in AGENTS.md ask for them.

Reads one or more SARIF files written by `github/codeql-action/analyze` and
prints, for every finding, the same five parts a reviewer must give: the source
(the CodeQL query help and the CWE), a verbatim quote of what that source says,
the offending lines quoted from the code, the SOC 2 Trust Services Criterion it
affects with a one-sentence reason, and the fix. The same text goes to the job
summary.

Exit status: 1 when a finding in shipped code is high or critical (a
`security-severity` of 7.0 or more, or a security-tagged result at level
"error"); 0 otherwise. Findings in test code and lower severities are listed
but do not fail the check.

Usage: codeql_report.py [--repo-root DIR] FILE.sarif [FILE.sarif ...]
"""

import argparse
import json
import os
import re
import sys

# CWE number -> (SOC 2 criterion, why a finding of this class weakens it).
# Criteria are from the AICPA Trust Services Criteria (TSP section 100); the
# CWE numbers are from https://cwe.mitre.org/. A new mapping needs a one-line
# reason, as the review rules in AGENTS.md require for any SOC 2 claim.
# Grouped by the control the weakness undermines. A security finding whose CWE
# is not listed falls back to CC7.1 so it is still triaged against a criterion.
GROUPS = [
    (
        "CC6.1 Logical access",
        "lets someone act without the authentication or authorization check that should have stopped them",
        {284, 285, 287, 306, 307, 346, 352, 639, 862, 863, 942, 1275, 384, 613},
    ),
    (
        "CC6.6 System boundaries / PI1.2 Processing inputs",
        "lets unvalidated outside input change how the system behaves or what it stores",
        {20, 22, 23, 36, 73, 74, 77, 78, 79, 80, 88, 89, 90, 94, 95, 116, 502, 601,
         611, 915, 918, 943, 1321, 1333},
    ),
    (
        "CC6.7 Transmission and removal of information",
        "weakens the protection of data in transit or at rest, or sends it where it should not go",
        {295, 297, 310, 311, 319, 326, 327, 328, 329, 330, 338, 347, 757, 759, 760, 916, 1204},
    ),
    (
        "C1.1 Confidential information",
        "exposes or hardcodes confidential information such as a key, token or personal data",
        {200, 201, 209, 259, 312, 313, 315, 321, 359, 497, 522, 523, 532, 798},
    ),
    (
        "CC7.2 Monitoring",
        "lets security-relevant events be forged, lost or recorded with secrets",
        {117, 778},
    ),
    (
        "A1.2 Availability",
        "lets a single request exhaust time, memory or storage and deny service",
        {400, 674, 730, 770, 776, 834, 835, 606, 405},
    ),
    (
        "PI1.2 Processing integrity",
        "lets data be processed incompletely or corrupted (memory, arithmetic or race errors)",
        {119, 120, 125, 190, 191, 362, 367, 369, 415, 416, 476, 787, 789},
    ),
    (
        "CC6.8 Unauthorized or malicious software / CC8.1 Change management",
        "lets untrusted input or an unreviewed component run in the build or delivery pipeline",
        {250, 276, 377, 379, 426, 427, 494, 732, 829, 1104, 1357},
    ),
]
CWE_TO_GROUP = {cwe: g for g in GROUPS for cwe in g[2]}
FALLBACK = (
    "CC7.1 Vulnerability detection",
    "is a vulnerability class this report has not mapped to a more specific control; triage it against the criterion that fits",
)
ACTIONS_FALLBACK = (
    "CC8.1 Change management / CC6.8 Unauthorized or malicious software",
    "weakens the controls that decide what code and automation may change or run",
)
TEST_PATH = re.compile(r"(^|/)(tests?\.rs|tests?/|__tests__/|.*\.(test|spec)\.[jt]sx?$)")


def cwes(tags):
    return sorted(int(m.group(1)) for t in tags for m in [re.search(r"cwe-0*(\d+)$", t)] if m)


def criterion(rule_id, tags, is_security):
    """(criterion, reason), or None when no SOC 2 criterion applies."""
    if not is_security:
        return None
    # A workflow finding is about the delivery pipeline whatever its CWE says.
    if rule_id.startswith("actions/"):
        return ACTIONS_FALLBACK
    for n in cwes(tags):
        if n in CWE_TO_GROUP:
            g = CWE_TO_GROUP[n]
            return g[0], g[1]
    return FALLBACK


def severity(rule, result):
    props = rule.get("properties", {})
    raw = props.get("security-severity")
    try:
        score = float(raw) if raw is not None else None
    except ValueError:
        score = None
    tags = props.get("tags", [])
    is_security = "security" in tags or score is not None
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
    if score is not None:
        name = "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"
    elif is_security and level == "error":
        name, score = "high", 7.0
    else:
        name = {"error": "major", "warning": "minor", "note": "minor"}.get(level, "minor")
    return name, score, is_security


def quote_lines(root, uri, region, snippet):
    start = region.get("startLine")
    end = region.get("endLine", start)
    if snippet:
        return start, end, snippet.rstrip("\n")
    path = os.path.join(root, uri)
    if start and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        return start, end, "\n".join(lines[start - 1:end])
    return start, end, "(source lines not available in the report)"


def first_sentence(text, limit=1200):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit] + (" ..." if len(text) > limit else "")


def recommendation(rule):
    text = rule.get("help", {}).get("text", "") or ""
    m = re.search(r"## Recommendation\s*(.+?)(\n## |\Z)", text, re.S)
    return first_sentence(m.group(1)) if m else "Follow the recommendation in the query help linked above."


def all_rules(run):
    """Every rule in the run, by id.

    CodeQL writes the rules of its query packs under `tool.extensions`, not
    `tool.driver.rules`, so both are read. Without that, a result has no
    severity, no security tag and no help text, and nothing would ever fail.
    """
    tool = run.get("tool", {})
    rules = {}
    for component in [tool.get("driver", {})] + tool.get("extensions", []):
        for r in component.get("rules", []) or []:
            rules.setdefault(r["id"], r)
    return rules


def findings(path):
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)
    for run in sarif.get("runs", []):
        rules = all_rules(run)
        for res in run.get("results", []):
            if res.get("suppressions"):
                continue
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id", "?")
            yield rules.get(rule_id, {"id": rule_id}), res


def render(root, rule, res):
    rule_id = rule.get("id", "?")
    props = rule.get("properties", {})
    tags = props.get("tags", [])
    sev, score, is_security = severity(rule, res)
    loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
    uri = loc.get("artifactLocation", {}).get("uri", "?")
    region = loc.get("region", {})
    start, end, code = quote_lines(root, uri, region, (loc.get("contextRegion") or region).get("snippet", {}).get("text"))
    mapped = criterion(rule_id, tags, is_security)
    soc2 = (f"SOC 2: {mapped[0]} -- this finding {mapped[1]}." if mapped
            else "SOC 2: none (correctness)")
    cwe_links = [f"https://cwe.mitre.org/data/definitions/{n}.html" for n in cwes(tags)]
    source = rule.get("helpUri") or f"CodeQL query {rule_id}"
    if cwe_links:
        source += " ; " + " ; ".join(cwe_links)
    quote = first_sentence(rule.get("fullDescription", {}).get("text") or rule.get("shortDescription", {}).get("text"))
    where = f"{uri}:{start}" + (f"-{end}" if end and end != start else "")
    score_txt = f" (security-severity {score})" if score is not None else ""
    return sev, uri, "\n".join([
        f"**{sev}: {res.get('message', {}).get('text', rule_id)}**",
        f"Source: CodeQL `{rule_id}` {source}",
        f"Source quote: > {quote} (CodeQL query help, bundled with the analysis run){score_txt}",
        f"Quote (`{where}`):",
        "```",
        code,
        "```",
        soc2,
        f"Fix: {recommendation(rule)}",
        "",
    ])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("sarif", nargs="+")
    args = ap.parse_args()

    failing, listed, out, gates = 0, 0, [], []
    for path in args.sarif:
        for rule, res in findings(path):
            sev, uri, text = render(args.repo_root, rule, res)
            is_security = severity(rule, res)[2]
            in_tests = bool(TEST_PATH.search(uri))
            gate = sev in ("high", "critical") and is_security and not in_tests
            failing += gate
            listed += 1
            if gate:
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                line = loc.get("region", {}).get("startLine", "?")
                gates.append(f"- {rule.get('id', '?')} at {uri}:{line}")
            entry = ("GATE " if gate else "") + text + ("(in test code, does not fail the check)\n" if in_tests else "")
            # Findings that fail the check come first, so they are never lost
            # in a long list of lower-severity or test-code findings.
            (out.insert(0, entry) if gate else out.append(entry))

    header = f"CodeQL: {listed} finding(s), {failing} failing the check (high or critical, shipped code)."
    if gates:
        header += "\nFailing the check:\n" + "\n".join(gates)
    body = header + "\n\n" + "\n".join(out)
    print(body)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### CodeQL findings (SOC 2 mapped)\n\n" + body + "\n")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
