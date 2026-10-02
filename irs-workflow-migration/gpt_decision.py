"""C09 GPT Independent Cross-Review CLI Adapter.

Codex runs ephemerally in read-only sandbox, evaluating candidate packets
against strict project schema. Human approval remains false.
"""
import argparse, datetime, hashlib, json, os, re, shutil, subprocess, sys, time, uuid
from pathlib import Path

HEX40_RE = re.compile(r"^[a-f0-9]{40}$")
HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
REQ_RE = re.compile(r"^REQ-[A-Za-z0-9_.-]+$")

def _safe_resolve(proj: Path, rel: str) -> Path:
    if not isinstance(rel, str) or not rel or ":" in rel or "\\" in rel:
        raise ValueError(f"Invalid path characters in: {rel}")
    if rel.startswith("/"):
        raise ValueError(f"Absolute path: {rel}")
    if any(part in ("", ".", "..", ".local") for part in rel.split("/")):
        raise ValueError(f"Path traversal or restricted component: {rel}")
    target = (proj / rel).resolve()
    if not target.is_relative_to(proj.resolve()) or ".local" in target.parts:
        raise ValueError(f"Target outside project or restricted: {rel}")
    return target

def _find_schema(proj: Path) -> tuple[Path, dict]:
    c = proj / "decision-output.schema.json"
    if c.is_file():
        return c, json.loads(c.read_text(encoding="utf-8"))
    raise FileNotFoundError("decision-output.schema.json not found in project")

def _validate_packet_pre_cli(pkt: dict, proj: Path) -> tuple[list[str], dict, dict]:
    if pkt.get("scope") != "migration":
        raise ValueError("Packet scope must be 'migration'")
    if not REQ_RE.match(str(pkt.get("request_id", ""))):
        raise ValueError(f"Invalid request_id: {pkt.get('request_id')}")
    auth_ref = pkt.get("authorization_source_ref")
    if not isinstance(auth_ref, str) or not auth_ref.strip():
        raise ValueError("authorization_source_ref must be non-empty string")
    ev_refs = pkt.get("evidence_refs")
    if not isinstance(ev_refs, list) or not all(isinstance(x, str) and x for x in ev_refs):
        raise ValueError("evidence_refs must be list of strings")
    if len(ev_refs) != len(set(ev_refs)):
        raise ValueError("evidence_refs must be unique")
    cand = pkt.get("candidate")
    if not isinstance(cand, dict) or set(cand.keys()) != {"commit", "tree", "content_hash", "evidence_hash", "scope"}:
        raise ValueError("Candidate 5-tuple invalid or incomplete")
    if cand.get("scope") != "migration":
        raise ValueError("Candidate scope must be 'migration'")
    c_commit, c_tree = cand["commit"], cand["tree"]
    both_null = c_commit is None and c_tree is None
    both_hex = (
        isinstance(c_commit, str) and HEX40_RE.match(c_commit) is not None
        and isinstance(c_tree, str) and HEX40_RE.match(c_tree) is not None
    )
    if not (both_null or both_hex):
        raise ValueError("Candidate commit and tree must both be null or both 40-hex")
    for k in ("content_hash", "evidence_hash"):
        v = cand[k]
        if not isinstance(v, str) or not HASH_RE.match(v):
            raise ValueError(f"Candidate {k} invalid hash")
    ac = pkt.get("automated_checks")
    if not isinstance(ac, dict) or set(ac.keys()) != {"status", "proof_ref", "proof_hash"}:
        raise ValueError("automated_checks strictly requires keys: status, proof_ref, proof_hash")
    pref, phash = ac["proof_ref"], ac["proof_hash"]
    if not isinstance(pref, str) or not isinstance(phash, str) or not HASH_RE.match(phash):
        raise ValueError("automated_checks missing valid proof ref or hash")
    pbytes = _safe_resolve(proj, pref).read_bytes()
    if f"sha256:{hashlib.sha256(pbytes).hexdigest()}" != phash:
        raise ValueError("automated_checks proof hash mismatch")
    proof_obj = json.loads(pbytes.decode("utf-8"))
    if proof_obj.get("status") != "PASS" or ac.get("status") != "PASS":
        raise ValueError("automated_checks status not PASS")
    missing_ev, ev_map = [], {}
    for ref in ev_refs:
        efile = _safe_resolve(proj, ref)
        if not efile.is_file():
            missing_ev.append(ref)
        else:
            ev_map[ref] = f"sha256:{hashlib.sha256(efile.read_bytes()).hexdigest()}"
    if not missing_ev:
        can_bytes = json.dumps(ev_map, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        h = f"sha256:{hashlib.sha256(can_bytes).hexdigest()}"
        if h != cand["evidence_hash"]:
            raise ValueError(f"evidence_hash mismatch: expected {cand['evidence_hash']}, got {h}")
    return missing_ev, proof_obj, ev_map

def _verify_images(proj: Path, pkt: dict, img_paths: list[str]) -> tuple[list[tuple[str, Path, str]], list[str]]:
    verified, missing = [], []
    capture_proofs = pkt.get("capture_proofs")
    if capture_proofs is None:
        capture_proofs = {}
    elif not isinstance(capture_proofs, dict):
        raise ValueError("capture_proofs must be a dict")
    ev_refs = set(pkt.get("evidence_refs", []))
    for rel in img_paths:
        if rel not in ev_refs:
            raise ValueError(f"Image {rel} not in evidence_refs")
        p = _safe_resolve(proj, rel)
        if not p.is_file():
            missing.append(rel)
            continue
        data = p.read_bytes()
        if len(data) > 5 * 1024 * 1024:
            raise ValueError(f"Image {rel} exceeds 5MB limit")
        if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff") or (data.startswith(b"RIFF") and data[8:12] == b"WEBP")):
            raise ValueError(f"Invalid image magic bytes: {rel}")
        h = f"sha256:{hashlib.sha256(data).hexdigest()}"
        exp = capture_proofs.get(rel)
        if not exp or h != exp:
            raise ValueError(f"Packet capture proof missing or hash mismatch for {rel}")
        verified.append((rel, p, h))
    return verified, missing

def _validate_output(data: dict, schema: dict, pkt: dict, missing_ev: list, missing_imgs: list, verified_imgs: list) -> None:
    req_keys = set(schema.get("required", []))
    if set(data.keys()) != req_keys:
        raise ValueError(f"Output keys mismatch schema required: {set(data.keys())} != {req_keys}")
    cand_req = set(schema.get("properties", {}).get("candidate", {}).get("required", []))
    c_out = data.get("candidate")
    if not isinstance(c_out, dict) or set(c_out.keys()) != cand_req:
        raise ValueError("Candidate keys mismatch schema")
    if not REQ_RE.match(data["request_id"]) or data["request_id"] != pkt["request_id"]:
        raise ValueError("request_id mismatch or invalid pattern")
    o_commit, o_tree = c_out["commit"], c_out["tree"]
    both_null = o_commit is None and o_tree is None
    both_hex = (
        isinstance(o_commit, str) and HEX40_RE.match(o_commit) is not None
        and isinstance(o_tree, str) and HEX40_RE.match(o_tree) is not None
    )
    if not (both_null or both_hex):
        raise ValueError("Candidate commit and tree must both be null or both 40-hex")
    for k in ("content_hash", "evidence_hash"):
        v = c_out[k]
        if not isinstance(v, str) or not HASH_RE.match(v):
            raise ValueError(f"Invalid candidate {k}: {v}")
    if data["decision"] not in ("approve", "reject", "needs_evidence"):
        raise ValueError("Invalid decision enum")
    if data["review_kind"] not in ("technical", "agent_visual"):
        raise ValueError("Invalid review_kind enum")
    if data["scope"] != "migration" or c_out["scope"] != "migration" or data["scope"] != pkt["scope"]:
        raise ValueError("Scope must be 'migration'")
    if c_out != pkt["candidate"]:
        raise ValueError("Candidate 5-tuple mismatch with packet")
    if data["human_approval"] is not False:
        raise ValueError("human_approval must be false")
    if data["authorization_source_ref"] != pkt.get("authorization_source_ref"):
        raise ValueError("authorization_source_ref mismatch")
    if not isinstance(data.get("findings"), list) or not all(isinstance(x, str) for x in data["findings"]):
        raise ValueError("findings must be list of strings")
    if not isinstance(data.get("evidence_refs"), list) or not all(isinstance(x, str) for x in data["evidence_refs"]):
        raise ValueError("evidence_refs must be list of strings")
    if len(data["evidence_refs"]) != len(set(data["evidence_refs"])):
        raise ValueError("evidence_refs must be unique")
    pkt_refs = pkt.get("evidence_refs", [])
    if data["decision"] == "approve":
        if set(data["evidence_refs"]) != set(pkt_refs) or len(data["evidence_refs"]) != len(pkt_refs):
            raise ValueError("Approved decision requires evidence_refs to match exact set of packet refs")
        if data["findings"] or not data["evidence_refs"] or missing_ev:
            raise ValueError("Approved decision invalid: findings present or missing evidence")
        if data["review_kind"] == "agent_visual" and (not verified_imgs or missing_imgs):
            raise ValueError("agent_visual approval requires verified host capture images")
    else:
        if not set(data["evidence_refs"]).issubset(set(pkt_refs)):
            raise ValueError("evidence_refs contains refs not in packet")

def main() -> None:
    parser = argparse.ArgumentParser(description="C09 GPT review adapter")
    parser.add_argument("--project", required=True, help="Absolute project path")
    parser.add_argument("--packet", required=True, help="Relative public packet JSON")
    parser.add_argument("--image", action="append", default=[], help="Relative image paths")
    args = parser.parse_args()

    proj = Path(args.project).resolve()
    if not proj.is_dir():
        raise FileNotFoundError(f"Project directory not found: {proj}")
    codex_bin = shutil.which("codex.exe") or shutil.which("codex")
    if not codex_bin:
        raise FileNotFoundError("codex executable not found in PATH")

    schema_path, schema_obj = _find_schema(proj)
    pkt = json.loads(_safe_resolve(proj, args.packet).read_bytes().decode("utf-8"))
    missing_ev, proof_data, ev_map = _validate_packet_pre_cli(pkt, proj)
    verified_imgs, missing_imgs = _verify_images(proj, pkt, args.image)

    run_id = str(uuid.uuid4())
    run_dir = proj / ".local" / "gpt-review" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    out_last = run_dir / "response.json"
    empty_cwd = run_dir / "empty_cwd"
    empty_cwd.mkdir()
    shutil.copyfile(schema_path, run_dir / "decision-output.schema.json")

    bounded_pkt = {
        "request_id": pkt["request_id"], "scope": pkt["scope"], "candidate": pkt["candidate"],
        "authorization_source_ref": pkt.get("authorization_source_ref"),
        "evidence_refs": pkt.get("evidence_refs", []),
        "content_excerpt": pkt.get("content_excerpt", pkt.get("candidate_excerpt", "")),
        "facts_constraints": pkt.get("facts_constraints", []),
        "automated_checks": pkt["automated_checks"],
        "verified_automated_checks": proof_data,
        "verified_evidence_hashes": ev_map,
    }
    if missing_ev:
        bounded_pkt["missing_evidence"] = missing_ev
    if missing_imgs:
        bounded_pkt["missing_images"] = missing_imgs

    prompt_payload = {
        "role": "bounded_code_reviewer",
        "instructions": (
            "Perform independent schema-enforced verification of candidate patch. "
            "Output ONLY valid JSON adhering strictly to output schema. Tools and code generation prohibited. "
            "Never declare human approval. Do not pretend computed hash is code review; "
            "if required context or evidence is missing, decision must be needs_evidence."
        ),
        "packet": bounded_pkt,
        "verified_images": [h for _, _, h in verified_imgs],
    }
    prompt_text = json.dumps(prompt_payload, ensure_ascii=False)
    if len(prompt_text.encode("utf-8")) > 60_000:
        raise ValueError(f"Final prompt exceeds 60k limit: {len(prompt_text.encode('utf-8'))} bytes")
    (run_dir / "prompt.json").write_text(prompt_text, encoding="utf-8")

    cmd = [
        codex_bin, "exec", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check",
        "--json", "--output-schema", str(run_dir / "decision-output.schema.json"),
        "--output-last-message", str(out_last), "-C", str(empty_cwd),
    ]
    for _, ipath, _ in verified_imgs:
        cmd.extend(["--image", str(ipath)])
    cmd.append("-")

    t0, utc_start = time.time(), datetime.datetime.now(datetime.timezone.utc).isoformat()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    try:
        proc = subprocess.run(cmd, input=prompt_text, text=True, encoding="utf-8", capture_output=True, timeout=300, env=env, shell=False)
    except subprocess.TimeoutExpired as exc:
        if exc.stdout is not None:
            (run_dir / "stdout.log").write_bytes(exc.stdout if isinstance(exc.stdout, bytes) else exc.stdout.encode("utf-8"))
        if exc.stderr is not None:
            (run_dir / "stderr.log").write_bytes(exc.stderr if isinstance(exc.stderr, bytes) else exc.stderr.encode("utf-8"))
        raise
    duration = round(time.time() - t0, 3)
    (run_dir / "stdout.log").write_text(proc.stdout, encoding="utf-8")
    (run_dir / "stderr.log").write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0 or not out_last.is_file():
        raise RuntimeError(f"Codex CLI failed (rc={proc.returncode}) or response file missing")

    resp_data = json.loads(out_last.read_text(encoding="utf-8"))
    _validate_output(resp_data, schema_obj, pkt, missing_ev, missing_imgs, verified_imgs)

    usage = {"prompt_tokens": "unknown", "completion_tokens": "unknown", "cached_tokens": "unknown"}
    model_returned = "unknown"
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        if ev.get("type") == "turn.completed":
            u = ev.get("usage", {})
            usage = {"prompt_tokens": u.get("input_tokens", "unknown"), "completion_tokens": u.get("output_tokens", "unknown"), "cached_tokens": u.get("cached_input_tokens", "unknown")}
            model_returned = ev.get("model", model_returned)

    usage_rec = {"timestamp": utc_start, "run_id": run_id, "duration_sec": duration, "model": model_returned, "usage": usage, "request_id": pkt.get("request_id")}
    with open(proj / ".local" / "gpt-review" / "usage.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(usage_rec) + "\n")
    print(json.dumps({"status": "success", "candidate_decision_ref": f".local/gpt-review/{run_id}/response.json", "usage": usage}))

if __name__ == "__main__":
    main()
