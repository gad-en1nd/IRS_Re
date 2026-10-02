import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import uuid
import native_boundary

ENDPOINT = "http://127.0.0.1:8317/v1/chat/completions"
MODEL = "gemini-3.8-flash-high"
TOOLS = [
    {"type": "function", "function": {"name": "read_file", "description": "Read file", "parameters": {"type": "object", "properties": {"filepath": {"type": "string", "enum": ["input.json", "result.json"]}}, "required": ["filepath"], "additionalProperties": False}, "strict": True}},
    {"type": "function", "function": {"name": "write_file", "description": "Write file", "parameters": {"type": "object", "properties": {"filepath": {"type": "string", "enum": ["result.json"]}, "content": {"type": "string"}}, "required": ["filepath", "content"], "additionalProperties": False}, "strict": True}},
    {"type": "function", "function": {"name": "run_check", "description": "Run check", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}, "strict": True}},
]

def verify_prereqs(proj: Path):
    iso = json.loads((proj / "acceptance" / "native-isolation.json").read_text(encoding="utf-8"))
    if iso.get("native_wrapper") != "WSL bubblewrap" or iso.get("status") != "PASS":
        raise ValueError("native-isolation status or wrapper mismatch")
    res = iso.get("results")
    req_keys = {
        "read_allowed",
        "write_allowed",
        "read_outside_denied",
        "write_outside_denied",
        "private_read_denied",
        "network_denied",
        "child_read_outside_denied",
        "child_write_outside_denied",
        "child_network_denied",
        "readonly_worker",
        "symlink",
        "tool_allowlist",
        "fixed_child_check",
        "integrity",
    }
    if not isinstance(res, dict) or set(res.keys()) != req_keys or not all(v == "PASS" for v in res.values()):
        raise ValueError("native-isolation 14 required results not PASS")
    rev = json.loads((proj / "acceptance" / "native-boundary-review.json").read_text(encoding="utf-8"))
    if rev.get("status") != "PASS" or rev.get("reviewer") != "ChatGPT":
        raise ValueError("native-boundary-review not PASS by ChatGPT")
    b_hash = hashlib.sha256((proj / "native_boundary.py").read_bytes()).hexdigest()
    p_hash = hashlib.sha256((proj / "acceptance" / "native-isolation.json").read_bytes()).hexdigest()
    if rev.get("native_boundary_sha256") != b_hash or rev.get("native_proof_sha256") != p_hash:
        raise ValueError("boundary or proof sha256 mismatch against review")

def validate_tool_args(name, args):
    if not isinstance(args, dict):
        raise ValueError(f"Malformed args: {type(args)}")
    if name == "read_file":
        if set(args.keys()) != {"filepath"} or args["filepath"] not in ("input.json", "result.json"):
            raise ValueError(f"Invalid read_file args: {args}")
    elif name == "write_file":
        if set(args.keys()) != {"filepath", "content"} or args["filepath"] != "result.json" or not isinstance(args["content"], str):
            raise ValueError(f"Invalid write_file args: {args}")
    elif name == "run_check":
        if args != {}:
            raise ValueError(f"Invalid run_check args: {args}")
    else:
        raise ValueError(f"Unsupported tool: {name}")

def check_run_check_result(res):
    if not isinstance(res, dict) or res.get("started") is not True or res.get("outcome") != "allowed":
        return False
    p_ns, c_ns = res.get("parent_netns"), res.get("child_netns")
    if not p_ns or p_ns != c_ns or res.get("child_started") is not True:
        return False
    cr = res.get("child_results")
    if not isinstance(cr, dict):
        return False
    return (
        cr.get("started") is True
        and cr.get("token_sum_valid") is True
        and cr.get("has_route") is False
        and cr.get("child_read_outside") == "denied_2"
        and cr.get("child_write_outside") == "denied_2"
        and cr.get("child_write_ro") == "denied_30"
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--probe-tools", action="store_true")
    cli = parser.parse_args()
    if not cli.probe_tools:
        raise ValueError("Requires --probe-tools")
    proj = Path(cli.project).resolve()
    if not proj.is_dir():
        raise ValueError(f"Invalid project directory: {proj}")
    verify_prereqs(proj)
    session = native_boundary.prepare_session(str(proj))
    base_dir = Path(session["base_dir"]).resolve()
    ro_in = base_dir / "readonly" / "input.json"
    ws_res = base_dir / "workspace" / "result.json"
    init_in_bytes = ro_in.read_bytes()
    init_in_sha = hashlib.sha256(init_in_bytes).hexdigest()
    exp_data = json.loads(init_in_bytes.decode("utf-8"))
    exp_tok = exp_data["token"]
    exp_sum = exp_data["a"] + exp_data["b"]
    prompt = "Read input.json using read_file. Compute the sum. Write result.json with token and sum using write_file. Run run_check. Conclude."
    messages = [{"role": "user", "content": prompt}]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    sid = str(uuid.uuid4())
    sdir = proj / ".local" / "gemini-tools" / sid
    sdir.mkdir(parents=True, exist_ok=True)
    trace, exec_calls, exec_names = [], {}, set()
    total_calls, pt_list, ct_list, ca_list, act_models = 0, [], [], [], []
    t0 = time.time()
    utc_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stopped_clean = False
    for round_idx in range(6):
        payload = {"model": MODEL, "messages": messages, "temperature": 0, "max_tokens": 2048, "tools": TOOLS, "tool_choice": "auto", "stream": False}
        (sdir / f"request_round_{round_idx}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        req = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(req, timeout=60) as resp:
                raw_resp = resp.read()
                (sdir / f"response_round_{round_idx}.bin").write_bytes(raw_resp)
                resp_data = json.loads(raw_resp.decode("utf-8"))
        except urllib.error.HTTPError as e:
            (sdir / f"http_error_round_{round_idx}.bin").write_bytes(e.read())
            raise RuntimeError(f"HTTPError {e.code}")
        round_log = {"round": round_idx, "payload": payload, "response": resp_data, "tool_results": []}
        (sdir / f"round_{round_idx}.json").write_text(json.dumps(round_log, indent=2), encoding="utf-8")
        choices = resp_data.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError(f"Expected exactly 1 choice, got: {choices}")
        act_models.append(resp_data.get("model", "unknown"))
        usage = resp_data.get("usage") if isinstance(resp_data.get("usage"), dict) else {}
        pt_list.append(usage.get("prompt_tokens"))
        ct_list.append(usage.get("completion_tokens"))
        pdet = usage.get("prompt_tokens_details")
        ca_val = pdet.get("cached_tokens") if isinstance(pdet, dict) and "cached_tokens" in pdet else usage.get("cached_tokens")
        ca_list.append(ca_val if isinstance(ca_val, int) else None)
        choice = choices[0]
        if choice.get("finish_reason") not in ("stop", "tool_calls"):
            raise ValueError(f"Invalid finish_reason: {choice.get('finish_reason')}")
        asst = choice.get("message")
        if not isinstance(asst, dict) or asst.get("role") != "assistant":
            raise ValueError(f"Invalid assistant message: {asst}")
        messages.append(asst)
        tcs = asst.get("tool_calls")
        if tcs is not None and not isinstance(tcs, list):
            raise ValueError("tool_calls is not a list")
        if not tcs:
            if choice.get("finish_reason") == "stop":
                stopped_clean = True
                trace.append(round_log)
                break
            raise ValueError(f"No tool calls with finish_reason: {choice.get('finish_reason')}")
        total_calls += len(tcs)
        if total_calls > 6:
            raise RuntimeError("Exceeded 6 total tool calls limit")
        for tc in tcs:
            if tc.get("type") != "function":
                raise ValueError(f"Invalid tool type: {tc.get('type')}")
            cid = tc.get("id")
            if not isinstance(cid, str) or not cid:
                raise ValueError(f"Invalid tool call id: {cid}")
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = fn.get("name")
            args_raw = fn.get("arguments")
            if not isinstance(args_raw, str):
                raise ValueError(f"Tool arguments not JSON str: {args_raw}")
            args = json.loads(args_raw)
            validate_tool_args(name, args)
            if cid in exec_calls:
                prev = exec_calls[cid]
                if prev["name"] != name or prev["args"] != args:
                    raise ValueError(f"Conflicting tool call execution for id {cid}")
                tres = prev["res"]
            else:
                tres = native_boundary.execute_tool(str(proj), str(base_dir), name, args, distro="Ubuntu")
                exec_calls[cid] = {"name": name, "args": args, "res": tres}
                exec_names.add(name)
            round_log["tool_results"].append({"id": cid, "name": name, "result": tres})
            (sdir / f"round_{round_idx}.json").write_text(json.dumps(round_log, indent=2), encoding="utf-8")
            content_str = json.dumps(tres) if not isinstance(tres, str) else tres
            messages.append({"role": "tool", "tool_call_id": cid, "content": content_str})
        trace.append(round_log)
    if not stopped_clean:
        raise RuntimeError("Loop completed without reaching stop without tool calls")
    elapsed = round(time.time() - t0, 4)
    num_rounds = len(trace)
    p_agg = sum(pt_list) if (len(pt_list) == num_rounds and all(isinstance(x, int) for x in pt_list)) else "unknown"
    c_agg = sum(ct_list) if (len(ct_list) == num_rounds and all(isinstance(x, int) for x in ct_list)) else "unknown"
    t_agg = (p_agg + c_agg) if isinstance(p_agg, int) and isinstance(c_agg, int) else "unknown"
    ca_agg = sum(ca_list) if (len(ca_list) == num_rounds and all(isinstance(x, int) for x in ca_list)) else "unknown"
    chk_ok = any(c["name"] == "run_check" and check_run_check_result(c["res"]) for c in exec_calls.values())
    tok_ok, sum_ok, res_sha = False, False, ""
    if ws_res.is_file():
        res_bytes = ws_res.read_bytes()
        res_sha = hashlib.sha256(res_bytes).hexdigest()
        rdata = json.loads(res_bytes.decode("utf-8"))
        tok_ok = (rdata.get("token") == exp_tok)
        sum_ok = (rdata.get("sum") == exp_sum)
    final_in_sha = hashlib.sha256(ro_in.read_bytes()).hexdigest()
    in_unchanged = (final_in_sha == init_in_sha)
    status_pass = (exec_names == {"read_file", "write_file", "run_check"}) and chk_ok and tok_ok and sum_ok and in_unchanged
    evidence = {
        "status": "PASS" if status_pass else "FAIL",
        "session_id": sid,
        "utc_timestamp": utc_start,
        "round_count": num_rounds,
        "distinct_tool_count": len(exec_names),
        "tool_names": sorted(list(exec_names)),
        "matched_ids": sorted(list(exec_calls.keys())),
        "requested_model": MODEL,
        "actual_models": act_models,
        "elapsed_seconds": elapsed,
        "usage": {"prompt_tokens": p_agg, "completion_tokens": c_agg, "total_tokens": t_agg, "cached_tokens": ca_agg},
        "content_hashes": {"input_sha256": init_in_sha, "result_sha256": res_sha},
        "checks": {"three_distinct_tools": exec_names == {"read_file", "write_file", "run_check"}, "child_checker": chk_ok, "token_verified": tok_ok, "sum_verified": sum_ok, "input_unchanged": in_unchanged},
    }
    probe_p = proj / "acceptance" / "gemini-tools-probe.json"
    probe_p.parent.mkdir(parents=True, exist_ok=True)
    probe_p.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    if not status_pass:
        sys.exit(1)

if __name__ == "__main__":
    main()
