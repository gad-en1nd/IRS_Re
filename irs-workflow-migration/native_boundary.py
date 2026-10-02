import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import time
import uuid

MAX_WRITE = 1048576
TIMEOUT = 60
ALLOWED_TOOLS = ("read_file", "write_file", "run_check")
EXPECTED_DENIAL_ERRNOS = (2, 13, 30)


def file_sha256(path):
    p = pathlib.Path(path)
    if not p.is_file():
        raise RuntimeError(f"Missing file for hash: {path}")
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def run_cmd(cmd, input_data=None, env=None):
    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        sub_env.update(env)
    proc = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=TIMEOUT,
        env=sub_env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed (rc={proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def get_wsl_path(distro, win_path):
    p = pathlib.PureWindowsPath(win_path).as_posix()
    return run_cmd(["wsl.exe", "-d", distro, "--exec", "wslpath", "-u", p]).strip()


def get_host_wsl_netns(distro):
    out = run_cmd(
        [
            "wsl.exe",
            "-d",
            distro,
            "--exec",
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            "import os; print(os.readlink('/proc/self/ns/net'))",
        ]
    )
    return out.strip()


def prepare_session(project_dir, distro="Ubuntu"):
    p = pathlib.Path(project_dir).resolve()
    sid = str(uuid.uuid4())
    s_dir = p / ".local" / "native" / sid
    ro_dir = s_dir / "readonly"
    ws_dir = s_dir / "workspace"
    outside_dir = p / ".local" / "outside_data" / str(uuid.uuid4())
    ro_dir.mkdir(parents=True, exist_ok=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    outside_dir.mkdir(parents=True, exist_ok=True)

    (ro_dir / "native_boundary.py").write_text(
        pathlib.Path(__file__).read_text(encoding="utf-8"), encoding="utf-8"
    )
    tok = secrets.token_hex(16)
    num1 = secrets.randbelow(400) + 10
    num2 = secrets.randbelow(400) + 10

    sentinel = outside_dir / f"sentinel_{uuid.uuid4().hex}.txt"
    private_sentinel = outside_dir / f"priv_{uuid.uuid4().hex}.txt"
    if sentinel.exists() or private_sentinel.exists():
        raise RuntimeError("Sentinel destination collision detected")
    sentinel.write_text(f"{tok}:{num1}:{num2}", encoding="utf-8")
    private_sentinel.write_text(f"PRIV:{tok}:{secrets.randbelow(99999)}", encoding="utf-8")

    base_lx = get_wsl_path(distro, str(s_dir))
    outside_lx = get_wsl_path(distro, str(outside_dir))
    lx_paths = {
        "readonly": f"{base_lx}/readonly",
        "workspace": f"{base_lx}/workspace",
        "outside_sentinel": f"{outside_lx}/{sentinel.name}",
        "private_sentinel": f"{outside_lx}/{private_sentinel.name}",
    }

    (ro_dir / "input.json").write_text(
        json.dumps({"token": tok, "a": num1, "b": num2}), encoding="utf-8"
    )
    (ro_dir / "config.json").write_text(
        json.dumps(
            {
                "expected_token": tok,
                "expected_sum": num1 + num2,
                "outside_path": lx_paths["outside_sentinel"],
                "private_path": lx_paths["private_sentinel"],
            }
        ),
        encoding="utf-8",
    )
    return {
        "base_dir": str(s_dir),
        "lx_paths": lx_paths,
        "sentinel": sentinel,
        "private_sentinel": private_sentinel,
    }


def run_bwrap(distro, lx_ro, lx_ws, args, input_json=None):
    cmd = [
        "wsl.exe",
        "-d",
        distro,
        "--exec",
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "PYTHONIOENCODING",
        "utf-8",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        lx_ro,
        "/app",
        "--bind",
        lx_ws,
        "/work",
        "--chdir",
        "/work",
        "/usr/bin/python3",
        "-I",
        "-B",
        "/app/native_boundary.py",
    ] + args
    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"
    data = json.dumps(input_json) if input_json is not None else None
    proc = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=TIMEOUT,
        env=sub_env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def validate_tool_schema(call_name, args):
    if call_name not in ALLOWED_TOOLS:
        raise ValueError(f"Host rejected unknown tool call: {call_name}")
    if not isinstance(args, dict):
        raise ValueError("Tool args must be a dictionary")
    if call_name == "read_file":
        if set(args.keys()) != {"filepath"}:
            raise ValueError("read_file requires exactly {'filepath'}")
        if args["filepath"] not in ("input.json", "result.json"):
            raise ValueError(f"Host rejected noncanonical read filepath: {args.get('filepath')}")
    elif call_name == "write_file":
        if set(args.keys()) != {"filepath", "content"}:
            raise ValueError("write_file requires exactly {'filepath', 'content'}")
        if args["filepath"] != "result.json":
            raise ValueError(f"Host rejected noncanonical write filepath: {args.get('filepath')}")
        if not isinstance(args["content"], str):
            raise ValueError("Content must be string")
        if len(args["content"].encode("utf-8")) > MAX_WRITE:
            raise ValueError("Payload exceeds maximum allowed bytes")
    elif call_name == "run_check":
        if len(args) != 0:
            raise ValueError("run_check accepts exactly 0 arguments")


def execute_tool(project, session_folder, call_name, args, distro="Ubuntu"):
    validate_tool_schema(call_name, args)
    s_path = pathlib.Path(session_folder).resolve()
    base_lx = get_wsl_path(distro, str(s_path))
    lx_ro = f"{base_lx}/readonly"
    lx_ws = f"{base_lx}/workspace"
    code, out, err = run_bwrap(distro, lx_ro, lx_ws, ["tool"], {"call": call_name, "args": args})
    log_dir = s_path / ".session" / "logs" / uuid.uuid4().hex
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "exec_record.json").write_text(
        json.dumps({"call": call_name, "code": code, "stdout": out, "stderr": err}),
        encoding="utf-8",
    )
    if code != 0 or not out.strip():
        raise RuntimeError(f"Native worker failed (rc={code}): {err.strip()}")
    resp = json.loads(out.strip())
    if not resp.get("started"):
        raise RuntimeError(f"Worker refused startup: {resp.get('error')}")
    return resp


def worker_run_tool(req):
    call = req.get("call")
    args = req.get("args", {})
    validate_tool_schema(call, args)
    if call == "read_file":
        fname = args["filepath"]
        if fname == "input.json":
            target = pathlib.Path("/app/input.json")
        elif fname == "result.json":
            target = pathlib.Path("/work/result.json")
        else:
            return {"started": True, "outcome": "denied", "errno": 2}
        if not target.is_file():
            return {"started": True, "outcome": "denied", "errno": 2}
        return {"started": True, "outcome": "allowed", "content": target.read_text(encoding="utf-8")}
    if call == "write_file":
        if args["filepath"] != "result.json":
            return {"started": True, "outcome": "denied", "errno": 13}
        target = pathlib.Path("/work/result.json")
        target.write_text(args["content"], encoding="utf-8")
        return {"started": True, "outcome": "allowed"}
    if call == "run_check":
        p_netns = os.readlink("/proc/self/ns/net")
        sub_env = os.environ.copy()
        sub_env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", "/app/native_boundary.py", "checker"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=TIMEOUT,
            env=sub_env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Native checker failed (rc={proc.returncode}): {proc.stderr.strip()}")
        c_info = json.loads(proc.stdout.strip())
        if not c_info.get("started"):
            raise RuntimeError("Native checker child failed to start")
        return {
            "started": True,
            "outcome": "allowed",
            "parent_netns": p_netns,
            "child_netns": c_info.get("child_netns"),
            "child_started": c_info.get("started", False),
            "child_results": c_info,
        }
    raise ValueError("Unhandled tool")


def probe_path_rw(p_str):
    p = pathlib.Path(p_str)
    r_res, w_res = None, None
    try:
        p.read_text(encoding="utf-8")
        r_res = "allowed"
    except OSError as e:
        r_res = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"
    try:
        p.write_text("probe_payload", encoding="utf-8")
        w_res = "allowed"
    except OSError as e:
        w_res = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"
    return r_res, w_res


def worker_mode(target_outside, target_priv):
    res = {"started": True, "results": {}}
    r = res["results"]
    r["netns"] = os.readlink("/proc/self/ns/net")
    routes = pathlib.Path("/proc/net/route").read_text(encoding="utf-8")
    lines = [ln.strip() for ln in routes.splitlines() if ln.strip()]
    r["has_route"] = len(lines) > 1
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("127.0.0.1", 8317))
        r["connect_external"] = True
    except (OSError, socket.timeout):
        r["connect_external"] = False

    r["read_outside"], r["write_outside"] = probe_path_rw(target_outside)
    r["read_private"], r["write_private"] = probe_path_rw(target_priv)

    ro_files = ["/app/native_boundary.py", "/app/input.json", "/app/config.json"]
    for rf in ro_files:
        k = f"write_{pathlib.Path(rf).name}"
        try:
            pathlib.Path(rf).write_text("leak", encoding="utf-8")
            r[k] = "allowed"
        except OSError as e:
            r[k] = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"

    esc = pathlib.Path(f"/work/escape-{uuid.uuid4().hex}")
    os.symlink(target_outside, str(esc))
    try:
        esc.read_text(encoding="utf-8")
        r["symlink_read"] = "allowed"
    except OSError as e:
        r["symlink_read"] = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"
    try:
        esc.write_text("symlink_payload", encoding="utf-8")
        r["symlink_write"] = "allowed"
    except OSError as e:
        r["symlink_write"] = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"
    print(json.dumps(res))


def checker_mode():
    cfg = json.loads(pathlib.Path("/app/config.json").read_text(encoding="utf-8"))
    res_data = json.loads(pathlib.Path("/work/result.json").read_text(encoding="utf-8"))
    valid = res_data.get("token") == cfg.get("expected_token") and res_data.get("sum") == cfg.get("expected_sum")
    routes = pathlib.Path("/proc/net/route").read_text(encoding="utf-8")
    has_route = len([ln.strip() for ln in routes.splitlines() if ln.strip()]) > 1
    r_out, w_out = probe_path_rw(cfg["outside_path"])
    r_priv, w_priv = probe_path_rw(cfg["private_path"])
    try:
        pathlib.Path("/app/config.json").write_text("tamper", encoding="utf-8")
        w_ro = "allowed"
    except OSError as e:
        w_ro = f"denied_{e.errno}" if e.errno in EXPECTED_DENIAL_ERRNOS else "BLOCKED"
    out = {
        "started": True,
        "child_netns": os.readlink("/proc/self/ns/net"),
        "token_sum_valid": valid,
        "has_route": has_route,
        "child_read_outside": r_out,
        "child_write_outside": w_out,
        "child_read_priv": r_priv,
        "child_write_priv": w_priv,
        "child_write_ro": w_ro,
    }
    print(json.dumps(out))


def run_probe(project_dir, distro="Ubuntu"):
    t0 = time.time()
    sess = prepare_session(project_dir, distro)
    s_dir = sess["base_dir"]
    sentinel = sess["sentinel"]
    priv_sentinel = sess["private_sentinel"]
    lx_paths = sess["lx_paths"]

    pre_hashes = {
        "app": file_sha256(pathlib.Path(s_dir) / "readonly" / "native_boundary.py"),
        "config": file_sha256(pathlib.Path(s_dir) / "readonly" / "config.json"),
        "input": file_sha256(pathlib.Path(s_dir) / "readonly" / "input.json"),
        "sentinel": file_sha256(sentinel),
        "priv": file_sha256(priv_sentinel),
    }
    host_netns = get_host_wsl_netns(distro)

    # Allowlist host rejection tests
    host_rejections_pass = True
    bad_tool_tests = [
        ("delete", {}),
        ("arbitrary_shell", {"cmd": "ls"}),
        ("unknown_probe", {}),
        ("read_file", {}),
        ("read_file", {"filepath": "input.json", "extra": 1}),
        ("read_file", {"filepath": "../input.json"}),
        ("read_file", {"filepath": "/app/input.json"}),
        ("read_file", {"filepath": "config.json"}),
        ("read_file", {"filepath": "native_boundary.py"}),
        ("read_file", {"filepath": "input.json:stream"}),
        ("write_file", {}),
        ("write_file", {"filepath": "out.txt"}),
        ("write_file", {"filepath": "out.txt", "content": "data"}),
        ("write_file", {"filepath": "../result.json", "content": "{}"}),
        ("write_file", {"filepath": "/work/result.json", "content": "{}"}),
        ("write_file", {"filepath": "result.json:stream", "content": "{}"}),
        ("write_file", {"filepath": "config.json", "content": "{}"}),
        ("run_check", {"unexpected": True}),
    ]
    for bad_call, bad_args in bad_tool_tests:
        try:
            execute_tool(project_dir, s_dir, bad_call, bad_args, distro)
            host_rejections_pass = False
        except ValueError:
            pass

    r1 = execute_tool(project_dir, s_dir, "read_file", {"filepath": "input.json"}, distro)
    in_data = json.loads(r1.get("content", "{}"))
    tok, val_a, val_b = in_data.get("token"), in_data.get("a"), in_data.get("b")
    read_allowed = r1.get("outcome") == "allowed" and tok is not None and val_a is not None and val_b is not None

    calc = {"token": tok, "sum": val_a + val_b}
    r2 = execute_tool(
        project_dir,
        s_dir,
        "write_file",
        {"filepath": "result.json", "content": json.dumps(calc)},
        distro,
    )
    write_allowed = r2.get("outcome") == "allowed"

    r3 = execute_tool(project_dir, s_dir, "run_check", {}, distro)
    child_res = r3.get("child_results", {})
    if not r3.get("child_started"):
        raise RuntimeError("Checker child was not started")
    c_valid = r3.get("outcome") == "allowed" and child_res.get("token_sum_valid") is True

    p_netns_run3 = r3.get("parent_netns")
    c_netns_run3 = r3.get("child_netns")
    run3_ns_valid = (
        bool(r3.get("child_started"))
        and bool(p_netns_run3)
        and bool(c_netns_run3)
        and p_netns_run3 == c_netns_run3
        and p_netns_run3 != host_netns
        and not child_res.get("has_route")
    )

    probe_log_dir = pathlib.Path(s_dir) / ".session" / "logs" / uuid.uuid4().hex
    probe_log_dir.mkdir(parents=True, exist_ok=True)
    code, out, err = run_bwrap(
        distro,
        lx_paths["readonly"],
        lx_paths["workspace"],
        ["worker", lx_paths["outside_sentinel"], lx_paths["private_sentinel"]],
    )
    (probe_log_dir / "worker_probe_raw.json").write_text(
        json.dumps({"code": code, "stdout": out, "stderr": err}),
        encoding="utf-8",
    )
    if code != 0 or not out.strip():
        raise RuntimeError(f"Worker probe failed (rc={code}): {err.strip()}")
    worker_data = json.loads(out.strip())
    if not worker_data.get("started"):
        raise RuntimeError("Worker probe failed to start")
    w_probe = worker_data.get("results", {})
    worker_netns = w_probe.get("netns")
    worker_ns_valid = (
        bool(worker_netns) and worker_netns != host_netns and not w_probe.get("has_route") and not w_probe.get("connect_external")
    )

    post_hashes = {
        "app": file_sha256(pathlib.Path(s_dir) / "readonly" / "native_boundary.py"),
        "config": file_sha256(pathlib.Path(s_dir) / "readonly" / "config.json"),
        "input": file_sha256(pathlib.Path(s_dir) / "readonly" / "input.json"),
        "sentinel": file_sha256(sentinel),
        "priv": file_sha256(priv_sentinel),
    }
    integrity = pre_hashes == post_hashes

    def eval_check(cond):
        return "PASS" if cond else "FAIL"

    checks = {
        "read_allowed": eval_check(read_allowed),
        "write_allowed": eval_check(write_allowed),
        "read_outside_denied": eval_check(w_probe.get("read_outside") == "denied_2" and integrity),
        "write_outside_denied": eval_check(w_probe.get("write_outside") == "denied_2" and integrity),
        "private_read_denied": eval_check(w_probe.get("read_private") == "denied_2" and integrity),
        "network_denied": eval_check(worker_ns_valid),
        "child_read_outside_denied": eval_check(child_res.get("child_read_outside") == "denied_2"),
        "child_write_outside_denied": eval_check(child_res.get("child_write_outside") == "denied_2"),
        "child_network_denied": eval_check(run3_ns_valid),
        "readonly_worker": eval_check(
            w_probe.get("write_native_boundary.py") == "denied_30"
            and w_probe.get("write_input.json") == "denied_30"
            and w_probe.get("write_config.json") == "denied_30"
            and child_res.get("child_write_ro") == "denied_30"
        ),
        "symlink": eval_check(w_probe.get("symlink_read") == "denied_2" and w_probe.get("symlink_write") == "denied_2"),
        "tool_allowlist": eval_check(host_rejections_pass),
        "fixed_child_check": eval_check(c_valid),
        "integrity": eval_check(integrity),
    }
    overall = "PASS" if all(v == "PASS" for v in checks.values()) else "FAIL"
    report = {
        "profile": "native-isolation-bubblewrap",
        "native_wrapper": "WSL bubblewrap",
        "deletion_limitation": "No deletion tool; OS write permission permits own workspace mutation.",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "duration_seconds": round(time.time() - t0, 3),
        "status": overall,
        "results": checks,
        "raw_worker_probe": {
            "netns": worker_netns,
            "details": {
                "has_route": w_probe.get("has_route"),
                "connect_external": w_probe.get("connect_external"),
                "read_outside": w_probe.get("read_outside"),
                "write_outside": w_probe.get("write_outside"),
                "read_private": w_probe.get("read_private"),
                "write_private": w_probe.get("write_private"),
                "symlink_read": w_probe.get("symlink_read"),
                "symlink_write": w_probe.get("symlink_write"),
            },
        },
        "raw_child_probe": {
            "parent_netns": p_netns_run3,
            "child_netns": c_netns_run3,
            "details": {
                "token_sum_valid": child_res.get("token_sum_valid"),
                "has_route": child_res.get("has_route"),
                "child_read_outside": child_res.get("child_read_outside"),
                "child_write_outside": child_res.get("child_write_outside"),
                "child_read_priv": child_res.get("child_read_priv"),
                "child_write_priv": child_res.get("child_write_priv"),
                "child_write_ro": child_res.get("child_write_ro"),
            },
        },
    }
    acc_dir = pathlib.Path(project_dir) / "acceptance"
    acc_dir.mkdir(parents=True, exist_ok=True)
    (acc_dir / "native-isolation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if overall != "PASS":
        sys.exit(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "tool":
        req = json.loads(sys.stdin.read())
        print(json.dumps(worker_run_tool(req)))
        return
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        target_out = sys.argv[2] if len(sys.argv) > 2 else "/outside/sentinel.txt"
        target_priv = sys.argv[3] if len(sys.argv) > 3 else "/outside/priv.txt"
        worker_mode(target_out, target_priv)
        return
    if len(sys.argv) > 1 and sys.argv[1] == "checker":
        checker_mode()
        return

    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="Path to project directory")
    parser.add_argument("--distro", default="Ubuntu", help="WSL distro name")
    args = parser.parse_args()
    run_probe(args.project, args.distro)


if __name__ == "__main__":
    main()
