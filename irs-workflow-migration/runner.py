import argparse
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore


class LedgerCorruptionError(Exception):
    pass


class EventConflictError(Exception):
    pass


class LockAcquisitionError(Exception):
    pass


class ValidationError(Exception):
    pass


HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
HEX40_RE = re.compile(r"^[a-f0-9]{40}$")
REQ_ID_RE = re.compile(r"^REQ-[A-Za-z0-9_.-]+$")
VALID_IMG_EXTS = (".png", ".jpg", ".jpeg", ".webp")


def compute_canonical_fingerprint(event: Dict[str, Any]) -> str:
    canonical_bytes = json.dumps(
        event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


def compute_file_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def assert_safe_public_path(root_dir: str, rel_path: str) -> str:
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise ValidationError(f"Invalid public path reference: {rel_path!r}")
    if "\\" in rel_path:
        raise ValidationError(f"Backslash forbidden in public ref: {rel_path}")
    if ":" in rel_path:
        raise ValidationError(f"Colon forbidden in public ref: {rel_path}")
    if os.path.isabs(rel_path) or rel_path.startswith("/"):
        raise ValidationError(f"Absolute path forbidden: {rel_path}")
    parts = rel_path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValidationError(f"Path traversal or non-canonical component forbidden: {rel_path}")
    if parts[0] == ".local" or ".local" in parts:
        raise ValidationError(f"Public reference into .local rejected: {rel_path}")

    root_real = os.path.realpath(root_dir)
    target_full = os.path.realpath(os.path.join(root_real, rel_path))
    if not (target_full == root_real or target_full.startswith(root_real + os.sep)):
        raise ValidationError(f"Path traversal outside root rejected: {rel_path}")
    local_real = os.path.realpath(os.path.join(root_real, ".local"))
    if target_full == local_real or target_full.startswith(local_real + os.sep):
        raise ValidationError(f"Public reference into .local rejected: {rel_path}")
    return target_full


def assert_safe_local_path(local_dir: str, rel_path: str) -> str:
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise ValidationError(f"Invalid private path reference: {rel_path!r}")
    local_real = os.path.realpath(local_dir)
    if os.path.isabs(rel_path) or rel_path.startswith("/"):
        raise ValidationError(f"Absolute private path forbidden: {rel_path}")
    parts = rel_path.replace("\\", "/").split("/")
    if any(p in (".", "..") for p in parts):
        raise ValidationError(f"Private path traversal forbidden: {rel_path}")
    target_full = os.path.realpath(os.path.join(local_real, rel_path))
    if not (target_full == local_real or target_full.startswith(local_real + os.sep)):
        raise ValidationError(f"Private path traversal rejected: {rel_path}")
    return target_full


def compute_evidence_mapping_hash(root_dir: str, evidence_refs: List[str]) -> str:
    mapping: Dict[str, str] = {}
    for ref in sorted(evidence_refs):
        full_path = assert_safe_public_path(root_dir, ref)
        if not os.path.isfile(full_path):
            raise ValidationError(f"Evidence file not found: {ref}")
        norm_key = os.path.normpath(ref).replace("\\", "/")
        mapping[norm_key] = compute_file_sha256(full_path)
    canonical_map = json.dumps(
        mapping, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical_map).hexdigest()


def atomic_write_text(file_path: str, text: str) -> None:
    dir_name = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(dir_name, exist_ok=True)
    rand_suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    tmp_path = os.path.join(dir_name, f".tmp.{os.path.basename(file_path)}.{rand_suffix}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, file_path)


def atomic_write_json(file_path: str, data: Any) -> None:
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    atomic_write_text(file_path, payload)


class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.f: Optional[Any] = None

    def acquire(self) -> None:
        if msvcrt is None and fcntl is None:
            raise LockAcquisitionError("Platform missing file lock implementation (no msvcrt or fcntl)")
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_path)), exist_ok=True)
        self.f = open(self.lock_path, "a+b")
        self.f.seek(0, os.SEEK_END)
        if self.f.tell() == 0:
            self.f.write(b"\0")
            self.f.flush()
            os.fsync(self.f.fileno())
        self.f.seek(0)
        if msvcrt is not None:
            try:
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
            except (OSError, IOError) as exc:
                self.f.close()
                self.f = None
                raise LockAcquisitionError("Failed to acquire native Windows lock (conflict)") from exc
        elif fcntl is not None:
            try:
                fcntl.flock(self.f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, IOError) as exc:
                self.f.close()
                self.f = None
                raise LockAcquisitionError("Failed to acquire POSIX lock (conflict)") from exc

    def release(self) -> None:
        if self.f is None:
            return
        try:
            self.f.seek(0)
            if msvcrt is not None:
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            elif fcntl is not None:
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        finally:
            self.f.close()
            self.f = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


class Runner:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.local_dir = os.path.join(self.root, ".local")
        self.lock_path = os.path.join(self.local_dir, "runner.lock")
        self.initial_state_path = os.path.join(self.local_dir, "initial-state.json")
        self.trusted_sources_path = os.path.join(self.local_dir, "trusted-sources.json")
        self.state_path = os.path.join(self.root, "state.json")
        self.events_path = os.path.join(self.root, "events.jsonl")
        self.decisions_path = os.path.join(self.root, "decisions.jsonl")
        self.status_md_path = os.path.join(self.root, "status.md")

    def _load_json(self, path: str) -> Any:
        if not os.path.isfile(path):
            raise ValidationError(f"File not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as exc:
                raise ValidationError(f"Invalid JSON in {path}") from exc

    def _load_trusted_sources(self) -> Dict[str, Any]:
        data = self._load_json(self.trusted_sources_path)
        if not isinstance(data, dict) or "sources" not in data or not isinstance(data["sources"], dict):
            raise ValidationError("Invalid trusted-sources.json layout")
        return data["sources"]

    def _verify_source_provenance(
        self, source_ref: str, expected_actor: str, expected_scope: str, expected_event_type: str
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        sources = self._load_trusted_sources()
        if source_ref not in sources:
            raise ValidationError(f"source_ref '{source_ref}' not registered in trusted-sources")
        source_meta = sources[source_ref]
        if not isinstance(source_meta, dict):
            raise ValidationError(f"Invalid registry entry for {source_ref}")
        if source_meta.get("actor") != expected_actor:
            raise ValidationError(
                f"Actor mismatch for {source_ref}: expected {expected_actor}, got {source_meta.get('actor')}"
            )
        if source_meta.get("scope") != expected_scope:
            raise ValidationError(f"Scope mismatch in source {source_ref}: {source_meta.get('scope')}")
        allowed_events = source_meta.get("event_types", [])
        if not isinstance(allowed_events, list) or expected_event_type not in allowed_events:
            raise ValidationError(f"Event type {expected_event_type} not allowed for source {source_ref}")

        evidence_ref = source_meta.get("evidence_ref")
        expected_hash = source_meta.get("evidence_hash")
        if not isinstance(evidence_ref, str) or not isinstance(expected_hash, str):
            raise ValidationError(f"Source {source_ref} missing valid evidence_ref or evidence_hash")

        full_proof_path = assert_safe_local_path(self.local_dir, evidence_ref)
        if not os.path.isfile(full_proof_path):
            raise ValidationError(f"Private proof not found: {evidence_ref}")
        actual_hash = compute_file_sha256(full_proof_path)
        if actual_hash != expected_hash:
            raise ValidationError(f"Hash mismatch on {evidence_ref}: {actual_hash} != {expected_hash}")
        with open(full_proof_path, "r", encoding="utf-8") as f:
            try:
                proof_content = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValidationError(f"Invalid JSON in private proof: {evidence_ref}") from exc
        return source_meta, proof_content

    def _validate_candidate_tuple(self, candidate: Any, expected_scope: str) -> None:
        if not isinstance(candidate, dict):
            raise ValidationError("Candidate must be a dictionary")
        expected_keys = {"commit", "tree", "content_hash", "evidence_hash", "scope"}
        if set(candidate.keys()) != expected_keys:
            raise ValidationError("Candidate must contain exact 5 keys")
        c, t = candidate["commit"], candidate["tree"]
        if c is None and t is None:
            pass
        elif isinstance(c, str) and isinstance(t, str) and HEX40_RE.match(c) and HEX40_RE.match(t):
            pass
        else:
            raise ValidationError("Candidate commit/tree invalid (both null or both 40hex)")
        for h in (candidate["content_hash"], candidate["evidence_hash"]):
            if not isinstance(h, str) or not HASH_RE.match(h):
                raise ValidationError(f"Candidate hash invalid: {h}")
        if candidate["scope"] != expected_scope:
            raise ValidationError("Candidate scope mismatch with event scope")

    def _read_ledger(self) -> List[Tuple[Dict[str, Any], str]]:
        events: List[Tuple[Dict[str, Any], str]] = []
        if not os.path.isfile(self.events_path):
            return events
        with open(self.events_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                if not raw_line.endswith("\n") and not raw_line.endswith("\r"):
                    raise LedgerCorruptionError(f"Truncated/incomplete line at line {line_no}")
                stripped = raw_line.strip()
                if not stripped:
                    raise LedgerCorruptionError(f"Blank line in events.jsonl at line {line_no}")
                try:
                    evt = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise LedgerCorruptionError(f"Corrupted JSON at line {line_no}") from exc
                if not isinstance(evt, dict):
                    raise LedgerCorruptionError(f"Event at line {line_no} is not a JSON object")
                fp = compute_canonical_fingerprint(evt)
                events.append((evt, fp))
        return events

    def _read_existing_decisions(self) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        decisions: List[Dict[str, Any]] = []
        by_event_id: Dict[str, Dict[str, Any]] = {}
        if not os.path.isfile(self.decisions_path):
            return decisions, by_event_id
        with open(self.decisions_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                if not raw_line.endswith("\n") and not raw_line.endswith("\r"):
                    raise LedgerCorruptionError(f"Truncated line in decisions.jsonl at {line_no}")
                stripped = raw_line.strip()
                if not stripped:
                    raise LedgerCorruptionError(f"Blank line in decisions.jsonl at line {line_no}")
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise LedgerCorruptionError(f"Corrupted line in decisions.jsonl at {line_no}") from exc
                if not isinstance(record, dict) or "event_id" not in record:
                    raise LedgerCorruptionError(f"Invalid decision record layout at line {line_no}")
                eid = record["event_id"]
                if eid in by_event_id:
                    if compute_canonical_fingerprint(record) != compute_canonical_fingerprint(by_event_id[eid]):
                        raise LedgerCorruptionError(f"Conflicting decision audit record for event {eid}")
                else:
                    by_event_id[eid] = record
                    decisions.append(record)
        return decisions, by_event_id

    def _validate_snapshot(self, state: Dict[str, Any]) -> None:
        if state.get("schema_version") != 1:
            raise LedgerCorruptionError(f"schema_version must be 1, got {state.get('schema_version')}")
        if state.get("generation") != "m1-candidate":
            raise LedgerCorruptionError(f"Unexpected generation: {state.get('generation')}")
        if state.get("mode") != "shadow":
            raise LedgerCorruptionError(f"Initial mode must be shadow, got {state.get('mode')}")
        if state.get("business_paused") is not True:
            raise LedgerCorruptionError("business_paused must be true at initialization")
        if state.get("write_run_tools_enabled") is not False:
            raise LedgerCorruptionError("write_run_tools_enabled must be false at initialization")
        if not isinstance(state.get("migration_paused"), bool):
            raise LedgerCorruptionError("migration_paused must be boolean at initialization")
        if state.get("tasks") != {}:
            raise LedgerCorruptionError("tasks must be empty dict at initialization")
        if state.get("processed_event_ids") != {}:
            raise LedgerCorruptionError("processed_event_ids must be empty dict at initialization")

        auth_id = state.get("migration_authorization_id")
        if not auth_id or not isinstance(auth_id, str):
            raise LedgerCorruptionError("migration_authorization_id missing in snapshot")

        auth_source_ref = state.get("authorization_source_ref")
        if not auth_source_ref or not isinstance(auth_source_ref, str):
            raise LedgerCorruptionError("authorization_source_ref missing in snapshot")

        sources = self._load_trusted_sources()
        if auth_source_ref not in sources:
            raise LedgerCorruptionError(f"authorization_source_ref '{auth_source_ref}' not found in trusted-sources")
        src = sources[auth_source_ref]
        if not isinstance(src, dict) or src.get("policy_id") != auth_id or src.get("scope") != "migration" or src.get("actor") != "human":
            raise LedgerCorruptionError(f"authorization_source_ref '{auth_source_ref}' does not match policy, scope, or actor")
        source_meta, proof = self._verify_source_provenance(auth_source_ref, "human", "migration", "submit_task")
        if (
            proof.get("policy_id") != source_meta.get("policy_id")
            or proof.get("scope") != source_meta.get("scope")
            or proof.get("actor") != source_meta.get("actor")
        ):
            raise LedgerCorruptionError("Proof JSON policy_id/scope/actor mismatch with registry")

    def init(self) -> Dict[str, Any]:
        with FileLock(self.lock_path):
            if os.path.isfile(self.initial_state_path):
                snapshot = self._load_json(self.initial_state_path)
                self._validate_snapshot(snapshot)
                events = self._read_ledger()
                projected_state, decisions = self._project_state(events)
                self._sync_decisions(decisions)
                atomic_write_json(self.state_path, projected_state)
                self._render_status_md(projected_state, len(events))
                return {"status": "initialized", "initial_snapshot": os.path.basename(self.initial_state_path)}

            if not os.path.isfile(self.state_path):
                raise ValidationError(f"Base state not found: {self.state_path}")
            base_state = self._load_json(self.state_path)
            self._validate_snapshot(base_state)
            atomic_write_json(self.initial_state_path, base_state)
            self._render_status_md(base_state, 0)
            return {"status": "initialized", "initial_snapshot": os.path.basename(self.initial_state_path)}

    def _validate_event_envelope_and_rules(self, evt: Dict[str, Any], state: Dict[str, Any]) -> None:
        exact_envelope_keys = {"event_id", "event_type", "request_id", "scope", "payload", "source_ref"}
        if set(evt.keys()) != exact_envelope_keys:
            raise ValidationError(f"Envelope keys invalid: {sorted(list(evt.keys()))}")

        etype = evt["event_type"]
        scope = evt["scope"]
        source_ref = evt["source_ref"]
        req_id = evt["request_id"]
        payload = evt["payload"]
        evt_id = evt["event_id"]

        if not isinstance(evt_id, str) or not evt_id.startswith("EVT-"):
            raise ValidationError(f"Invalid event_id format: {evt_id}")
        if not isinstance(req_id, str) or not REQ_ID_RE.match(req_id):
            raise ValidationError(f"Invalid request_id format: {req_id}")
        if scope != "migration":
            raise ValidationError(f"Scope '{scope}' rejected: M1 strictly allows only migration scope")
        if not isinstance(payload, dict):
            raise ValidationError("Payload must be a dictionary")
        if not isinstance(source_ref, str) or not source_ref:
            raise ValidationError("source_ref must be non-empty string")

        if state.get("migration_paused") and etype in ("submit_task", "task_completed", "cutover"):
            raise ValidationError(f"Event {etype} rejected: migration is paused")

        if etype == "submit_task":
            source_meta, _ = self._verify_source_provenance(source_ref, "human", scope, etype)
            policy_id = source_meta.get("policy_id")
            initial_auth_id = state.get("migration_authorization_id")
            if not policy_id or policy_id != initial_auth_id:
                raise ValidationError(f"submit_task human source policy_id '{policy_id}' must equal initial migration_authorization_id '{initial_auth_id}'")

            if set(payload.keys()) != {"candidate", "task"}:
                raise ValidationError("submit_task payload must have exact keys 'candidate' and 'task'")
            cand = payload["candidate"]
            self._validate_candidate_tuple(cand, scope)
            task_obj = payload["task"]
            if not isinstance(task_obj, dict):
                raise ValidationError("task must be a dictionary")
            task_id = task_obj.get("task_id")
            if not isinstance(task_id, str) or not task_id.strip():
                raise ValidationError("submit_task must contain non-empty task.task_id string")
            if "shell" in task_obj or "scopeshell" in task_obj or "scope" in task_obj:
                raise ValidationError("Hidden shell or scope execution keys forbidden in task contract")

            for path_field in ("allow_read_paths", "allow_write_paths"):
                if path_field not in task_obj:
                    raise ValidationError(f"submit_task task missing required field: {path_field}")
                path_list = task_obj[path_field]
                if not isinstance(path_list, list):
                    raise ValidationError(f"{path_field} must be a list")
                for p in path_list:
                    assert_safe_public_path(self.root, p)

            existing = state.get("tasks", {}).get(req_id)
            if existing is not None:
                if existing["candidate"] == cand and existing.get("task_contract") != task_obj:
                    raise ValidationError("Task contract change with identical candidate rejected")

        elif etype == "review_result":
            source_meta, proof = self._verify_source_provenance(source_ref, "ChatGPT", scope, etype)
            if source_meta.get("request_id") != req_id:
                raise ValidationError(f"Trusted source {source_ref} bound to request {source_meta.get('request_id')}, not {req_id}")
            expected_cand = source_meta.get("candidate")
            cand = payload.get("candidate")
            if expected_cand != cand:
                raise ValidationError("Candidate identity mismatch with trusted source binding")
            self._validate_candidate_tuple(cand, scope)

            req_keys = {
                "request_id",
                "candidate",
                "decision",
                "findings",
                "evidence_refs",
                "review_kind",
                "human_approval",
                "authorization_source_ref",
                "scope",
            }
            if set(payload.keys()) != req_keys:
                raise ValidationError(f"review_result payload keys invalid: {sorted(list(payload.keys()))}")
            if payload["request_id"] != req_id:
                raise ValidationError("review_result request_id mismatch with envelope")
            if payload["scope"] != scope:
                raise ValidationError("review_result scope mismatch with envelope")
            if payload["authorization_source_ref"] != source_ref:
                raise ValidationError("authorization_source_ref must match event source_ref")
            if payload["human_approval"] is not False:
                raise ValidationError("human_approval must be strictly false")
            if payload["decision"] not in ("approve", "reject", "needs_evidence"):
                raise ValidationError(f"Invalid decision: {payload['decision']}")
            if payload["review_kind"] not in ("technical", "agent_visual"):
                raise ValidationError(f"Invalid review_kind: {payload['review_kind']}")
            if not isinstance(payload["findings"], list) or not all(isinstance(x, str) for x in payload["findings"]):
                raise ValidationError("findings must be a list of strings")
            if not isinstance(payload["evidence_refs"], list) or not all(isinstance(x, str) for x in payload["evidence_refs"]):
                raise ValidationError("evidence_refs must be a list of strings")

            for ref in payload["evidence_refs"]:
                assert_safe_public_path(self.root, ref)

            if proof.get("decision") != payload:
                raise ValidationError("Review payload does not strictly match verified proof decision")

            task_record = state.get("tasks", {}).get(req_id)
            if not task_record:
                raise ValidationError(f"Cannot review nonexistent task: {req_id}")
            if task_record["candidate"] != cand:
                raise ValidationError("Candidate in review is stale or does not match active task candidate")

            if payload["decision"] == "approve":
                if len(payload["findings"]) > 0:
                    raise ValidationError("Approved decision cannot contain findings")
                if len(payload["evidence_refs"]) == 0:
                    raise ValidationError("Approved decision must include evidence_refs")
                calc_hash = compute_evidence_mapping_hash(self.root, payload["evidence_refs"])
                if calc_hash != cand["evidence_hash"]:
                    raise ValidationError(f"Evidence mapping hash {calc_hash} != candidate {cand['evidence_hash']}")
                if payload["review_kind"] == "agent_visual":
                    image_refs = [
                        r for r in payload["evidence_refs"]
                        if os.path.splitext(r)[1].lower() in VALID_IMG_EXTS
                    ]
                    if len(image_refs) < 1:
                        raise ValidationError("agent_visual approve requires at least one real image in evidence_refs")
                    if proof.get("screenshot_real") is not True:
                        raise ValidationError("agent_visual approve requires private proof screenshot_real=true")

                    screenshot_hashes = proof.get("screenshot_hashes")
                    if not isinstance(screenshot_hashes, dict):
                        raise ValidationError("agent_visual approve requires private proof screenshot_hashes dictionary")

                    for img_ref in image_refs:
                        full_img_path = assert_safe_public_path(self.root, img_ref)
                        if not os.path.isfile(full_img_path):
                            raise ValidationError(f"Referenced screenshot not found on disk: {img_ref}")
                        actual_img_hash = compute_file_sha256(full_img_path)
                        expected_img_hash = screenshot_hashes.get(img_ref)
                        if not expected_img_hash or not isinstance(expected_img_hash, str):
                            raise ValidationError(f"Missing screenshot hash in private proof for {img_ref}")
                        if actual_img_hash != expected_img_hash:
                            raise ValidationError(f"Screenshot hash mismatch for {img_ref}: {actual_img_hash} != {expected_img_hash}")

        elif etype == "task_completed":
            if set(payload.keys()) != {"candidate"}:
                raise ValidationError("task_completed payload must contain exact key 'candidate'")
            source_meta, proof = self._verify_source_provenance(source_ref, "ChatGPT", scope, etype)
            if source_meta.get("request_id") != req_id:
                raise ValidationError(f"Completion source bound to request {source_meta.get('request_id')}, not {req_id}")
            cand = payload.get("candidate")
            self._validate_candidate_tuple(cand, scope)
            if source_meta.get("candidate") != cand:
                raise ValidationError("Completion source bound candidate mismatch")

            task_record = state.get("tasks", {}).get(req_id)
            if not task_record:
                raise ValidationError(f"Cannot complete nonexistent task: {req_id}")
            if task_record["candidate"] != cand:
                raise ValidationError("Completed candidate does not match current task candidate")
            if task_record.get("review_decision") != "approve":
                raise ValidationError("Cannot complete task without prior approved review")

            stored_review = task_record.get("review_payload")
            if not stored_review or not isinstance(stored_review, dict):
                raise ValidationError("Stored review payload missing for completed task")
            if stored_review.get("decision") != "approve":
                raise ValidationError("Stored review decision must be approve")

            proof_decision = proof.get("decision")
            if proof_decision != stored_review:
                raise ValidationError("task_completed private proof decision must match stored review payload exactly")

            if proof.get("request_id") is not None and proof.get("request_id") != req_id:
                raise ValidationError("task_completed private proof request_id mismatch")
            if proof.get("candidate") is not None and proof.get("candidate") != cand:
                raise ValidationError("task_completed private proof candidate mismatch")

        elif etype == "pause":
            source_meta, _ = self._verify_source_provenance(source_ref, "human", scope, etype)
            policy_id = payload.get("policy_id")
            if not policy_id or not isinstance(policy_id, str):
                raise ValidationError("pause event requires policy_id string")
            if source_meta.get("policy_id") != policy_id:
                raise ValidationError("pause payload policy_id does not match human source policy")

        elif etype == "bind_roles":
            source_meta, proof = self._verify_source_provenance(source_ref, "human", scope, etype)
            roles = payload.get("roles")
            if not isinstance(roles, dict):
                raise ValidationError("bind_roles requires roles dict")

            if proof.get("roles") != roles:
                raise ValidationError("bind_roles payload roles does not match private proof roles exactly")

            verified_roles = proof.get("verified_roles")
            if not isinstance(verified_roles, dict):
                raise ValidationError("bind_roles proof missing verified_roles dictionary")

            allowed_roles = {"overview", "approval", "acceptance", "ad_hoc"}
            for r in roles:
                if r not in allowed_roles:
                    raise ValidationError(f"Invalid role '{r}' in bind_roles")

            required_roles = {"overview", "approval", "acceptance"}
            for r in required_roles:
                if r not in roles:
                    raise ValidationError(f"Required role '{r}' missing from roles")

            seen_thread_ids = set()
            for role_name, role_data in roles.items():
                if not isinstance(role_data, dict):
                    raise ValidationError(f"Role '{role_name}' must be an object")
                tid = role_data.get("thread_id")
                if not isinstance(tid, str) or not tid.strip():
                    raise ValidationError(f"Role '{role_name}' must have a non-empty thread_id string")
                if tid in seen_thread_ids:
                    raise ValidationError(f"Role '{role_name}' has duplicate thread_id '{tid}'")
                seen_thread_ids.add(tid)
                if role_data.get("status") != "candidate":
                    raise ValidationError(f"Role '{role_name}' status must be 'candidate', got {role_data.get('status')}")
                if verified_roles.get(role_name) != tid:
                    raise ValidationError(f"Role '{role_name}' thread_id '{tid}' does not match verified_roles proof '{verified_roles.get(role_name)}'")

        elif etype == "cutover":
            source_meta, proof = self._verify_source_provenance(source_ref, "human", scope, etype)
            policy_id = source_meta.get("policy_id")
            if not policy_id or policy_id != state.get("migration_authorization_id"):
                raise ValidationError("cutover requires human source policy_id matching migration_authorization_id")
            if proof.get("cutover_payload") != payload:
                raise ValidationError("cutover payload does not match human authorization proof")

            gates = payload.get("gates")
            if not isinstance(gates, dict):
                raise ValidationError("cutover requires gates dict")
            expected_gates = {f"V0{i}" for i in range(1, 10)}
            if not expected_gates.issubset(gates.keys()):
                raise ValidationError("cutover missing required gates V01-V09")

            # Protected host provenance registry; no cryptographic identity inference.
            for g_id in sorted(list(expected_gates)):
                g_info = gates[g_id]
                if not isinstance(g_info, dict) or g_info.get("status") != "PASS":
                    raise ValidationError(f"Gate {g_id} is not PASS")
                ref = g_info.get("ref")
                expected_hash = g_info.get("sha256")
                gate_source_ref = g_info.get("source_ref")
                if not ref or not expected_hash:
                    raise ValidationError(f"Gate {g_id} missing ref or sha256")
                if not gate_source_ref or not isinstance(gate_source_ref, str):
                    raise ValidationError(f"Gate {g_id} missing source_ref")

                full_path = assert_safe_public_path(self.root, ref)
                if not os.path.isfile(full_path):
                    raise ValidationError(f"Gate artifact not found: {ref}")
                actual_hash = compute_file_sha256(full_path)
                if actual_hash != expected_hash:
                    raise ValidationError(f"Gate artifact {ref} hash mismatch")

                try:
                    with open(full_path, "r", encoding="utf-8") as gf:
                        g_data = json.load(gf)
                except json.JSONDecodeError as exc:
                    raise ValidationError(f"Gate artifact {ref} not valid JSON") from exc
                if not isinstance(g_data, dict):
                    raise ValidationError(f"Gate artifact {ref} JSON must be object")
                if g_data.get("gate_id") != g_id or g_data.get("status") != "PASS":
                    raise ValidationError(f"Gate {g_id} content does not declare PASS")
                if g_data.get("reviewer") != "ChatGPT":
                    raise ValidationError(f"Gate {g_id} reviewer must be ChatGPT")

                gate_meta, gate_private_proof = self._verify_source_provenance(
                    gate_source_ref, expected_actor="ChatGPT", expected_scope="migration", expected_event_type="cutover_gate"
                )
                if gate_private_proof.get("gate") != g_data:
                    raise ValidationError(f"Gate {g_id} private proof gate does not match public gate JSON exactly")
                if gate_private_proof.get("gate_artifact_hash") != actual_hash:
                    raise ValidationError(f"Gate {g_id} private proof gate_artifact_hash mismatch")

                if g_id == "V05":
                    proof_ref = g_data.get("native_proof_ref")
                    proof_hash = g_data.get("native_proof_hash")
                    if not proof_ref or not proof_hash or not isinstance(proof_ref, str) or not isinstance(proof_hash, str):
                        raise ValidationError("Gate V05 missing native_proof_ref or native_proof_hash string")
                    full_proof_path = assert_safe_public_path(self.root, proof_ref)
                    if not os.path.isfile(full_proof_path):
                        raise ValidationError(f"V05 native proof file not found: {proof_ref}")
                    actual_proof_bytes_hash = compute_file_sha256(full_proof_path)
                    if actual_proof_bytes_hash != proof_hash:
                        raise ValidationError(f"V05 native proof hash mismatch: {actual_proof_bytes_hash} != {proof_hash}")
                    try:
                        with open(full_proof_path, "r", encoding="utf-8") as npf:
                            native_proof_data = json.load(npf)
                    except json.JSONDecodeError as exc:
                        raise ValidationError("V05 native proof not valid JSON") from exc
                    if not isinstance(native_proof_data, dict):
                        raise ValidationError("V05 native proof JSON must be an object")
                    if native_proof_data.get("native_wrapper") != "codex sandbox":
                        raise ValidationError("V05 native proof native_wrapper must be 'codex sandbox'")
                    results = native_proof_data.get("results")
                    if not isinstance(results, dict):
                        raise ValidationError("V05 native proof missing results dictionary")
                    required_checks = (
                        "read_allowed",
                        "write_allowed",
                        "read_outside_denied",
                        "write_outside_denied",
                        "private_read_denied",
                        "network_denied",
                        "child_read_outside_denied",
                        "child_write_outside_denied",
                        "child_network_denied",
                    )
                    for chk in required_checks:
                        if results.get(chk) != "PASS":
                            raise ValidationError(f"V05 native proof result '{chk}' must be 'PASS', got '{results.get(chk)}'")

            seen_roles_tids = set()
            for r in ("overview", "approval", "acceptance"):
                r_entry = state.get("roles", {}).get(r, {})
                tid = r_entry.get("thread_id")
                if not tid or not isinstance(tid, str) or not tid.strip():
                    raise ValidationError(f"Cutover blocked: role {r} thread_id not bound in state")
                if tid in seen_roles_tids:
                    raise ValidationError(f"Cutover blocked: duplicate thread_id {tid} in roles")
                seen_roles_tids.add(tid)

        else:
            raise ValidationError(f"Unknown event_type: {etype}")

    def _apply_event_to_state(
        self, state: Dict[str, Any], evt: Dict[str, Any], fp: str
    ) -> Optional[Dict[str, Any]]:
        etype = evt["event_type"]
        payload = evt["payload"]
        req_id = evt.get("request_id")
        decision_record: Optional[Dict[str, Any]] = None

        if etype == "submit_task":
            task_obj = payload["task"]
            task_id = task_obj["task_id"]
            cand = payload["candidate"]
            existing = state["tasks"].get(req_id)
            if existing is not None:
                if existing["candidate"] == cand and existing.get("task_contract") == task_obj:
                    pass
                else:
                    existing["candidate"] = cand
                    existing["task_contract"] = task_obj
                    existing["review_status"] = "NEEDS_REVIEW"
                    existing["review_decision"] = None
                    existing["review_findings"] = None
                    existing["review_payload"] = None
                    existing["completion_status"] = "pending"
                    existing["revision"] = existing.get("revision", 1) + 1
            else:
                state["tasks"][req_id] = {
                    "task_id": task_id,
                    "candidate": cand,
                    "task_contract": task_obj,
                    "review_status": "NEEDS_REVIEW",
                    "review_decision": None,
                    "review_findings": None,
                    "review_payload": None,
                    "completion_status": "pending",
                    "revision": 1,
                }
        elif etype == "review_result":
            target_task = state["tasks"][req_id]
            target_task["review_decision"] = payload["decision"]
            target_task["review_status"] = "REVIEWED"
            target_task["review_findings"] = payload["findings"]
            target_task["review_payload"] = payload
            decision_record = dict(payload)
            decision_record["event_id"] = evt["event_id"]
        elif etype == "task_completed":
            target_task = state["tasks"][req_id]
            target_task["completion_status"] = "completed"
        elif etype == "pause":
            if evt["scope"] == "migration":
                state["migration_paused"] = True
                state["effective_migration_pause_policy"] = payload.get("policy_id")
        elif etype == "bind_roles":
            for rk, rv in payload["roles"].items():
                state["roles"][rk] = rv
        elif etype == "cutover":
            state["generation"] = "m1-active"
            state["mode"] = "active"
            state["active_owner"] = "runner"
            state["orchestration_only"] = True
            state["business_paused"] = True

        state["processed_event_ids"][evt["event_id"]] = fp
        return decision_record

    def _project_state(self, events: List[Tuple[Dict[str, Any], str]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        if not os.path.isfile(self.initial_state_path):
            raise ValidationError("initial-state.json missing; run init first")
        state = self._load_json(self.initial_state_path)
        self._validate_snapshot(state)

        decisions: List[Dict[str, Any]] = []
        seen_event_ids: Dict[str, str] = {}

        for evt, fp in events:
            evt_id = evt.get("event_id")
            if not isinstance(evt_id, str):
                raise ValidationError("Event missing event_id string")
            if evt_id in seen_event_ids:
                if seen_event_ids[evt_id] == fp:
                    continue
                raise EventConflictError(f"Duplicate event_id {evt_id} with conflicting fingerprint")
            if evt_id in state.get("processed_event_ids", {}):
                if state["processed_event_ids"][evt_id] == fp:
                    seen_event_ids[evt_id] = fp
                    continue
                raise EventConflictError(f"Duplicate event_id {evt_id} conflicting with processed_event_ids")
            seen_event_ids[evt_id] = fp

            self._validate_event_envelope_and_rules(evt, state)
            decision_rec = self._apply_event_to_state(state, evt, fp)
            if decision_rec is not None:
                decisions.append(decision_rec)
        return state, decisions

    def _sync_decisions(self, replay_decisions: List[Dict[str, Any]]) -> None:
        existing_decisions, existing_by_id = self._read_existing_decisions()
        replay_by_id: Dict[str, Dict[str, Any]] = {}
        for d in replay_decisions:
            eid = d["event_id"]
            if eid in replay_by_id:
                if compute_canonical_fingerprint(d) != compute_canonical_fingerprint(replay_by_id[eid]):
                    raise LedgerCorruptionError(f"Duplicate conflicting replay decision for {eid}")
            else:
                replay_by_id[eid] = d

        for eid, rec in existing_by_id.items():
            if eid not in replay_by_id:
                raise LedgerCorruptionError(f"Extra decision record for event {eid} absent from authoritative replay")
            if compute_canonical_fingerprint(rec) != compute_canonical_fingerprint(replay_by_id[eid]):
                raise LedgerCorruptionError(f"Decision mismatch for event {eid}")

        missing_to_append: List[Dict[str, Any]] = []
        seen_appended = set(existing_by_id.keys())
        for d in replay_decisions:
            eid = d["event_id"]
            if eid not in seen_appended:
                seen_appended.add(eid)
                missing_to_append.append(d)

        if missing_to_append:
            with open(self.decisions_path, "a", encoding="utf-8") as f:
                for item in missing_to_append:
                    f.write(json.dumps(item, ensure_ascii=False, allow_nan=False) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def _render_status_md(self, state: Dict[str, Any], event_count: int) -> None:
        md_content = (
            f"# IRS Migration Status\n\n"
            f"- Generation: `{state.get('generation')}`\n"
            f"- Mode: `{state.get('mode')}`\n"
            f"- Active Owner: `{state.get('active_owner')}`\n"
            f"- Business Paused: `{state.get('business_paused')}`\n"
            f"- Migration Paused: `{state.get('migration_paused')}`\n"
            f"- Effective Pause Policy: `{state.get('effective_pause_policy')}`\n"
            f"- Effective Migration Pause Policy: `{state.get('effective_migration_pause_policy')}`\n"
            f"- Total Events: `{event_count}`\n"
            f"- Tasks Tracked: `{len(state.get('tasks', {}))}`\n"
        )
        atomic_write_text(self.status_md_path, md_content)

    def recover(self) -> Dict[str, Any]:
        with FileLock(self.lock_path):
            events = self._read_ledger()
            projected_state, decisions = self._project_state(events)
            self._sync_decisions(decisions)
            atomic_write_json(self.state_path, projected_state)
            self._render_status_md(projected_state, len(events))
            return {"status": "recovered", "event_count": len(events)}

    def status(self) -> Dict[str, Any]:
        with FileLock(self.lock_path):
            events = self._read_ledger()
            projected_state, decisions = self._project_state(events)
            self._sync_decisions(decisions)
            atomic_write_json(self.state_path, projected_state)
            self._render_status_md(projected_state, len(events))
            return {
                "status": "ok",
                "event_count": len(events),
                "generation": projected_state.get("generation"),
                "mode": projected_state.get("mode"),
                "migration_paused": projected_state.get("migration_paused"),
                "business_paused": projected_state.get("business_paused"),
            }

    def ingest(self, event_file_path: str) -> Dict[str, Any]:
        with FileLock(self.lock_path):
            if not os.path.isfile(event_file_path):
                raise ValidationError(f"Event file not found: {event_file_path}")
            with open(event_file_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
            try:
                event = json.loads(raw_content)
            except json.JSONDecodeError as exc:
                raise ValidationError("Invalid JSON in event file") from exc
            if not isinstance(event, dict):
                raise ValidationError("Event JSON root must be an object")

            evt_id = event.get("event_id")
            if not evt_id or not isinstance(evt_id, str):
                raise ValidationError("Missing or invalid event_id")
            new_fp = compute_canonical_fingerprint(event)

            existing_events = self._read_ledger()
            duplicate_found = False
            for existing_evt, existing_fp in existing_events:
                if existing_evt.get("event_id") == evt_id:
                    if existing_fp == new_fp:
                        duplicate_found = True
                        break
                    raise EventConflictError(f"Conflict: identical event_id {evt_id} with different payload")

            current_state, current_decisions = self._project_state(existing_events)
            self._sync_decisions(current_decisions)

            if duplicate_found:
                atomic_write_json(self.state_path, current_state)
                self._render_status_md(current_state, len(existing_events))
                return {"status": "duplicate", "event_id": evt_id}

            prospective_events = existing_events + [(event, new_fp)]
            projected_state, prospective_decisions = self._project_state(prospective_events)

            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
                f.flush()
                os.fsync(f.fileno())

            self._sync_decisions(prospective_decisions)
            atomic_write_json(self.state_path, projected_state)
            self._render_status_md(projected_state, len(prospective_events))
            return {"status": "ingested", "event_id": evt_id, "event_type": event.get("event_type")}


def main() -> None:
    parser = argparse.ArgumentParser(description="IRS Workflow Migration Runner")
    parser.add_argument("--root", required=True, help="Migration root directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize immutable baseline and verify configs")
    subparsers.add_parser("status", help="Report runner status and counts")
    subparsers.add_parser("recover", help="Replay ledger and sync state")
    ingest_p = subparsers.add_parser("ingest", help="Ingest and validate new event")
    ingest_p.add_argument("event_file", help="Path to JSON event file")

    args = parser.parse_args()
    runner = Runner(args.root)

    if args.command == "init":
        res = runner.init()
    elif args.command == "status":
        res = runner.status()
    elif args.command == "recover":
        res = runner.recover()
    elif args.command == "ingest":
        res = runner.ingest(args.event_file)
    else:
        raise ValidationError(f"Unknown command: {args.command}")
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
