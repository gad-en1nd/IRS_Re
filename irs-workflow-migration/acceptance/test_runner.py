import ast
import hashlib
import json
import os
import sys
import unittest
import uuid
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from runner import (
    EventConflictError,
    FileLock,
    LedgerCorruptionError,
    LockAcquisitionError,
    Runner,
    ValidationError,
    assert_safe_local_path,
    assert_safe_public_path,
    atomic_write_json,
    atomic_write_text,
    compute_canonical_fingerprint,
    compute_evidence_mapping_hash,
    compute_file_sha256,
)

SCRATCH_BASE = os.path.join(PROJECT_ROOT, "acceptance", ".scratch")


class TestRunnerAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture_id = str(uuid.uuid4())
        self.root = os.path.join(SCRATCH_BASE, self.fixture_id)
        os.makedirs(self.root, exist_ok=True)
        self.local_dir = os.path.join(self.root, ".local")
        os.makedirs(self.local_dir, exist_ok=True)

    def _write_json(self, rel_or_abs_path: str, data: Any) -> str:
        if os.path.isabs(rel_or_abs_path):
            target_path = rel_or_abs_path
        else:
            target_path = os.path.join(self.root, rel_or_abs_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        atomic_write_json(target_path, data)
        return target_path

    def _write_text(self, rel_or_abs_path: str, text: str) -> str:
        if os.path.isabs(rel_or_abs_path):
            target_path = rel_or_abs_path
        else:
            target_path = os.path.join(self.root, rel_or_abs_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        atomic_write_text(target_path, text)
        return target_path

    def _register_trusted_source(
        self,
        source_ref: str,
        actor: str,
        scope: str,
        event_types: List[str],
        proof_content: Dict[str, Any],
        policy_id: Optional[str] = None,
        request_id: Optional[str] = None,
        candidate: Optional[Dict[str, Any]] = None,
        proof_rel: Optional[str] = None,
    ) -> str:
        if proof_rel is None:
            proof_rel = f"proofs/{source_ref}.json"
        proof_full = assert_safe_local_path(self.local_dir, proof_rel)
        os.makedirs(os.path.dirname(proof_full), exist_ok=True)
        atomic_write_json(proof_full, proof_content)
        proof_hash = compute_file_sha256(proof_full)

        source_meta: Dict[str, Any] = {
            "actor": actor,
            "scope": scope,
            "event_types": event_types,
            "evidence_ref": proof_rel,
            "evidence_hash": proof_hash,
        }
        if policy_id is not None:
            source_meta["policy_id"] = policy_id
        if request_id is not None:
            source_meta["request_id"] = request_id
        if candidate is not None:
            source_meta["candidate"] = candidate

        trusted_sources_path = os.path.join(self.local_dir, "trusted-sources.json")
        if os.path.isfile(trusted_sources_path):
            with open(trusted_sources_path, "r", encoding="utf-8") as f:
                ts_data = json.load(f)
        else:
            ts_data = {"sources": {}}
        ts_data["sources"][source_ref] = source_meta
        atomic_write_json(trusted_sources_path, ts_data)
        return proof_hash

    def _make_candidate(
        self,
        scope: str = "migration",
        commit: Optional[str] = "1111111111111111111111111111111111111111",
        tree: Optional[str] = "2222222222222222222222222222222222222222",
        content_hash: str = "sha256:" + "a" * 64,
        evidence_hash: Optional[str] = None,
        evidence_files: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        if evidence_files is not None:
            for rel_p, content in evidence_files.items():
                full_p = os.path.join(self.root, rel_p)
                os.makedirs(os.path.dirname(full_p), exist_ok=True)
                atomic_write_text(full_p, content)
            computed_hash = compute_evidence_mapping_hash(self.root, list(evidence_files.keys()))
            evidence_hash = computed_hash
        elif evidence_hash is None:
            evidence_hash = "sha256:" + "b" * 64

        return {
            "commit": commit,
            "tree": tree,
            "content_hash": content_hash,
            "evidence_hash": evidence_hash,
            "scope": scope,
        }

    def _init_valid_migration(
        self,
        policy_id: str = "POL-SYNTH-MIG-001",
        auth_source_ref: str = "SRC-SYNTH-HUMAN-AUTH",
    ) -> Runner:
        auth_proof = {
            "auth_statement": "synthetic-authorization-granted",
            "actor": "human",
            "scope": "migration",
            "policy_id": policy_id,
        }
        self._register_trusted_source(
            source_ref=auth_source_ref,
            actor="human",
            scope="migration",
            event_types=["submit_task", "pause", "bind_roles", "cutover"],
            proof_content=auth_proof,
            policy_id=policy_id,
        )
        base_state = {
            "schema_version": 1,
            "generation": "m1-candidate",
            "mode": "shadow",
            "business_paused": True,
            "write_run_tools_enabled": False,
            "tasks": {},
            "processed_event_ids": {},
            "migration_authorization_id": policy_id,
            "authorization_source_ref": auth_source_ref,
            "active_owner": None,
            "migration_paused": False,
            "effective_pause_policy": None,
            "effective_migration_pause_policy": None,
            "roles": {},
        }
        self._write_json("state.json", base_state)
        runner = Runner(self.root)
        res = runner.init()
        self.assertEqual(res.get("status"), "initialized")
        return runner

    def _write_and_ingest(self, runner: Runner, event: Dict[str, Any], filename: str = "event.json") -> Dict[str, Any]:
        event_path = os.path.join(self.root, filename)
        atomic_write_json(event_path, event)
        return runner.ingest(event_path)

    def test_valid_init_and_status(self) -> None:
        runner = self._init_valid_migration()
        initial_state_file = os.path.join(self.local_dir, "initial-state.json")
        self.assertTrue(os.path.isfile(initial_state_file))
        status_file = os.path.join(self.root, "status.md")
        self.assertTrue(os.path.isfile(status_file))
        with open(status_file, "r", encoding="utf-8") as f:
            status_text = f.read()
        self.assertIn("# IRS Migration Status", status_text)
        self.assertIn("Generation: `m1-candidate`", status_text)

        status_res = runner.status()
        self.assertEqual(status_res.get("status"), "ok")
        self.assertEqual(status_res.get("event_count"), 0)
        self.assertEqual(status_res.get("generation"), "m1-candidate")
        self.assertEqual(status_res.get("mode"), "shadow")
        self.assertIs(status_res.get("business_paused"), True)
        self.assertIs(status_res.get("migration_paused"), False)

    def test_authorization_source_ref_migration_start(self) -> None:
        runner = self._init_valid_migration(policy_id="POL-MIG-START", auth_source_ref="SRC-START-HUMAN")
        cand = self._make_candidate()
        event = {
            "event_id": "EVT-START-001",
            "event_type": "submit_task",
            "request_id": "REQ-START-001",
            "scope": "migration",
            "source_ref": "SRC-START-HUMAN",
            "payload": {
                "candidate": cand,
                "task": {"task_id": "TASK-INIT-01", "allow_read_paths": [], "allow_write_paths": []},
            },
        }
        res = self._write_and_ingest(runner, event)
        self.assertEqual(res.get("status"), "ingested")
        state = runner._load_json(runner.state_path)
        self.assertIn("REQ-START-001", state.get("tasks", {}))

    def test_invalid_init_inputs(self) -> None:
        # Missing state.json
        r_empty = Runner(self.root)
        with self.assertRaises(ValidationError):
            r_empty.init()

        # Missing trusted-sources.json
        self._write_json("state.json", {"schema_version": 1})
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # Setup valid trusted source for base state mutations
        self._register_trusted_source(
            source_ref="SRC-BASE",
            actor="human",
            scope="migration",
            event_types=["submit_task"],
            proof_content={"actor": "human", "scope": "migration", "policy_id": "POL-BASE"},
            policy_id="POL-BASE",
        )

        valid_base = {
            "schema_version": 1,
            "generation": "m1-candidate",
            "mode": "shadow",
            "business_paused": True,
            "write_run_tools_enabled": False,
            "tasks": {},
            "processed_event_ids": {},
            "migration_authorization_id": "POL-BASE",
            "authorization_source_ref": "SRC-BASE",
            "active_owner": None,
            "migration_paused": False,
            "effective_pause_policy": None,
            "effective_migration_pause_policy": None,
            "roles": {},
        }

        # Invalid schema_version
        b = dict(valid_base, schema_version=2)
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # Invalid generation
        b = dict(valid_base, generation="legacy")
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # Invalid mode
        b = dict(valid_base, mode="active")
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # business_paused not True
        b = dict(valid_base, business_paused=False)
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # write_run_tools_enabled not False
        b = dict(valid_base, write_run_tools_enabled=True)
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # tasks not empty dict
        b = dict(valid_base, tasks={"REQ-1": {}})
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # processed_event_ids not empty
        b = dict(valid_base, processed_event_ids={"EVT-1": "hash"})
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # missing migration_authorization_id
        b = dict(valid_base)
        del b["migration_authorization_id"]
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

        # auth_source_ref not registered
        b = dict(valid_base, authorization_source_ref="SRC-UNREGISTERED")
        self._write_json("state.json", b)
        with self.assertRaises(LedgerCorruptionError):
            r_empty.init()

    def test_submit_task_validation(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        # Missing task_id in task contract
        evt_no_id = {
            "event_id": "EVT-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_no_id)

        # Empty task_id in task contract
        evt_empty_id = {
            "event_id": "EVT-SUB-002",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-002",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "   ", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_empty_id)

        # Forbidden shell key in task contract
        evt_shell = {
            "event_id": "EVT-SUB-003",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-003",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T-01", "allow_read_paths": [], "allow_write_paths": [], "shell": "/bin/sh"}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_shell)

        # Unsafe allow_read_paths traversal
        evt_bad_read = {
            "event_id": "EVT-SUB-004",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-004",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T-02", "allow_read_paths": ["../outside.txt"], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_bad_read)

        # Unsafe write_paths
        evt_bad_write = {
            "event_id": "EVT-SUB-005",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-005",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T-03", "allow_read_paths": [], "allow_write_paths": ["/abs/write"]}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_bad_write)

        # Contract specifies allow_write_paths relative safe lists must also be validated
        evt_bad_allow_write = {
            "event_id": "EVT-SUB-006",
            "event_type": "submit_task",
            "request_id": "REQ-SUB-006",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T-04", "allow_read_paths": [], "allow_write_paths": ["../escape"]}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_bad_allow_write)

    def test_approved_review_and_completion_with_proof(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate(evidence_files={"evidence/output.txt": "synthetic-test-evidence"})

        # Submit task
        sub_evt = {
            "event_id": "EVT-REV-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-REV-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-01", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt)

        # Register ChatGPT technical review source
        review_payload = {
            "request_id": "REQ-REV-001",
            "candidate": cand,
            "decision": "approve",
            "findings": [],
            "evidence_refs": ["evidence/output.txt"],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-SYNTH-GPT-REV",
            "scope": "migration",
        }
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-REV",
            actor="ChatGPT",
            scope="migration",
            event_types=["review_result"],
            proof_content={"decision": review_payload},
            request_id="REQ-REV-001",
            candidate=cand,
        )

        rev_evt = {
            "event_id": "EVT-REV-001",
            "event_type": "review_result",
            "request_id": "REQ-REV-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-REV",
            "payload": review_payload,
        }
        self._write_and_ingest(runner, rev_evt)

        # Complete task
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-COMP",
            actor="ChatGPT",
            scope="migration",
            event_types=["task_completed"],
            proof_content={
                "decision": review_payload,
                "request_id": "REQ-REV-001",
                "candidate": cand,
            },
            request_id="REQ-REV-001",
            candidate=cand,
        )
        comp_evt = {
            "event_id": "EVT-COMP-001",
            "event_type": "task_completed",
            "request_id": "REQ-REV-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-COMP",
            "payload": {"candidate": cand},
        }
        comp_res = self._write_and_ingest(runner, comp_evt)
        self.assertEqual(comp_res.get("status"), "ingested")

        state = runner._load_json(runner.state_path)
        task_rec = state["tasks"]["REQ-REV-001"]
        self.assertEqual(task_rec["completion_status"], "completed")
        self.assertEqual(task_rec["review_decision"], "approve")

    def test_reject_and_needs_evidence_lacking_files_cannot_complete(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        sub_evt = {
            "event_id": "EVT-REJ-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-REJ-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-REJ", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt)

        # Reject decision with empty evidence files accepted
        reject_payload = {
            "request_id": "REQ-REJ-001",
            "candidate": cand,
            "decision": "reject",
            "findings": ["Synthetic syntax error findings"],
            "evidence_refs": [],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-SYNTH-GPT-REJ",
            "scope": "migration",
        }
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-REJ",
            actor="ChatGPT",
            scope="migration",
            event_types=["review_result"],
            proof_content={"decision": reject_payload},
            request_id="REQ-REJ-001",
            candidate=cand,
        )
        rev_evt = {
            "event_id": "EVT-REJ-REV-001",
            "event_type": "review_result",
            "request_id": "REQ-REJ-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-REJ",
            "payload": reject_payload,
        }
        res = self._write_and_ingest(runner, rev_evt)
        self.assertEqual(res.get("status"), "ingested")

        # Attempting completion on rejected task must fail
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-COMP-FAIL",
            actor="ChatGPT",
            scope="migration",
            event_types=["task_completed"],
            proof_content={"decision": reject_payload},
            request_id="REQ-REJ-001",
            candidate=cand,
        )
        comp_evt = {
            "event_id": "EVT-COMP-FAIL-001",
            "event_type": "task_completed",
            "request_id": "REQ-REJ-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-COMP-FAIL",
            "payload": {"candidate": cand},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, comp_evt)

    def test_approval_missing_evidence_image_hash_fails(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        sub_evt = {
            "event_id": "EVT-APP-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-APP-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-APP", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt)

        # Approve missing evidence_refs entirely
        approve_no_evidence = {
            "request_id": "REQ-APP-001",
            "candidate": cand,
            "decision": "approve",
            "findings": [],
            "evidence_refs": [],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-SYNTH-GPT-APP1",
            "scope": "migration",
        }
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-APP1",
            actor="ChatGPT",
            scope="migration",
            event_types=["review_result"],
            proof_content={"decision": approve_no_evidence},
            request_id="REQ-APP-001",
            candidate=cand,
        )
        evt1 = {
            "event_id": "EVT-APP-REV-001",
            "event_type": "review_result",
            "request_id": "REQ-APP-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-APP1",
            "payload": approve_no_evidence,
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt1)

        # Agent visual review missing image files
        self._write_text("evidence/text.txt", "only text")
        cand_txt = self._make_candidate(evidence_files={"evidence/text.txt": "only text"})
        approve_no_image = {
            "request_id": "REQ-APP-001",
            "candidate": cand_txt,
            "decision": "approve",
            "findings": [],
            "evidence_refs": ["evidence/text.txt"],
            "review_kind": "agent_visual",
            "human_approval": False,
            "authorization_source_ref": "SRC-SYNTH-GPT-APP2",
            "scope": "migration",
        }
        self._register_trusted_source(
            source_ref="SRC-SYNTH-GPT-APP2",
            actor="ChatGPT",
            scope="migration",
            event_types=["review_result"],
            proof_content={"decision": approve_no_image, "screenshot_hashes": {}},
            request_id="REQ-APP-001",
            candidate=cand_txt,
        )
        evt2 = {
            "event_id": "EVT-APP-REV-002",
            "event_type": "review_result",
            "request_id": "REQ-APP-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-GPT-APP2",
            "payload": approve_no_image,
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt2)

    def test_actor_spoof_and_mismatch(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        # submit_task spoofed with ChatGPT source
        self._register_trusted_source(
            source_ref="SRC-SPOOF-GPT",
            actor="ChatGPT",
            scope="migration",
            event_types=["submit_task"],
            proof_content={"p": 1},
        )
        evt_spoof = {
            "event_id": "EVT-SPOOF-001",
            "event_type": "submit_task",
            "request_id": "REQ-SPOOF-001",
            "scope": "migration",
            "source_ref": "SRC-SPOOF-GPT",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-SPOOF", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_spoof)

        # review_result request_id mismatch with trusted source binding
        cand_rev = self._make_candidate()
        sub_evt = {
            "event_id": "EVT-MIS-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-MIS-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand_rev, "task": {"task_id": "TASK-MIS", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt)

        rev_payload = {
            "request_id": "REQ-MIS-001",
            "candidate": cand_rev,
            "decision": "reject",
            "findings": ["mismatch test"],
            "evidence_refs": [],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-GPT-MIS-REQ",
            "scope": "migration",
        }
        # Source bound to REQ-DIFFERENT
        self._register_trusted_source(
            source_ref="SRC-GPT-MIS-REQ",
            actor="ChatGPT",
            scope="migration",
            event_types=["review_result"],
            proof_content={"decision": rev_payload},
            request_id="REQ-DIFFERENT",
            candidate=cand_rev,
        )
        evt_mis_req = {
            "event_id": "EVT-MIS-REV-001",
            "event_type": "review_result",
            "request_id": "REQ-MIS-001",
            "scope": "migration",
            "source_ref": "SRC-GPT-MIS-REQ",
            "payload": rev_payload,
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_mis_req)

    def test_duplicate_id_harmless_and_projection_recovery(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()
        sub_evt = {
            "event_id": "EVT-DUP-001",
            "event_type": "submit_task",
            "request_id": "REQ-DUP-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-DUP", "allow_read_paths": [], "allow_write_paths": []}},
        }
        res1 = self._write_and_ingest(runner, sub_evt, "evt_dup.json")
        self.assertEqual(res1.get("status"), "ingested")

        # Corrupt state.json completely
        self._write_text("state.json", "{\"corrupted\": true}")

        # Re-ingest exact same event; returns harmless duplicate and recovers projection
        res2 = self._write_and_ingest(runner, sub_evt, "evt_dup.json")
        self.assertEqual(res2.get("status"), "duplicate")

        state = runner._load_json(runner.state_path)
        self.assertIn("REQ-DUP-001", state.get("tasks", {}))

    def test_conflict_duplicate_fails(self) -> None:
        runner = self._init_valid_migration()
        cand1 = self._make_candidate()
        sub_evt1 = {
            "event_id": "EVT-CONF-001",
            "event_type": "submit_task",
            "request_id": "REQ-CONF-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand1, "task": {"task_id": "TASK-CONF1", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt1, "conf1.json")

        # Same event_id with different candidate
        cand2 = self._make_candidate(content_hash="sha256:" + "f" * 64)
        sub_evt2 = {
            "event_id": "EVT-CONF-001",
            "event_type": "submit_task",
            "request_id": "REQ-CONF-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand2, "task": {"task_id": "TASK-CONF2", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(EventConflictError):
            self._write_and_ingest(runner, sub_evt2, "conf2.json")

    def test_historical_repeated_event_skips_and_conflicting_fails(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()
        evt = {
            "event_id": "EVT-HIST-001",
            "event_type": "submit_task",
            "request_id": "REQ-HIST-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-HIST", "allow_read_paths": [], "allow_write_paths": []}},
        }
        # Write identical event twice into ledger
        line = json.dumps(evt, ensure_ascii=False) + "\n"
        with open(runner.events_path, "w", encoding="utf-8") as f:
            f.write(line)
            f.write(line)

        # Recover must skip identical duplicate
        rec = runner.recover()
        self.assertEqual(rec.get("status"), "recovered")

        # Write conflicting event with same ID
        evt_conf = dict(evt, request_id="REQ-HIST-002")
        line_conf = json.dumps(evt_conf, ensure_ascii=False) + "\n"
        with open(runner.events_path, "a", encoding="utf-8") as f:
            f.write(line_conf)

        with self.assertRaises(EventConflictError):
            runner.recover()

    def test_revision_after_completion_resets_pending_and_review(self) -> None:
        runner = self._init_valid_migration()
        cand1 = self._make_candidate(evidence_files={"ev1.txt": "content1"})

        sub1 = {
            "event_id": "EVT-REV-S1",
            "event_type": "submit_task",
            "request_id": "REQ-REV-CYCLE",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand1, "task": {"task_id": "TASK-RC", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub1)

        rev1_payload = {
            "request_id": "REQ-REV-CYCLE",
            "candidate": cand1,
            "decision": "approve",
            "findings": [],
            "evidence_refs": ["ev1.txt"],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-GPT-RC1",
            "scope": "migration",
        }
        self._register_trusted_source(
            "SRC-GPT-RC1", "ChatGPT", "migration", ["review_result"],
            proof_content={"decision": rev1_payload}, request_id="REQ-REV-CYCLE", candidate=cand1
        )
        self._write_and_ingest(runner, {
            "event_id": "EVT-REV-R1", "event_type": "review_result", "request_id": "REQ-REV-CYCLE",
            "scope": "migration", "source_ref": "SRC-GPT-RC1", "payload": rev1_payload
        })

        self._register_trusted_source(
            "SRC-GPT-RCC1", "ChatGPT", "migration", ["task_completed"],
            proof_content={"decision": rev1_payload, "request_id": "REQ-REV-CYCLE", "candidate": cand1},
            request_id="REQ-REV-CYCLE", candidate=cand1
        )
        self._write_and_ingest(runner, {
            "event_id": "EVT-REV-C1", "event_type": "task_completed", "request_id": "REQ-REV-CYCLE",
            "scope": "migration", "source_ref": "SRC-GPT-RCC1", "payload": {"candidate": cand1}
        })

        # Now submit revision with candidate 2
        cand2 = self._make_candidate(content_hash="sha256:" + "e" * 64)
        sub2 = {
            "event_id": "EVT-REV-S2",
            "event_type": "submit_task",
            "request_id": "REQ-REV-CYCLE",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand2, "task": {"task_id": "TASK-RC", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub2)

        state = runner._load_json(runner.state_path)
        task_rec = state["tasks"]["REQ-REV-CYCLE"]
        self.assertEqual(task_rec["revision"], 2)
        self.assertEqual(task_rec["completion_status"], "pending")
        self.assertEqual(task_rec["review_status"], "NEEDS_REVIEW")
        self.assertIsNone(task_rec["review_decision"])

    def test_changed_contract_same_candidate_rejects_before_ledger(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        sub1 = {
            "event_id": "EVT-CTR-001",
            "event_type": "submit_task",
            "request_id": "REQ-CTR-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-CTR-A", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub1)

        sub2 = {
            "event_id": "EVT-CTR-002",
            "event_type": "submit_task",
            "request_id": "REQ-CTR-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-CTR-DIFFERENT", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, sub2)

        # Verify ledger was not appended
        ledger_events = runner._read_ledger()
        self.assertEqual(len(ledger_events), 1)

    def test_unknown_and_business_events_rejected(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate()

        evt_unknown = {
            "event_id": "EVT-UNK-001",
            "event_type": "arbitrary_event",
            "request_id": "REQ-UNK-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_unknown)

        evt_business = {
            "event_id": "EVT-BIZ-001",
            "event_type": "submit_task",
            "request_id": "REQ-BIZ-001",
            "scope": "business",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_business)

    def test_pause_scope_preserves_business_policy(self) -> None:
        runner = self._init_valid_migration()
        pause_evt = {
            "event_id": "EVT-PAUSE-001",
            "event_type": "pause",
            "request_id": "REQ-PAUSE-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"policy_id": "POL-SYNTH-MIG-001"},
        }
        self._write_and_ingest(runner, pause_evt)

        state = runner._load_json(runner.state_path)
        self.assertIs(state.get("migration_paused"), True)
        self.assertIs(state.get("business_paused"), True)
        self.assertEqual(state.get("effective_migration_pause_policy"), "POL-SYNTH-MIG-001")

        # Actions blocked while migration is paused
        cand = self._make_candidate()
        sub_blocked = {
            "event_id": "EVT-BLK-001",
            "event_type": "submit_task",
            "request_id": "REQ-BLK-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "T", "allow_read_paths": [], "allow_write_paths": []}},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, sub_blocked)

    def test_restart_reconstructs_state_status_audit(self) -> None:
        runner1 = self._init_valid_migration()
        cand = self._make_candidate()

        sub_evt = {
            "event_id": "EVT-RES-001",
            "event_type": "submit_task",
            "request_id": "REQ-RES-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-RES", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner1, sub_evt)

        # Instantiate separate runner on same root (simulating restart)
        runner2 = Runner(self.root)
        status_res = runner2.status()
        self.assertEqual(status_res.get("status"), "ok")
        self.assertEqual(status_res.get("event_count"), 1)

        state = runner2._load_json(runner2.state_path)
        self.assertIn("REQ-RES-001", state.get("tasks", {}))

        init_res = runner2.init()
        self.assertEqual(init_res.get("status"), "initialized")
        status_res = runner2.status()
        self.assertEqual(status_res.get("event_count"), 1)
        state = runner2._load_json(runner2.state_path)
        self.assertIn("REQ-RES-001", state.get("tasks", {}))

    def test_reject_approve_two_audits_no_orphan_truncated_visible(self) -> None:
        runner = self._init_valid_migration()
        cand = self._make_candidate(evidence_files={"ev.txt": "evidence"})

        sub_evt = {
            "event_id": "EVT-AUD-SUB-001",
            "event_type": "submit_task",
            "request_id": "REQ-AUD-001",
            "scope": "migration",
            "source_ref": "SRC-SYNTH-HUMAN-AUTH",
            "payload": {"candidate": cand, "task": {"task_id": "TASK-AUD", "allow_read_paths": [], "allow_write_paths": []}},
        }
        self._write_and_ingest(runner, sub_evt)

        # First review: reject
        rej_payload = {
            "request_id": "REQ-AUD-001",
            "candidate": cand,
            "decision": "reject",
            "findings": ["fix needed"],
            "evidence_refs": [],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-AUD-REJ",
            "scope": "migration",
        }
        self._register_trusted_source(
            "SRC-AUD-REJ", "ChatGPT", "migration", ["review_result"],
            proof_content={"decision": rej_payload}, request_id="REQ-AUD-001", candidate=cand
        )
        self._write_and_ingest(runner, {
            "event_id": "EVT-AUD-REV-1", "event_type": "review_result", "request_id": "REQ-AUD-001",
            "scope": "migration", "source_ref": "SRC-AUD-REJ", "payload": rej_payload
        })

        # Second review: approve on same candidate
        app_payload = {
            "request_id": "REQ-AUD-001",
            "candidate": cand,
            "decision": "approve",
            "findings": [],
            "evidence_refs": ["ev.txt"],
            "review_kind": "technical",
            "human_approval": False,
            "authorization_source_ref": "SRC-AUD-APP",
            "scope": "migration",
        }
        self._register_trusted_source(
            "SRC-AUD-APP", "ChatGPT", "migration", ["review_result"],
            proof_content={"decision": app_payload}, request_id="REQ-AUD-001", candidate=cand
        )
        self._write_and_ingest(runner, {
            "event_id": "EVT-AUD-REV-2", "event_type": "review_result", "request_id": "REQ-AUD-001",
            "scope": "migration", "source_ref": "SRC-AUD-APP", "payload": app_payload
        })

        decisions, _ = runner._read_existing_decisions()
        self.assertEqual(len(decisions), 2)

        # Orphan decision injected into decisions.jsonl
        orphan_record = {
            "event_id": "EVT-ORPHAN",
            "decision": "approve",
            "request_id": "REQ-AUD-001",
        }
        with open(runner.decisions_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(orphan_record) + "\n")

        with self.assertRaises(LedgerCorruptionError):
            runner.recover()

        # Truncated line in events ledger
        with open(runner.events_path, "a", encoding="utf-8") as f:
            f.write("{\"truncated_event\": true")

        with self.assertRaises(LedgerCorruptionError):
            runner.recover()

    def test_bind_roles_validation(self) -> None:
        runner = self._init_valid_migration()

        # Missing required role 'acceptance'
        roles_missing = {
            "overview": {"thread_id": "TH-01", "status": "candidate"},
            "approval": {"thread_id": "TH-02", "status": "candidate"},
        }
        self._register_trusted_source(
            "SRC-ROLE-MISS", "human", "migration", ["bind_roles"],
            proof_content={"roles": roles_missing, "verified_roles": {"overview": "TH-01", "approval": "TH-02"}}
        )
        evt_miss = {
            "event_id": "EVT-ROLE-001",
            "event_type": "bind_roles",
            "request_id": "REQ-ROLE-001",
            "scope": "migration",
            "source_ref": "SRC-ROLE-MISS",
            "payload": {"roles": roles_missing},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_miss)

        # Duplicate thread_ids across roles
        roles_dup = {
            "overview": {"thread_id": "TH-SAME", "status": "candidate"},
            "approval": {"thread_id": "TH-SAME", "status": "candidate"},
            "acceptance": {"thread_id": "TH-03", "status": "candidate"},
        }
        self._register_trusted_source(
            "SRC-ROLE-DUP", "human", "migration", ["bind_roles"],
            proof_content={
                "roles": roles_dup,
                "verified_roles": {"overview": "TH-SAME", "approval": "TH-SAME", "acceptance": "TH-03"},
            }
        )
        evt_dup = {
            "event_id": "EVT-ROLE-002",
            "event_type": "bind_roles",
            "request_id": "REQ-ROLE-002",
            "scope": "migration",
            "source_ref": "SRC-ROLE-DUP",
            "payload": {"roles": roles_dup},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_dup)

        # Proof verified_roles mismatch
        roles_valid = {
            "overview": {"thread_id": "TH-01", "status": "candidate"},
            "approval": {"thread_id": "TH-02", "status": "candidate"},
            "acceptance": {"thread_id": "TH-03", "status": "candidate"},
        }
        self._register_trusted_source(
            "SRC-ROLE-MISPROOF", "human", "migration", ["bind_roles"],
            proof_content={
                "roles": roles_valid,
                "verified_roles": {"overview": "TH-WRONG", "approval": "TH-02", "acceptance": "TH-03"},
            }
        )
        evt_misproof = {
            "event_id": "EVT-ROLE-003",
            "event_type": "bind_roles",
            "request_id": "REQ-ROLE-003",
            "scope": "migration",
            "source_ref": "SRC-ROLE-MISPROOF",
            "payload": {"roles": roles_valid},
        }
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, evt_misproof)

    def _setup_cutover_environment(self, runner: Runner) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        # 1. Bind roles
        roles_data = {
            "overview": {"thread_id": "TH-OV", "status": "candidate"},
            "approval": {"thread_id": "TH-AP", "status": "candidate"},
            "acceptance": {"thread_id": "TH-AC", "status": "candidate"},
        }
        self._register_trusted_source(
            "SRC-CUT-ROLES", "human", "migration", ["bind_roles"],
            proof_content={
                "roles": roles_data,
                "verified_roles": {"overview": "TH-OV", "approval": "TH-AP", "acceptance": "TH-AC"},
            }
        )
        self._write_and_ingest(runner, {
            "event_id": "EVT-CUT-BIND", "event_type": "bind_roles", "request_id": "REQ-CUT-BIND",
            "scope": "migration", "source_ref": "SRC-CUT-ROLES", "payload": {"roles": roles_data}
        })

        # 2. Setup V05 native proof
        native_proof_content = {
            "native_wrapper": "codex sandbox",
            "results": {
                "read_allowed": "PASS",
                "write_allowed": "PASS",
                "read_outside_denied": "PASS",
                "write_outside_denied": "PASS",
                "private_read_denied": "PASS",
                "network_denied": "PASS",
                "child_read_outside_denied": "PASS",
                "child_write_outside_denied": "PASS",
                "child_network_denied": "PASS",
            },
        }
        self._write_json("proofs/v05_native.json", native_proof_content)
        v05_native_hash = compute_file_sha256(os.path.join(self.root, "proofs/v05_native.json"))

        # 3. Setup gates V01-V09
        gates_payload: Dict[str, Any] = {}
        for i in range(1, 10):
            gid = f"V0{i}"
            g_data: Dict[str, Any] = {
                "gate_id": gid,
                "status": "PASS",
                "reviewer": "ChatGPT",
            }
            if gid == "V05":
                g_data["native_proof_ref"] = "proofs/v05_native.json"
                g_data["native_proof_hash"] = v05_native_hash

            g_path = f"gates/{gid}.json"
            self._write_json(g_path, g_data)
            g_hash = compute_file_sha256(os.path.join(self.root, g_path))

            src_ref = f"SRC-GATE-{gid}"
            self._register_trusted_source(
                src_ref, "ChatGPT", "migration", ["cutover_gate"],
                proof_content={"gate": g_data, "gate_artifact_hash": g_hash}
            )
            gates_payload[gid] = {
                "ref": g_path,
                "sha256": g_hash,
                "source_ref": src_ref,
                "status": "PASS",
            }
        return roles_data, gates_payload

    def test_gate_validations_and_valid_cutover(self) -> None:
        runner = self._init_valid_migration(policy_id="POL-CUTOVER")
        _, gates_payload = self._setup_cutover_environment(runner)

        cutover_payload = {"gates": gates_payload}
        self._register_trusted_source(
            "SRC-CUTOVER-AUTH", "human", "migration", ["cutover"],
            proof_content={"cutover_payload": cutover_payload},
            policy_id="POL-CUTOVER",
        )

        # Gate boolean forgery: status = True instead of 'PASS'
        bad_gates = dict(gates_payload)
        bad_gates["V01"] = dict(bad_gates["V01"], status=True)
        with self.assertRaises(ValidationError):
            self._write_and_ingest(runner, {
                "event_id": "EVT-CUT-BAD1", "event_type": "cutover", "request_id": "REQ-CUT-01",
                "scope": "migration", "source_ref": "SRC-CUTOVER-AUTH",
                "payload": {"gates": bad_gates}
            })

        # Valid cutover ingests and switches state to active
        res = self._write_and_ingest(runner, {
            "event_id": "EVT-CUT-VALID", "event_type": "cutover", "request_id": "REQ-CUT-02",
            "scope": "migration", "source_ref": "SRC-CUTOVER-AUTH",
            "payload": cutover_payload
        })
        self.assertEqual(res.get("status"), "ingested")

        state = runner._load_json(runner.state_path)
        self.assertEqual(state.get("generation"), "m1-active")
        self.assertEqual(state.get("mode"), "active")
        self.assertEqual(state.get("active_owner"), "runner")
        self.assertIs(state.get("business_paused"), True)

    def test_lock_contention(self) -> None:
        lock_path = os.path.join(self.local_dir, "runner_test.lock")
        lock1 = FileLock(lock_path)
        lock1.acquire()
        try:
            lock2 = FileLock(lock_path)
            with self.assertRaises(LockAcquisitionError):
                lock2.acquire()
        finally:
            lock1.release()

        # Successfully acquire after release
        lock2.acquire()
        lock2.release()

    def test_public_path_security(self) -> None:
        # Absolute paths rejected
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "/etc/passwd")

        # Traversal rejected
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "../escape.txt")
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "sub/../../escape.txt")

        # .local references rejected
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, ".local/trusted-sources.json")
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "sub/.local/secret.txt")

        # Backslash rejected
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "sub\\file.txt")

        # Colons rejected in public references
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "file:stream")
        with self.assertRaises(ValidationError):
            assert_safe_public_path(self.root, "C:file.txt")

    def test_symlink_escape(self) -> None:
        outside_target = os.path.abspath(os.path.join(self.root, ".."))
        symlink_path = os.path.join(self.root, "symlink_leak")
        try:
            os.symlink(outside_target, symlink_path)
            symlink_created = True
        except (OSError, NotImplementedError, AttributeError):
            symlink_created = False

        if symlink_created:
            with self.assertRaises(ValidationError):
                assert_safe_public_path(self.root, "symlink_leak/secret.txt")

    def test_static_ast_no_model_or_network_calls(self) -> None:
        runner_file = os.path.join(PROJECT_ROOT, "runner.py")
        with open(runner_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename="runner.py")

        banned_modules = {
            "aiohttp", "anthropic", "http", "langchain", "openai",
            "requests", "socket", "subprocess", "torch", "transformers", "urllib"
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    self.assertNotIn(root_mod, banned_modules, f"Banned module imported: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    self.assertNotIn(root_mod, banned_modules, f"Banned module imported: {node.module}")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"eval", "exec"}, f"Banned execution call: {node.func.id}")
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, {"Popen", "call", "check_output"}, f"Banned subprocess call: {node.func.attr}")


if __name__ == "__main__":
    unittest.main()
