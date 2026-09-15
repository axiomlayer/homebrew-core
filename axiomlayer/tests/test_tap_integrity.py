from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "verify_tap_integrity.py"
REPOSITORY_ROOT = MODULE_PATH.parents[1]
WORKFLOW_SOURCE = (
    REPOSITORY_ROOT / ".github" / "workflows" / "axiomlayer-tap-integrity.yml"
)
POLICY_SOURCE = REPOSITORY_ROOT / "axiomlayer" / "tap-integrity-policy.json"
SPEC = importlib.util.spec_from_file_location("verify_tap_integrity", MODULE_PATH)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class PolicyInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_duplicate_json_object_key_is_refused(self) -> None:
        policy = self.root / "policy.json"
        policy.write_text('{"schema":"first","schema":"second"}\n', encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "duplicate"):
            VERIFIER.read_json(policy)

    def test_symlinked_policy_is_refused(self) -> None:
        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        policy = self.root / "policy.json"
        policy.symlink_to(target)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "non-symlink"):
            VERIFIER.read_json(policy)

    def test_cli_does_not_resolve_away_policy_symlink(self) -> None:
        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        policy = self.root / "policy.json"
        policy.symlink_to(target)
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--policy",
                str(policy),
                "baseline",
                "--repo",
                str(self.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)

    def test_complete_checked_policy_is_accepted(self) -> None:
        policy = VERIFIER.read_json(POLICY_SOURCE)
        VERIFIER.validate_policy(policy)
        VERIFIER.verify_verifier_identity(policy)

    def test_verifier_byte_drift_is_refused(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["workflowPolicy"]["verifierSha256"] = "0" * 64
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "verifier digest"):
            VERIFIER.verify_verifier_identity(policy)

    def test_ignored_policy_extension_is_refused(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["unreviewedExtension"] = True
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "fields drifted"):
            VERIFIER.validate_policy(policy)

    def test_canary_runner_architecture_remap_is_refused(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["canary"]["surfaces"][0]["runner"] = "ubuntu-24.04-arm"
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "mapping drifted"):
            VERIFIER.validate_policy(policy)

    def test_active_cask_cannot_opt_into_no_check(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["caskAudit"]["definitions"][0]["allowNoCheck"] = True
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "must require"):
            VERIFIER.validate_policy(policy)

    def test_bootstrap_cannot_require_terminal_check_before_canary(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["workflowPolicy"]["rulesetBootstrap"]["phaseOne"][
            "requiredStatusChecks"
        ] = ["Required tap integrity authority"]
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "two-phase"):
            VERIFIER.validate_policy(policy)

    def test_final_ruleset_must_require_terminal_check(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        policy["workflowPolicy"]["rulesetBootstrap"]["phaseTwo"][
            "requiredStatusChecks"
        ] = []
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "two-phase"):
            VERIFIER.validate_policy(policy)

    def test_normalization_inventory_cannot_expand_implicitly(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        extra = copy.deepcopy(policy["formulaAudit"]["normalizedSources"][-1])
        extra["path"] = "Formula/z/zlib.rb"
        policy["formulaAudit"]["normalizedSources"].append(extra)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "inventory"):
            VERIFIER.validate_policy(policy)

    def test_only_reviewed_formula_paths_are_in_the_integration_lane(self) -> None:
        policy = copy.deepcopy(json.loads(POLICY_SOURCE.read_text(encoding="utf-8")))
        self.assertTrue(VERIFIER.allowed_integration_path("Formula/b/bash.rb", policy))
        self.assertFalse(VERIFIER.allowed_integration_path("Formula/z/zlib.rb", policy))


class GitIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        VERIFIER.git(self.root, "init")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_git_commands_ignore_global_and_environment_config(self) -> None:
        attacker_home = self.root / "attacker-home"
        attacker_home.mkdir()
        (attacker_home / ".gitconfig").write_text(
            "[credential]\n\thelper = unsafe-helper\n", encoding="utf-8"
        )
        injected = {
            "HOME": str(attacker_home),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": "AUTHORIZATION: bearer not-a-real-token",
            "GIT_ASKPASS": "/tmp/unsafe-askpass",
            "SSH_ASKPASS": "/tmp/unsafe-ssh-askpass",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            helper = VERIFIER.git(
                self.root, "config", "--get", "credential.helper", check=False
            )
            header = VERIFIER.git(
                self.root,
                "config",
                "--get",
                "http.https://github.com/.extraheader",
                check=False,
            )
        self.assertNotEqual(helper.returncode, 0)
        self.assertEqual(helper.stdout, "")
        self.assertNotEqual(header.returncode, 0)
        self.assertEqual(header.stdout, "")

    def test_remote_ref_lookup_receives_the_isolated_environment(self) -> None:
        completed = VERIFIER.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"{'a' * 40}\trefs/heads/main\n",
            stderr="",
        )
        with mock.patch.object(
            VERIFIER.subprocess, "run", return_value=completed
        ) as run:
            result = VERIFIER.git_remote_refs(
                "https://github.com/example/project.git", ["refs/heads/main"]
            )
        environment = run.call_args.kwargs["env"]
        self.assertEqual(result, {"refs/heads/main": "a" * 40})
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertNotIn("GIT_ASKPASS", environment)


class ProvenanceTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repository(self, name: str) -> Path:
        repo = self.root / name
        repo.mkdir()
        VERIFIER.git(repo, "init", "-b", "main")
        VERIFIER.git(repo, "config", "user.name", "Provenance Fixture")
        VERIFIER.git(repo, "config", "user.email", "fixture@example.invalid")
        return repo

    def commit(self, repo: Path, message: str) -> str:
        VERIFIER.git(repo, "commit", "--allow-empty", "--no-gpg-sign", "-m", message)
        return VERIFIER.git_output(repo, "rev-parse", "HEAD")

    def test_dynamic_history_reaches_commit_beyond_initial_shallow_window(self) -> None:
        upstream = self.repository("deep-upstream")
        deep_commit = self.commit(upstream, "deep provenance root")
        for index in range(140):
            self.commit(upstream, f"history {index:03d}")
        expected_tree = VERIFIER.git_output(
            upstream, "rev-parse", f"{deep_commit}^{{tree}}"
        )
        VERIFIER.verify_commit_on_remote_ref(
            upstream.as_uri(),
            "refs/heads/main",
            deep_commit,
            expected_tree,
            "deep fixture candidate",
        )

    def test_newer_candidate_is_independent_of_premerge_fork_main(self) -> None:
        upstream = self.repository("upstream")
        base = self.commit(upstream, "protected fork base")
        source = upstream / "Formula" / "a" / "alpha.rb"
        source.parent.mkdir(parents=True)
        source.write_text("class Alpha < Formula\nend\n", encoding="utf-8")
        VERIFIER.git(upstream, "add", "Formula/a/alpha.rb")
        VERIFIER.git(
            upstream, "commit", "--no-gpg-sign", "-m", "new upstream candidate"
        )
        candidate = VERIFIER.git_output(upstream, "rev-parse", "HEAD")
        candidate_tree = VERIFIER.git_output(upstream, "rev-parse", "HEAD^{tree}")

        checkout = self.root / "checkout"
        VERIFIER.git(self.root, "clone", upstream.as_uri(), str(checkout))
        VERIFIER.git(checkout, "config", "user.name", "Provenance Fixture")
        VERIFIER.git(checkout, "config", "user.email", "fixture@example.invalid")
        VERIFIER.git(checkout, "checkout", "-b", "candidate-integration", candidate)
        policy_lane = checkout / "axiomlayer" / "policy.txt"
        policy_lane.parent.mkdir()
        policy_lane.write_text("reviewed integration\n", encoding="utf-8")
        VERIFIER.git(checkout, "add", "axiomlayer/policy.txt")
        VERIFIER.git(checkout, "commit", "--no-gpg-sign", "-m", "candidate integration")
        VERIFIER.git(checkout, "checkout", "-B", "main", base)
        VERIFIER.git(
            checkout,
            "merge",
            "--no-ff",
            "--no-gpg-sign",
            "candidate-integration",
            "-m",
            "pull request merge fixture",
        )

        VERIFIER.verify_commit_on_remote_ref(
            upstream.as_uri(),
            "refs/heads/main",
            candidate,
            candidate_tree,
            "newer fixture candidate",
        )
        VERIFIER.verify_checkout_base(checkout, base)
        with self.assertRaisesRegex(
            VERIFIER.IntegrityViolation, "not based on current protected"
        ):
            VERIFIER.verify_checkout_base(checkout, candidate)
        self.assertTrue(
            VERIFIER.commit_is_ancestor(
                checkout, candidate, VERIFIER.git_output(checkout, "rev-parse", "HEAD")
            )
        )
        self.assertNotEqual(candidate, base)


class ConsumerAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        tracked = self.root / "config" / "device.json"
        tracked.parent.mkdir(parents=True)
        tracked.write_text('{"device":"fixture"}\n', encoding="utf-8")
        VERIFIER.git(self.root, "init")
        VERIFIER.git(self.root, "config", "user.name", "Consumer Fixture")
        VERIFIER.git(self.root, "config", "user.email", "fixture@example.invalid")
        VERIFIER.git(self.root, "add", "config/device.json")
        VERIFIER.git(self.root, "commit", "--no-gpg-sign", "-m", "fixture")
        data = tracked.read_bytes()
        self.anchor = {
            "blob": VERIFIER.git_blob_id(data),
            "sha256": VERIFIER.sha256_bytes(data),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_symlinked_consumer_anchor_is_refused_even_with_identical_bytes(
        self,
    ) -> None:
        tracked = self.root / "config" / "device.json"
        witness = self.root / "config" / "witness.json"
        witness.write_bytes(tracked.read_bytes())
        tracked.unlink()
        tracked.symlink_to(witness.name)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "contains a symlink"):
            VERIFIER.verify_file_anchor(
                self.root, "config/device.json", self.anchor, "fixture"
            )


class FormulaAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "Aliases").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def formula(self, name: str, body: str) -> None:
        destination = self.root / "Formula" / name[0] / f"{name}.rb"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")

    def valid_formula(self, name: str, dependency: str | None = None) -> str:
        dependency_line = f'  depends_on "{dependency}"\n' if dependency else ""
        return (
            f"class {name.title()} < Formula\n"
            f'  url "https://example.invalid/{name}.tar.gz"\n'
            f'  sha256 "{"a" * 64}"\n'
            f"{dependency_line}"
            "end\n"
        )

    def test_recursive_closure_is_audited(self) -> None:
        self.formula("alpha", self.valid_formula("alpha", "beta"))
        self.formula("beta", self.valid_formula("beta"))
        result = VERIFIER.audit_formula_closure(self.root, ["alpha"])
        self.assertEqual(result["formulae"], ["alpha", "beta"])
        self.assertEqual(result["formulaCount"], 2)

    def test_ripper_captures_supported_dependency_call_forms(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/alpha.tar.gz"\n'
                f'  sha256 "{"a" * 64}"\n'
                '  depends_on("beta")\n'
                "  depends_on(\n"
                '    "gamma",\n'
                "  )\n"
                '  depends_on "delta" => :build\n'
                '  uses_from_macos("zlib")\n'
                "end\n"
            ),
        )
        for dependency in ("beta", "gamma", "delta"):
            self.formula(dependency, self.valid_formula(dependency))
        result = VERIFIER.audit_formula_closure(self.root, ["alpha"])
        self.assertEqual(result["formulae"], ["alpha", "beta", "delta", "gamma"])
        self.assertEqual(result["systemDependencies"], ["zlib"])

    def test_dependency_text_and_receiver_calls_do_not_enter_closure(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/alpha.tar.gz"\n'
                f'  sha256 "{"a" * 64}"\n'
                "  description = <<~TEXT\n"
                '    depends_on "heredoc-missing"\n'
                "  TEXT\n"
                '  note = %q(depends_on "string-missing")\n'
                '  # depends_on "comment-missing"\n'
                '  helper.depends_on "receiver-missing"\n'
                "end\n"
            ),
        )
        result = VERIFIER.audit_formula_closure(self.root, ["alpha"])
        self.assertEqual(result["formulae"], ["alpha"])

    def test_heredoc_dependency_argument_fails_closed(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/alpha.tar.gz"\n'
                f'  sha256 "{"a" * 64}"\n'
                "  depends_on <<~NAME\n"
                "    missing\n"
                "  NAME\n"
                "end\n"
            ),
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "dynamic depends_on"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_missing_dependency_fails_closed(self) -> None:
        self.formula("alpha", self.valid_formula("alpha", "missing"))
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "missing formula"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_no_check_fails_closed(self) -> None:
        self.formula(
            "alpha",
            'class Alpha < Formula\n  url "https://example.invalid/a.tar.gz"\n  sha256 :no_check\nend\n',
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "no_check"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_parenthesized_no_check_fails_closed(self) -> None:
        self.formula(
            "alpha",
            'class Alpha < Formula\n  url "https://example.invalid/a.tar.gz"\n  sha256(:no_check)\nend\n',
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "no_check"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_malformed_digest_fails_closed(self) -> None:
        self.formula(
            "alpha",
            'class Alpha < Formula\n  url "https://example.invalid/a.tar.gz"\n  sha256 "bad"\nend\n',
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "malformed"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_formula_heredoc_comment_and_string_cannot_supply_digest(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/a.tar.gz"\n'
                "  description = <<~TEXT\n"
                f'    sha256 "{"f" * 64}"\n'
                "  TEXT\n"
                f'  note = %q(sha256 "{"e" * 64}")\n'
                f'  # sha256 "{"d" * 64}"\n'
                f'  helper.sha256 "{"c" * 64}"\n'
                "end\n"
            ),
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "no declared"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_multiline_parenthesized_formula_digest_is_accepted(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                "  url(\n"
                '    "https://example.invalid/a.tar.gz",\n'
                "  )\n"
                "  sha256(\n"
                f'    "{"a" * 64}",\n'
                "  )\n"
                "end\n"
            ),
        )
        result = VERIFIER.audit_formula_closure(self.root, ["alpha"])
        self.assertEqual(result["integrityDeclarations"], 1)

    def test_dynamic_checksum_forms_fail_closed(self) -> None:
        dynamic_forms = {
            "nil": "nil",
            "environment": 'ENV["UNPINNED_SHA"]',
            "interpolation": '"#{ENV["UNPINNED_SHA"]}"',
            "nested call": f'pick("{"a" * 64}")',
        }
        for name, expression in dynamic_forms.items():
            with self.subTest(name=name):
                self.formula(
                    "alpha",
                    (
                        "class Alpha < Formula\n"
                        '  url "https://example.invalid/a.tar.gz"\n'
                        f"  sha256 {expression}\n"
                        "end\n"
                    ),
                )
                with self.assertRaisesRegex(
                    VERIFIER.IntegrityViolation, "dynamic or malformed sha256"
                ):
                    VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_exact_architecture_checksum_map_is_accepted(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/a.tar.gz"\n'
                f'  sha256 arm: "{"a" * 64}",\n'
                f'         intel: "{"b" * 64}"\n'
                "end\n"
            ),
        )
        result = VERIFIER.audit_formula_closure(self.root, ["alpha"])
        self.assertEqual(result["integrityDeclarations"], 2)

    def test_incomplete_or_dynamic_checksum_map_fails_closed(self) -> None:
        forms = {
            "missing architecture": f'arm: "{"a" * 64}"',
            "extra architecture": (
                f'arm: "{"a" * 64}", intel: "{"b" * 64}", linux: "{"c" * 64}"'
            ),
            "dynamic value": f'arm: "{"a" * 64}", intel: ENV["SHA"]',
        }
        for name, arguments in forms.items():
            with self.subTest(name=name):
                self.formula(
                    "alpha",
                    (
                        "class Alpha < Formula\n"
                        '  url "https://example.invalid/a.tar.gz"\n'
                        f"  sha256 {arguments}\n"
                        "end\n"
                    ),
                )
                with self.assertRaises(VERIFIER.IntegrityViolation):
                    VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_exact_upstream_blob_uses_reviewed_literal_normalization(self) -> None:
        raw = (
            "class Alpha < Formula\n"
            '  url "https://example.invalid/a.tar.gz"\n'
            '  sha256 checksums["arm"]\n'
            "end\n"
        ).encode()
        normalized = (
            "class Alpha < Formula\n"
            '  url "https://example.invalid/a.tar.gz"\n'
            f'  sha256 "{"a" * 64}"\n'
            "end\n"
        ).encode()
        self.formula("alpha", raw.decode())
        normalization_root = self.root / "reviewed"
        normalized_path = normalization_root / "Formula" / "a" / "alpha.rb"
        normalized_path.parent.mkdir(parents=True)
        normalized_path.write_bytes(normalized)
        policy = {
            "formulaAudit": {
                "normalizedSources": [
                    {
                        "path": "Formula/a/alpha.rb",
                        "upstreamBlob": VERIFIER.git_blob_id(raw),
                        "normalizedBlob": VERIFIER.git_blob_id(normalized),
                        "sha256": VERIFIER.sha256_bytes(normalized),
                    }
                ]
            }
        }
        result = VERIFIER.audit_formula_closure(
            self.root,
            ["alpha"],
            policy=policy,
            normalization_root=normalization_root,
        )
        self.assertEqual(result["integrityDeclarations"], 1)

    def test_changed_upstream_blob_cannot_inherit_normalization(self) -> None:
        raw = (
            "class Alpha < Formula\n"
            '  url "https://example.invalid/a.tar.gz"\n'
            '  sha256 checksums["arm"]\n'
            "end\n"
        ).encode()
        normalized = (
            "class Alpha < Formula\n"
            '  url "https://example.invalid/a.tar.gz"\n'
            f'  sha256 "{"a" * 64}"\n'
            "end\n"
        ).encode()
        self.formula("alpha", (raw + b"# upstream drift\n").decode())
        normalization_root = self.root / "reviewed"
        normalized_path = normalization_root / "Formula" / "a" / "alpha.rb"
        normalized_path.parent.mkdir(parents=True)
        normalized_path.write_bytes(normalized)
        policy = {
            "formulaAudit": {
                "normalizedSources": [
                    {
                        "path": "Formula/a/alpha.rb",
                        "upstreamBlob": VERIFIER.git_blob_id(raw),
                        "normalizedBlob": VERIFIER.git_blob_id(normalized),
                        "sha256": VERIFIER.sha256_bytes(normalized),
                    }
                ]
            }
        }
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "new reviewed"):
            VERIFIER.audit_formula_closure(
                self.root,
                ["alpha"],
                policy=policy,
                normalization_root=normalization_root,
            )

    def test_resource_hash_cannot_cover_unpinned_primary_source(self) -> None:
        self.formula(
            "alpha",
            (
                "class Alpha < Formula\n"
                '  url "https://example.invalid/alpha.tar.gz"\n'
                '  resource "helper" do\n'
                '    url "https://example.invalid/helper.tar.gz"\n'
                f'    sha256 "{"f" * 64}"\n'
                "  end\n"
                "end\n"
            ),
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "without declared"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_direct_formula_symlink_is_refused(self) -> None:
        outside = self.root / "outside.rb"
        outside.write_text(self.valid_formula("alpha"), encoding="utf-8")
        destination = self.root / "Formula" / "a" / "alpha.rb"
        destination.parent.mkdir(parents=True)
        destination.symlink_to(outside)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "symlink"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_formula_shard_symlink_is_refused(self) -> None:
        outside = self.root / "outside-shard"
        outside.mkdir()
        (outside / "alpha.rb").write_text(self.valid_formula("alpha"), encoding="utf-8")
        formula_root = self.root / "Formula"
        formula_root.mkdir()
        (formula_root / "a").symlink_to(outside)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "contains a symlink"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_formula_root_symlink_is_refused(self) -> None:
        outside = self.root / "outside-formula"
        (outside / "a").mkdir(parents=True)
        (outside / "a" / "alpha.rb").write_text(
            self.valid_formula("alpha"), encoding="utf-8"
        )
        (self.root / "Formula").symlink_to(outside)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "Formula root"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_formula_alias_escape_is_refused(self) -> None:
        outside = self.root / "outside-alias.rb"
        outside.write_text(self.valid_formula("alpha"), encoding="utf-8")
        (self.root / "Formula").mkdir()
        alias = self.root / "Aliases" / "alpha"
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(outside)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "escapes Formula"):
            VERIFIER.audit_formula_closure(self.root, ["alpha"])

    def test_formula_metadata_audit_does_not_execute_class_body(self) -> None:
        proof = self.root / "formula-class-body-proof"
        body = (
            "class Alpha < Formula\n"
            '  url "https://example.invalid/alpha.tar.gz"\n'
            f'  sha256 "{"a" * 64}"\n'
            f"  File.write({str(proof)!r}, 'executed')\n"
            "  def install\n"
            "  end\n"
            "end\n"
        )
        self.formula("alpha", body)
        VERIFIER.audit_formula_closure(self.root, ["alpha"])
        result = VERIFIER.audit_representative_formulae(self.root, ["alpha"])
        self.assertFalse(result[0]["rubySourceExecuted"])
        self.assertFalse(proof.exists())


class CaskAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def definition(
        self, data: bytes, *, allow_no_check: bool = False
    ) -> dict[str, object]:
        return {
            "name": "sample",
            "path": "Casks/s/sample.rb",
            "blob": VERIFIER.git_blob_id(data),
            "sha256": VERIFIER.sha256_bytes(data),
            "disposition": "deferred" if allow_no_check else "active",
            "minimumDeclaredSha256": 0 if allow_no_check else 1,
            "allowNoCheck": allow_no_check,
        }

    def test_active_cask_requires_declared_hash(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 "{"b" * 64}"\n'
            "end\n"
        ).encode()
        result = VERIFIER.validate_cask_definition(
            data, self.definition(data), self.root
        )
        self.assertFalse(result["noCheck"])

    def test_active_cask_refuses_no_check(self) -> None:
        data = b'cask "sample" do\n  url "https://example.invalid/sample.zip"\n  sha256 :no_check\nend\n'
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "no_check"):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_parenthesized_cask_no_check_is_refused(self) -> None:
        data = b'cask "sample" do\n  url "https://example.invalid/sample.zip"\n  sha256(:no_check)\nend\n'
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "no_check"):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_unrelated_hex_literal_is_not_a_declared_sha256(self) -> None:
        data = (
            'cask "sample" do\n'
            f'  version "{"e" * 64}"\n'
            '  url "https://example.invalid/sample.zip"\n'
            "end\n"
        ).encode()
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "too few"):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_cask_heredoc_cannot_supply_digest(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            "  caveats <<~TEXT\n"
            f'    sha256 "{"f" * 64}"\n'
            "  TEXT\n"
            "end\n"
        ).encode()
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "too few"):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_cask_comment_and_string_cannot_supply_digest(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  caveats %q(sha256 "{"e" * 64}")\n'
            f'  # sha256 "{"f" * 64}"\n'
            "end\n"
        ).encode()
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "too few"):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_conditional_multiline_cask_digests_are_accepted(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            "  on_arm do\n"
            "    sha256(\n"
            f'      "{"a" * 64}",\n'
            "    )\n"
            "  end\n"
            "  on_intel do\n"
            f'    sha256 "{"b" * 64}"\n'
            "  end\n"
            "end\n"
        ).encode()
        definition = self.definition(data)
        definition["minimumDeclaredSha256"] = 2
        result = VERIFIER.validate_cask_definition(data, definition, self.root)
        self.assertEqual(result["declaredSha256"], 2)

    def test_cask_architecture_checksum_map_is_exhaustively_validated(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 arm: "{"a" * 64}",\n'
            f'         intel: "{"b" * 64}"\n'
            "end\n"
        ).encode()
        definition = self.definition(data)
        definition["minimumDeclaredSha256"] = 2
        result = VERIFIER.validate_cask_definition(data, definition, self.root)
        self.assertEqual(result["declaredSha256"], 2)

    def test_dynamic_cask_checksum_is_refused_even_with_nested_hex(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 choose("{"a" * 64}")\n'
            "end\n"
        ).encode()
        with self.assertRaisesRegex(
            VERIFIER.IntegrityViolation, "dynamic or malformed sha256"
        ):
            VERIFIER.validate_cask_definition(data, self.definition(data), self.root)

    def test_cask_dependency_calls_use_direct_ripper_arguments(self) -> None:
        formula = self.root / "Formula" / "b" / "beta.rb"
        formula.parent.mkdir(parents=True)
        formula.write_text("class Beta < Formula\nend\n", encoding="utf-8")
        (self.root / "Aliases").mkdir()
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 "{"a" * 64}"\n'
            "  depends_on(\n"
            '    formula: "beta",\n'
            "  )\n"
            '  note = %q(depends_on formula: "string-missing")\n'
            '  # depends_on formula: "comment-missing"\n'
            '  helper.depends_on formula: "receiver-missing"\n'
            "end\n"
        ).encode()
        result = VERIFIER.validate_cask_definition(
            data, self.definition(data), self.root
        )
        self.assertEqual(result["formulaDependencies"], ["beta"])

    def test_definition_byte_tampering_is_refused(self) -> None:
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 "{"c" * 64}"\n'
            "end\n"
        ).encode()
        definition = self.definition(data)
        with self.assertRaisesRegex(
            VERIFIER.IntegrityViolation, "source SHA-256 drifted"
        ):
            VERIFIER.validate_cask_definition(
                data + b"# changed\n", definition, self.root
            )

    def test_cask_metadata_audit_does_not_execute_class_body(self) -> None:
        proof = self.root / "cask-class-body-proof"
        data = (
            'cask "sample" do\n'
            '  url "https://example.invalid/sample.zip"\n'
            f'  sha256 "{"d" * 64}"\n'
            f"  File.write({str(proof)!r}, 'executed')\n"
            "end\n"
        ).encode()
        VERIFIER.validate_cask_definition(data, self.definition(data), self.root)
        self.assertFalse(proof.exists())


class WorkflowBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        workflow_root = self.root / ".github" / "workflows"
        workflow_root.mkdir(parents=True)
        (self.root / ".github" / "upstream-workflows").mkdir(parents=True)
        self.workflow = workflow_root / "axiomlayer-tap-integrity.yml"
        workflow_text = WORKFLOW_SOURCE.read_text(encoding="utf-8")
        self.policy = {
            "workflowPolicy": {
                "active": [".github/workflows/axiomlayer-tap-integrity.yml"],
                "allowedActions": {},
                "representativeFormulae": ["go", "jq", "ripgrep", "sqlite"],
                "metadataEvaluation": {
                    "mode": "static-source-declarations",
                    "rubySourceExecution": False,
                    "homebrewRuntimeLoaded": False,
                    "homebrewStateMutationAllowed": False,
                    "formulaHooksInvoked": False,
                    "caskHooksInvoked": False,
                },
                "archiveManifest": {
                    "activeSha256": VERIFIER.sha256_bytes(workflow_text.encode()),
                },
            }
        }
        self.workflow.write_text(workflow_text, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_workflow(self, text: str) -> None:
        self.workflow.write_text(text, encoding="utf-8")
        self.policy["workflowPolicy"]["archiveManifest"]["activeSha256"] = (
            VERIFIER.sha256_bytes(text.encode())
        )

    def terminal_authority_script(self) -> str:
        marker = "      - name: Refuse skipped, invalid, or incomplete verification\n"
        tail = self.workflow.read_text(encoding="utf-8").split(marker, 1)[1]
        return textwrap.dedent(tail.split("        run: |\n", 1)[1])

    def run_terminal_authority(
        self, **overrides: str
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": "/usr/bin:/bin",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "axiomlayer/homebrew-core",
            "EVENT_REPOSITORY": "axiomlayer/homebrew-core",
            "EVENT_DEFAULT_BRANCH": "main",
            "AXIOMLAYER_INPUT_CLASS": "fabricated-public-metadata",
            "PINNED_POLICY_RESULT": "success",
            "CANARY_RESULT": "skipped",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_BASE_REF": "",
            "PR_HEAD_REPOSITORY": "",
            "PR_NUMBER": "",
            "GITHUB_REF": "refs/heads/main",
            "REF_PROTECTED": "true",
            "WORKFLOW_REF": (
                "axiomlayer/homebrew-core/.github/workflows/"
                "axiomlayer-tap-integrity.yml@refs/heads/main"
            ),
        }
        environment.update(overrides)
        return subprocess.run(
            ["bash"],
            input=self.terminal_authority_script(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=environment,
        )

    def test_zero_permission_action_free_workflow_is_accepted(self) -> None:
        VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_terminal_authority_accepts_only_complete_valid_routes(self) -> None:
        pull_request = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_BASE_REF": "main",
            "PR_HEAD_REPOSITORY": "axiomlayer/homebrew-core",
            "PR_NUMBER": "42",
            "GITHUB_REF": "refs/pull/42/merge",
            "REF_PROTECTED": "false",
            "WORKFLOW_REF": (
                "axiomlayer/homebrew-core/.github/workflows/"
                "axiomlayer-tap-integrity.yml@refs/pull/42/merge"
            ),
        }
        schedule = {"GITHUB_EVENT_NAME": "schedule", "CANARY_RESULT": "success"}
        manual = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "CANARY_RESULT": "success",
        }
        for name, route in {
            "same-repository pull request": pull_request,
            "protected main push": {},
            "protected main schedule": schedule,
            "protected main manual": manual,
        }.items():
            with self.subTest(name=name):
                result = self.run_terminal_authority(**route)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_terminal_authority_refuses_green_skip_and_invalid_routes(self) -> None:
        pull_request = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_BASE_REF": "main",
            "PR_HEAD_REPOSITORY": "axiomlayer/homebrew-core",
            "PR_NUMBER": "42",
            "GITHUB_REF": "refs/pull/42/merge",
            "REF_PROTECTED": "false",
            "WORKFLOW_REF": (
                "axiomlayer/homebrew-core/.github/workflows/"
                "axiomlayer-tap-integrity.yml@refs/pull/42/merge"
            ),
        }
        cases = {
            "skipped baseline": {"PINNED_POLICY_RESULT": "skipped"},
            "failed baseline": {"PINNED_POLICY_RESULT": "failure"},
            "unprotected push": {"REF_PROTECTED": "false"},
            "unsupported event": {"GITHUB_EVENT_NAME": "release"},
            "non-fabricated input": {"AXIOMLAYER_INPUT_CLASS": "production"},
            "scheduled canary skipped": {
                "GITHUB_EVENT_NAME": "schedule",
                "CANARY_RESULT": "skipped",
            },
            "pull-request canary ran": pull_request | {"CANARY_RESULT": "success"},
            "fork pull request": pull_request
            | {"PR_HEAD_REPOSITORY": "someone/homebrew-core"},
        }
        for name, route in cases.items():
            with self.subTest(name=name):
                result = self.run_terminal_authority(**route)
                self.assertNotEqual(result.returncode, 0)

    def test_extra_active_python_helper_is_refused(self) -> None:
        helper = self.root / ".github/workflows/helper.py"
        helper.write_text("exit 0\n", encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "active workflows"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_dynamic_homebrew_ruby_evaluation_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "    steps:\n",
            "    steps:\n      - run: brew ruby unsafe.rb\n",
            1,
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "forbidden"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_duplicate_permissions_key_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "permissions: {}", "permissions: {}\npermissions: write-all", 1
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_quoted_duplicate_permissions_key_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "permissions: {}", 'permissions: {}\n"permissions": {}', 1
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_duplicate_job_guard_is_refused(self) -> None:
        safe = f"    if: {VERIFIER.PINNED_POLICY_CONDITION}"
        text = self.workflow.read_text(encoding="utf-8").replace(
            safe, f"{safe}\n    if: true", 1
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_yaml_anchor_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "permissions: {}", "permissions: &shared {}", 1
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_yaml_merge_key_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "permissions: {}", "permissions:\n  <<: {}", 1
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_multiple_yaml_documents_are_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8") + "---\nname: shadow\n"
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "ambiguous YAML"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_casefolded_secret_and_jsr_are_refused(self) -> None:
        source = self.workflow.read_text(encoding="utf-8")
        payloads = {
            "secret context": "echo ${{ SeCrEtS.EXAMPLE }}",
            "JSR source": "echo https://JSR.IO/example",
        }
        for name, payload in payloads.items():
            with self.subTest(name=name):
                text = source.replace(
                    "    steps:\n", f"    steps:\n      - run: {payload}\n", 1
                )
                self.write_workflow(text)
                with self.assertRaises(VERIFIER.IntegrityViolation):
                    VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_quoted_environment_key_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "    runs-on: ubuntu-24.04",
            '    runs-on: ubuntu-24.04\n    "environment": production',
            1,
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "environment"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_unpinned_action_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "    steps:\n",
            "    steps:\n      - uses: actions/checkout@main\n",
            1,
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "not full-SHA pinned"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_quoted_unpinned_action_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "    steps:\n",
            '    steps:\n      - "uses": "actions/checkout@main"\n',
            1,
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "not full-SHA pinned"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_flow_style_action_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "    steps:\n",
            "    steps:\n      - {uses: actions/checkout@main}\n",
            1,
        )
        self.write_workflow(text)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "capability key"):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_write_permission_is_refused(self) -> None:
        text = self.workflow.read_text(encoding="utf-8").replace(
            "permissions: {}",
            "permissions:\n  contents: write",
            1,
        )
        self.write_workflow(text)
        with self.assertRaises(VERIFIER.IntegrityViolation):
            VERIFIER.verify_active_workflow(self.root, self.policy)

    def test_event_and_runner_drift_is_refused(self) -> None:
        source = self.workflow.read_text(encoding="utf-8")
        mutations = {
            "uppercase owner": source.replace(
                "axiomlayer/homebrew-core", "AxiomLayer/homebrew-core", 1
            ),
            "fork pull request": source.replace(
                "github.event.pull_request.head.repo.full_name == 'axiomlayer/homebrew-core'",
                "github.event.pull_request.head.repo.full_name == 'someone/homebrew-core'",
                1,
            ),
            "feature manual ref": source.replace(
                "github.ref == 'refs/heads/main'",
                "github.ref == 'refs/heads/feature/unsafe'",
                1,
            ),
            "unprotected main": source.replace(
                "github.ref_protected == true",
                "github.ref_protected == false",
                1,
            ),
            "alternate workflow": source.replace(
                "axiomlayer-tap-integrity.yml@refs/heads/main",
                "release.yml@refs/heads/main",
                1,
            ),
            "weekly schedule": source.replace(
                'cron: "17 11 * * *"', 'cron: "17 11 * * 3"', 1
            ),
            "floating runner": source.replace(
                "runner: ubuntu-24.04-arm", "runner: ubuntu-latest", 1
            ),
            "self-hosted runner": source.replace(
                "runner: macos-15-intel", "runner: self-hosted", 1
            ),
            "real input classification": source.replace(
                "AXIOMLAYER_INPUT_CLASS: fabricated-public-metadata",
                "AXIOMLAYER_INPUT_CLASS: production-secret",
                1,
            ),
            "terminal input guard removed": source.replace(
                'test "$AXIOMLAYER_INPUT_CLASS" = fabricated-public-metadata',
                'test "$AXIOMLAYER_INPUT_CLASS" != fabricated-public-metadata',
                1,
            ),
            "runner guard removed": source.replace(
                'test "$RUNNER_ENVIRONMENT" = github-hosted',
                'test "$RUNNER_ENVIRONMENT" != github-hosted',
                1,
            ),
            "ambient Git config restored": source.replace(
                "export GIT_CONFIG_NOSYSTEM=1",
                "export GIT_CONFIG_NOSYSTEM=0",
                1,
            ),
            "fetch head binding removed": source.replace(
                "rev-parse FETCH_HEAD",
                "rev-parse HEAD",
                1,
            ),
            "terminal job can skip": source.replace(
                "    if: ${{ always() }}",
                "    if: ${{ success() }}",
                1,
            ),
            "terminal job accepts skipped baseline": source.replace(
                '          test "$PINNED_POLICY_RESULT" = success',
                '          test "$PINNED_POLICY_RESULT" = skipped',
                1,
            ),
            "terminal canary authority weakened": source.replace(
                '              test "$CANARY_RESULT" = success',
                '              test "$CANARY_RESULT" != failure',
                1,
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutation, source)
                self.write_workflow(mutation)
                with self.assertRaises(VERIFIER.IntegrityViolation):
                    VERIFIER.verify_active_workflow(self.root, self.policy)


class ArchiveBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        sources = {
            ".github/actionlint.yaml": b"config-variables: []\n",
            ".github/codeql/extensions/homebrew-actions.yml": b"extensions: []\n",
            ".github/dependabot.yml": b"version: 2\nupdates: []\n",
            ".github/workflows/upstream.yml": b"name: upstream\non: push\n",
        }
        for relative, data in sources.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        VERIFIER.git(self.root, "init")
        VERIFIER.git(self.root, "config", "user.name", "Archive Fixture")
        VERIFIER.git(self.root, "config", "user.email", "fixture@example.invalid")
        VERIFIER.git(self.root, "add", ".github")
        VERIFIER.git(self.root, "commit", "--no-gpg-sign", "-m", "fixture baseline")
        baseline = VERIFIER.git_output(self.root, "rev-parse", "HEAD")

        destinations = {
            ".github/actionlint.yaml": ".github/upstream-workflows/actionlint.yaml.disabled",
            ".github/codeql/extensions/homebrew-actions.yml": ".github/upstream-workflows/codeql/extensions/homebrew-actions.yml.disabled",
            ".github/dependabot.yml": ".github/upstream-workflows/dependabot.yml.disabled",
            ".github/workflows/upstream.yml": ".github/upstream-workflows/upstream.yml.disabled",
        }
        entries = []
        for source, archive in sorted(destinations.items()):
            source_path = self.root / source
            data = source_path.read_bytes()
            archive_path = self.root / archive
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_path.write_bytes(data)
            source_path.unlink()
            entries.append(
                {
                    "sourcePath": source,
                    "archivePath": archive,
                    "sha256": VERIFIER.sha256_bytes(data),
                }
            )
        readme = self.root / ".github/upstream-workflows/README.md"
        readme.write_text("inert baseline automation\n", encoding="utf-8")
        VERIFIER.git(self.root, "add", "-A", ".github")
        self.policy = {
            "workflowPolicy": {
                "archiveManifest": {
                    "baselineCommit": baseline,
                    "archiveRoot": ".github/upstream-workflows",
                    "readme": {
                        "path": ".github/upstream-workflows/README.md",
                        "sha256": VERIFIER.sha256_bytes(readme.read_bytes()),
                    },
                    "entries": entries,
                }
            }
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_complete_byte_identical_archive_is_accepted(self) -> None:
        VERIFIER.verify_archive(self.root, self.policy)

    def test_archive_tampering_is_refused(self) -> None:
        target = self.root / ".github/upstream-workflows/upstream.yml.disabled"
        target.write_bytes(target.read_bytes() + b"# drift\n")
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "digest drifted"):
            VERIFIER.verify_archive(self.root, self.policy)

    def test_extra_archive_file_is_refused(self) -> None:
        (self.root / ".github/upstream-workflows/extra.disabled").write_text(
            "extra\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "inventory drifted"):
            VERIFIER.verify_archive(self.root, self.policy)

    def test_archive_mode_drift_is_refused(self) -> None:
        target = self.root / ".github/upstream-workflows/upstream.yml.disabled"
        target.chmod(0o755)
        VERIFIER.git(self.root, "add", str(target))
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "mode drifted"):
            VERIFIER.verify_archive(self.root, self.policy)

    def test_reactivated_dependabot_is_refused(self) -> None:
        source = self.root / ".github/dependabot.yml"
        source.write_text("version: 2\nupdates: []\n", encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "reactivated"):
            VERIFIER.verify_archive(self.root, self.policy)

    def test_symlinked_archive_entry_is_refused(self) -> None:
        target = self.root / ".github/upstream-workflows/upstream.yml.disabled"
        data = target.read_bytes()
        target.unlink()
        witness = self.root / "witness.yml"
        witness.write_bytes(data)
        target.symlink_to(witness)
        with self.assertRaisesRegex(VERIFIER.IntegrityViolation, "absent or unsafe"):
            VERIFIER.verify_archive(self.root, self.policy)


if __name__ == "__main__":
    unittest.main()
