"""
Automated Unit Tests for Tier B ManifestDiffParser & Validation Logic
=====================================================================
Covers:
- requirements.txt before/after parsing (PEP 508 normalization)
- pyproject.toml before/after parsing
- Multi-dependency modification rejection
- Non-manifest code modification rejection (Rule EXC-06)
- Lockfile isolation vs transitive churn detection
- Conjunctive replay eligibility checks
"""

import os
import sys
import unittest

# Ensure infra/collector/job is in import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "infra", "collector", "job")))

from main import ManifestDiffParser, ManifestAnalysis, VersionBump, ValidationChecklist


def make_reader(before=None, after=None):
    before, after = before or {}, after or {}

    def reader(path, side):
        return (before if side == "before" else after).get(path)

    return reader


def run(files, before=None, after=None):
    return ManifestDiffParser.analyze(files, make_reader(before, after))


class TestManifestDiffParser(unittest.TestCase):
    def test_requirements_single_bump(self):
        before = "fastapi==0.95.0\npydantic==1.10.13\nuvicorn==0.22.0\n"
        after = "fastapi==0.95.0\npydantic==2.14.1\nuvicorn==0.22.0\n"
        files = [{"filename": "requirements.txt", "status": "modified"}]
        analysis, bumps = run(files, {"requirements.txt": before}, {"requirements.txt": after})

        self.assertTrue(analysis.exactly_one_dependency_updated)
        self.assertEqual(analysis.canonical_packages_modified, ["pydantic"])
        self.assertEqual(len(bumps), 1)
        self.assertEqual(bumps[0].package_name, "pydantic")
        self.assertEqual(bumps[0].old_version, "1.10.13")
        self.assertEqual(bumps[0].new_version, "2.14.1")
        self.assertEqual(bumps[0].bump_type, "major")
        self.assertTrue(bumps[0].is_valid_pep440)

    def test_requirements_multi_dependency_rejection(self):
        """Must reject when multiple packages are updated in one PR."""
        before = "requests==2.28.0\nurllib3==1.26.15\n"
        after = "requests==2.31.0\nurllib3==2.0.0\n"
        files = [{"filename": "requirements.txt", "status": "modified"}]
        analysis, bumps = run(files, {"requirements.txt": before}, {"requirements.txt": after})

        self.assertFalse(analysis.exactly_one_dependency_updated)
        self.assertEqual(len(analysis.canonical_packages_modified), 2)
        self.assertIn("requests", analysis.canonical_packages_modified)
        self.assertIn("urllib3", analysis.canonical_packages_modified)

    def test_pep621_pyproject_toml_array_bump(self):
        """PEP 621 array dependencies in pyproject.toml must be cleanly extracted."""
        before = '[project]\nname="app"\nversion="0.1.0"\ndependencies = [\n    "holidays==0.107",\n    "SQLAlchemy==2.1.1",\n]\n'
        after = '[project]\nname="app"\nversion="0.1.0"\ndependencies = [\n    "holidays==0.107",\n    "SQLAlchemy==2.1.6",\n]\n'
        files = [{"filename": "pyproject.toml", "status": "modified"}]
        analysis, bumps = run(files, {"pyproject.toml": before}, {"pyproject.toml": after})

        self.assertTrue(analysis.exactly_one_dependency_updated)
        self.assertEqual(analysis.canonical_packages_modified, ["sqlalchemy"])
        self.assertEqual(len(bumps), 1)
        self.assertEqual(bumps[0].package_name, "sqlalchemy")
        self.assertEqual(bumps[0].old_version, "2.1.1")
        self.assertEqual(bumps[0].new_version, "2.1.6")
        self.assertEqual(bumps[0].bump_type, "patch")

    def test_requirements_in_categorized_as_direct_manifest(self):
        """pip-tools requirements.in must be recognized as a direct manifest, not non-manifest code."""
        files = [
            {"filename": "requirements.in", "status": "modified"}
        ]
        analysis, bumps = run(files, {"requirements.in": "fastapi==0.100.0\n"}, {"requirements.in": "fastapi==0.101.0\n"})

        self.assertEqual(analysis.direct_manifest_files, ["requirements.in"])
        self.assertEqual(analysis.non_manifest_files, [])
        self.assertTrue(analysis.exactly_one_dependency_updated)

    def test_requirements_lock_hash_ignored(self):
        """Lines containing --hash must be ignored and not treated as package '-hash'."""
        before = "fastapi==0.161.1 \\\n    --hash=sha256:4076b88434452e20289379068e976c4a04c65ffc8e6be31510106e150a422f0f\n"
        after = "fastapi==0.162.0 \\\n    --hash=sha256:3785963de305dd09912426cb81f2d230fce98ab3521cdfe97265c8d14983128c\n"
        files = [{"filename": "requirements.txt", "status": "modified"}]
        analysis, bumps = run(files, {"requirements.txt": before}, {"requirements.txt": after})

        self.assertTrue(analysis.exactly_one_dependency_updated)
        self.assertEqual(analysis.canonical_packages_modified, ["fastapi"])
        self.assertEqual(len(bumps), 1)
        self.assertEqual(bumps[0].package_name, "fastapi")

    def test_non_manifest_code_file_categorization(self):
        """Bundled python code changes must be flagged as non_manifest_code."""
        files = [
            {"filename": "requirements.txt", "status": "modified"},
            {"filename": "src/utils.py", "status": "modified"}
        ]
        analysis, bumps = run(
            files,
            {"requirements.txt": "certifi==2023.5.7\n", "src/utils.py": "# comment\n"},
            {"requirements.txt": "certifi==2023.7.22\n", "src/utils.py": "import certifi\n"}
        )

        self.assertIn("src/utils.py", analysis.non_manifest_files)
        self.assertTrue(analysis.exactly_one_dependency_updated)

    def test_lockfile_isolated_to_target_package(self):
        """Lockfile changes strictly isolated to target package -> CONFIRMED_ISOLATED."""
        lock_b = '[[package]]\nname = "urllib3"\nversion = "1.26.15"\n'
        lock_a = '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'
        files = [
            {"filename": "requirements.txt", "status": "modified"},
            {"filename": "uv.lock", "status": "modified"}
        ]
        analysis, bumps = run(
            files,
            {"requirements.txt": "urllib3==1.26.15\n", "uv.lock": lock_b},
            {"requirements.txt": "urllib3==2.0.0\n", "uv.lock": lock_a}
        )

        self.assertEqual(analysis.lockfile_status, "CONFIRMED_ISOLATED")
        self.assertEqual(analysis.transitive_confound_risk, "LOW")

    def test_lockfile_transitive_churn_detected(self):
        """Lockfile modifying additional dependencies -> UNRESOLVED_LOCKFILE_CHANGE."""
        lock_b = '[[package]]\nname = "urllib3"\nversion = "1.26.15"\n[[package]]\nname = "idna"\nversion = "3.4"\n'
        lock_a = '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n[[package]]\nname = "idna"\nversion = "3.5"\n'
        files = [
            {"filename": "requirements.txt", "status": "modified"},
            {"filename": "poetry.lock", "status": "modified"}
        ]
        analysis, bumps = run(
            files,
            {"requirements.txt": "urllib3==1.26.15\n", "poetry.lock": lock_b},
            {"requirements.txt": "urllib3==2.0.0\n", "poetry.lock": lock_a}
        )

        self.assertEqual(analysis.lockfile_status, "UNRESOLVED_LOCKFILE_CHANGE")
        self.assertEqual(analysis.transitive_confound_risk, "HIGH")


class TestReplayEligibility(unittest.TestCase):
    def test_companion_packages_allowed(self):
        """pydantic and pydantic-core bumped together should be allowed as a companion family."""
        before = "pydantic==2.5.0\npydantic-core==2.14.0\n"
        after = "pydantic==2.6.0\npydantic-core==2.16.0\n"
        files = [{"filename": "requirements.txt", "status": "modified"}]
        analysis, bumps = run(files, {"requirements.txt": before}, {"requirements.txt": after})

        self.assertTrue(analysis.exactly_one_dependency_updated)
        self.assertEqual(len(analysis.canonical_packages_modified), 2)
        self.assertIn("pydantic", analysis.canonical_packages_modified)
        self.assertIn("pydantic-core", analysis.canonical_packages_modified)

    def test_conjunctive_readiness_all_pass(self):
        checklist = ValidationChecklist(
            python_repo_verified=True,
            single_dependency_verified=True,
            versions_resolved=True,
            no_non_manifest_code_edits=True,
            commit_shas_captured=True,
            lockfile_confound_free=True,
            tests_present=True,
            base_ci_status="SUCCESS",
            pr_merged=True,
            ready_for_differential_replay=True
        )
        self.assertTrue(checklist.ready_for_differential_replay)

    def test_conjunctive_readiness_fails_if_any_false(self):
        checklist = ValidationChecklist(
            python_repo_verified=True,
            single_dependency_verified=True,
            versions_resolved=True,
            no_non_manifest_code_edits=False,  # Failed!
            commit_shas_captured=True,
            lockfile_confound_free=True,
            tests_present=True,
            base_ci_status="SUCCESS",
            pr_merged=True,
            ready_for_differential_replay=False
        )
        self.assertFalse(checklist.ready_for_differential_replay)


if __name__ == "__main__":
    unittest.main()
