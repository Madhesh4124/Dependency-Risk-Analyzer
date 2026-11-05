"""Unit tests for ManifestDiffParser across all supported formats."""

import pytest
from risk_agent.models.schemas import VersionBumpType
from risk_agent.parser.diff_parser import (
    ManifestDiffParser,
    canonicalize_name,
    determine_bump_type,
)


class TestCanonicalizationAndBumpType:
    def test_canonicalize_name(self):
        assert canonicalize_name("PyYAML") == "pyyaml"
        assert canonicalize_name("scikit_learn") == "scikit-learn"
        assert canonicalize_name("BeautifulSoup4") == "beautifulsoup4"
        assert canonicalize_name("backports.ssl-match-hostname") == "backports-ssl-match-hostname"

    def test_determine_bump_type(self):
        assert determine_bump_type("1.0.0", "2.0.0") == VersionBumpType.MAJOR
        assert determine_bump_type("1.2.0", "1.3.0") == VersionBumpType.MINOR
        assert determine_bump_type("1.2.3", "1.2.4") == VersionBumpType.PATCH
        assert determine_bump_type("invalid", "2.0.0") == VersionBumpType.UNKNOWN


class TestRequirementsParser:
    def test_parse_requirements_file_pair(self):
        before = (
            "# Main requirements\n"
            "fastapi==0.110.0\n"
            "requests==2.28.1 --hash=sha256:12345\n"
            "pydantic==1.10.12 ; python_version > '3.8'\n"
        )
        after = (
            "fastapi==0.110.0\n"
            "requests==2.31.0 --hash=sha256:67890\n"
            "pydantic==2.5.0 ; python_version > '3.8'\n"
        )
        bumps = ManifestDiffParser.parse_file_pair("requirements.txt", before, after)
        assert len(bumps) == 2

        req_bump = next(b for b in bumps if b.package_name == "requests")
        assert req_bump.old_version == "2.28.1"
        assert req_bump.new_version == "2.31.0"
        assert req_bump.bump_type == VersionBumpType.MINOR

        pyd_bump = next(b for b in bumps if b.package_name == "pydantic")
        assert pyd_bump.old_version == "1.10.12"
        assert pyd_bump.new_version == "2.5.0"
        assert pyd_bump.bump_type == VersionBumpType.MAJOR

    def test_parse_requirements_patch(self):
        patch = (
            "--- a/requirements.txt\n"
            "+++ b/requirements.txt\n"
            "@@ -1,3 +1,3 @@\n"
            "-data-transformer==1.0.0\n"
            "+data-transformer==2.0.0\n"
        )
        bumps = ManifestDiffParser.parse_unified_diff("requirements.txt", patch)
        assert len(bumps) == 1
        assert bumps[0].package_name == "data-transformer"
        assert bumps[0].old_version == "1.0.0"
        assert bumps[0].new_version == "2.0.0"
        assert bumps[0].bump_type == VersionBumpType.MAJOR


class TestPyprojectAndSetupCfgParser:
    def test_parse_pyproject_toml(self):
        before = (
            '[project]\n'
            'dependencies = [\n'
            '    "numpy==1.24.0",\n'
            '    "scipy==1.10.0",\n'
            ']\n'
        )
        after = (
            '[project]\n'
            'dependencies = [\n'
            '    "numpy==2.0.0",\n'
            '    "scipy==1.10.0",\n'
            ']\n'
        )
        bumps = ManifestDiffParser.parse_file_pair("pyproject.toml", before, after)
        assert len(bumps) == 1
        assert bumps[0].package_name == "numpy"
        assert bumps[0].old_version == "1.24.0"
        assert bumps[0].new_version == "2.0.0"
        assert bumps[0].bump_type == VersionBumpType.MAJOR

    def test_parse_setup_cfg(self):
        before = (
            "[options]\n"
            "install_requires =\n"
            "    click==8.0.0\n"
            "    colorama==0.4.4\n"
        )
        after = (
            "[options]\n"
            "install_requires =\n"
            "    click==8.1.3\n"
            "    colorama==0.4.4\n"
        )
        bumps = ManifestDiffParser.parse_file_pair("setup.cfg", before, after)
        assert len(bumps) == 1
        assert bumps[0].package_name == "click"
        assert bumps[0].old_version == "8.0.0"
        assert bumps[0].new_version == "8.1.3"
        assert bumps[0].bump_type == VersionBumpType.MINOR

    def test_ignore_unsupported_files(self):
        bumps = ManifestDiffParser.parse_file_pair("main.py", "x = 1", "x = 2")
        assert bumps == []

