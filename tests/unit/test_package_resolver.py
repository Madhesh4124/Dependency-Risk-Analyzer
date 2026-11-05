"""Unit tests for Package-to-Import Resolver."""

import pytest
from risk_agent.resolver.package_resolver import PackageResolver


class TestPackageResolver:
    def test_known_mismatches_from_static_map(self):
        cases = [
            ("beautifulsoup4", "bs4"),
            ("pyyaml", "yaml"),
            ("pillow", "PIL"),
            ("scikit-learn", "sklearn"),
            ("synthetic-yaml", "s_yaml"),
        ]
        for pkg, expected_mod in cases:
            res = PackageResolver.resolve(pkg)
            assert res.resolution_confidence == "high"
            assert expected_mod in res.import_module_names

    def test_installed_package_metadata(self):
        # pytest or fastapi is installed in current venv
        res = PackageResolver.resolve("fastapi")
        assert "fastapi" in res.import_module_names
        assert res.resolution_confidence == "high"

    def test_unknown_package_fallback(self):
        res = PackageResolver.resolve("my-custom-obscure-lib")
        assert res.import_module_names == ["my_custom_obscure_lib"]
        assert res.resolution_confidence == "low"
        assert res.method_used == "fallback"
