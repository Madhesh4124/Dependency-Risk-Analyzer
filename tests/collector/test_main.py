"""pytest suite for main.py. Run:  pytest -q test_main.py

All inputs are synthetic. Add real PR payloads under tests/fixtures as you collect them.
"""

import datetime as dt
import json
import os
import sys

# Ensure infra/collector/job is in path
for rel_path in [
    ("infra", "collector", "job"),
    ("..", "infra", "collector", "job"),
    ("..", "..", "infra", "collector", "job"),
]:
    d = os.path.abspath(os.path.join(os.path.dirname(__file__), *rel_path))
    if os.path.exists(d) and d not in sys.path:
        sys.path.insert(0, d)

import httpx
import pytest

import main as m
from main import GitHubAPIError, ManifestDiffParser as P


def make_reader(before=None, after=None):
    before, after = before or {}, after or {}

    def reader(path, side):
        return (before if side == "before" else after).get(path)

    return reader


def run(files, before=None, after=None):
    return P.analyze(files, make_reader(before, after))


def f(name, status="modified"):
    return {"filename": name, "status": status}


# ---------------------------------------------------------------- bump basics
def test_plain_pin_bump():
    a, b = run([f("requirements.txt")],
               {"requirements.txt": "flask==2.0.0\nrequests==2.30.0\n"},
               {"requirements.txt": "flask==2.0.0\nrequests==2.31.0\n"})
    assert not a.rejections and not a.inconclusive_codes
    assert [(x.package_name, x.old_version, x.new_version, x.bump_type) for x in b] == [
        ("requests", "2.30.0", "2.31.0", "minor")]
    assert b[0].resolution_source == "direct_pin"


def test_numeric_version_ordering_not_lexicographic():
    _, b = run([f("requirements.txt")], {"requirements.txt": "foo==1.9.0\n"}, {"requirements.txt": "foo==1.10.0\n"})
    assert b[0].bump_type == "minor"


def test_downgrade_rejected():
    a, b = run([f("requirements.txt")], {"requirements.txt": "foo==2.0.0\n"}, {"requirements.txt": "foo==1.9.0\n"})
    assert not b and any(r.startswith("EXC-10") for r in a.rejections)


def test_prerelease_to_final_is_not_patch():
    _, b = run([f("requirements.txt")], {"requirements.txt": "foo==1.0.0rc1\n"}, {"requirements.txt": "foo==1.0.0\n"})
    assert b[0].bump_type == "prerelease_or_post" and b[0].involves_prerelease


def test_calver_and_zero_major_flags():
    _, b = run([f("requirements.txt")], {"requirements.txt": "certifi==2023.7.22\n"}, {"requirements.txt": "certifi==2024.2.2\n"})
    assert b[0].is_calver
    _, b = run([f("requirements.txt")], {"requirements.txt": "foo==0.9.0\n"}, {"requirements.txt": "foo==0.10.0\n"})
    assert b[0].is_zero_major and b[0].bump_type == "minor"


# ---------------------------------------------------------------- spec handling
def test_extras_and_markers_and_hashes_parse():
    before = 'requests[security]==2.30.0 ; python_version >= "3.8" \\\n    --hash=sha256:abc\n'
    after = 'requests[security]==2.31.0 ; python_version >= "3.8" \\\n    --hash=sha256:def\n'
    _, b = run([f("requirements.txt")], {"requirements.txt": before}, {"requirements.txt": after})
    assert b and b[0].new_version == "2.31.0"


def test_range_spec_without_lockfile_is_inconclusive():
    a, b = run([f("requirements.txt")], {"requirements.txt": "foo>=1.0\n"}, {"requirements.txt": "foo>=2.0\n"})
    assert not b and "INCONCLUSIVE_UNPINNED_SPEC" in a.inconclusive_codes


def test_range_spec_with_lockfile_uses_resolved_versions():
    lock_b = '[[package]]\nname = "foo"\nversion = "1.5.0"\n'
    lock_a = '[[package]]\nname = "foo"\nversion = "2.0.0"\n'
    pp_b = '[project]\ndependencies = ["foo>=1.0"]\n'
    pp_a = '[project]\ndependencies = ["foo>=2.0"]\n'
    a, b = run([f("pyproject.toml"), f("uv.lock")],
               {"pyproject.toml": pp_b, "uv.lock": lock_b}, {"pyproject.toml": pp_a, "uv.lock": lock_a})
    assert not a.rejections and not a.inconclusive_codes
    assert (b[0].old_version, b[0].new_version, b[0].resolution_source) == ("1.5.0", "2.0.0", "lockfile")
    assert a.lockfile_status == "CONFIRMED_ISOLATED"


def test_poetry_bare_version_is_pin_and_caret_is_not():
    _, b = run([f("pyproject.toml")],
               {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "2.30.0"\n'},
               {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "2.31.0"\n'})
    assert b and b[0].new_version == "2.31.0"
    a, b = run([f("pyproject.toml")],
               {"pyproject.toml": '[tool.poetry.dependencies]\nrequests = "^2.30"\n'},
               {"pyproject.toml": '[tool.poetry.dependencies]\nrequests = "^2.31"\n'})
    assert not b and "INCONCLUSIVE_UNPINNED_SPEC" in a.inconclusive_codes


def test_pep621_array():
    _, b = run([f("pyproject.toml")],
               {"pyproject.toml": '[project]\nname="x"\nversion="0.1.0"\ndependencies = [\n  "requests==2.30.0",\n]\n'},
               {"pyproject.toml": '[project]\nname="x"\nversion="0.1.0"\ndependencies = [\n  "requests==2.31.0",\n]\n'})
    assert b[0].package_name == "requests"


def test_project_version_bump_is_not_a_dependency():
    a, b = run([f("pyproject.toml")],
               {"pyproject.toml": '[project]\nname="x"\nversion="0.1.0"\ndependencies=["a==1.0"]\n'},
               {"pyproject.toml": '[project]\nname="x"\nversion="0.1.1"\ndependencies=["a==1.0"]\n'})
    assert any(r.startswith("EXC-01") for r in a.rejections)


# ---------------------------------------------------------------- multi-file / multi-dep
def test_same_package_two_files_both_changed_is_ambiguous():
    a, b = run([f("requirements.txt"), f("requirements-dev.txt")],
               {"requirements.txt": "foo==1.9.0\n", "requirements-dev.txt": "foo==1.2.0\n"},
               {"requirements.txt": "foo==1.10.0\n", "requirements-dev.txt": "foo==1.11.0\n"})
    assert not b and "INCONCLUSIVE_AMBIGUOUS_VERSIONS" in a.inconclusive_codes


def test_two_direct_deps_rejected():
    a, _ = run([f("requirements.txt")], {"requirements.txt": "a==1.0\nb==1.0\n"}, {"requirements.txt": "a==1.1\nb==1.1\n"})
    assert any(r.startswith("EXC-02") for r in a.rejections)


def test_companion_family_allowed():
    a, b = run([f("requirements.txt")],
               {"requirements.txt": "pydantic==2.0.0\npydantic-core==2.0.1\n"},
               {"requirements.txt": "pydantic==2.1.0\npydantic-core==2.2.0\n"})
    assert a.exactly_one_dependency_updated and len(b) == 2 and not a.rejections


def test_added_dependency_rejected():
    a, b = run([f("requirements.txt")], {"requirements.txt": "a==1.0\n"}, {"requirements.txt": "a==1.0\nb==2.0\n"})
    assert not b and any(r.startswith("EXC-08") for r in a.rejections)


# ---------------------------------------------------------------- lockfiles
def test_transitive_lock_churn_is_flagged_not_isolated():
    lock_b = ('[[package]]\nname = "requests"\nversion = "2.30.0"\n\n'
              '[[package]]\nname = "urllib3"\nversion = "1.26.0"\n')
    lock_a = ('[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
              '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n')
    a, _ = run([f("requirements.txt"), f("poetry.lock")],
               {"requirements.txt": "requests==2.30.0\n", "poetry.lock": lock_b},
               {"requirements.txt": "requests==2.31.0\n", "poetry.lock": lock_a})
    assert a.lockfile_status == "UNRESOLVED_LOCKFILE_CHANGE" and a.transitive_confound_risk == "HIGH"
    assert "INCONCLUSIVE_LOCKFILE_CHURN" in a.inconclusive_codes
    assert not a.rejections  # churn is inconclusive, not a multi-dependency rejection


def test_lock_only_single_package():
    a, b = run([f("uv.lock")],
               {"uv.lock": '[[package]]\nname = "idna"\nversion = "3.6"\n'},
               {"uv.lock": '[[package]]\nname = "idna"\nversion = "3.7"\n'})
    assert b[0].resolution_source == "lockfile" and not a.inconclusive_codes


def test_lock_only_multiple_packages_is_inconclusive():
    lb = '[[package]]\nname = "a"\nversion = "1"\n[[package]]\nname = "b"\nversion = "1"\n'
    la = '[[package]]\nname = "a"\nversion = "2"\n[[package]]\nname = "b"\nversion = "2"\n'
    a, _ = run([f("poetry.lock")], {"poetry.lock": lb}, {"poetry.lock": la})
    assert "INCONCLUSIVE_LOCKFILE_CHURN" in a.inconclusive_codes


def test_pipfile_lock_parsed():
    jb = json.dumps({"default": {"requests": {"version": "==2.30.0"}}, "develop": {}})
    ja = json.dumps({"default": {"requests": {"version": "==2.31.0"}}, "develop": {}})
    _, b = run([f("Pipfile.lock")], {"Pipfile.lock": jb}, {"Pipfile.lock": ja})
    assert b and b[0].new_version == "2.31.0"


def test_pin_lock_mismatch_inconclusive():
    a, b = run([f("requirements.txt"), f("poetry.lock")],
               {"requirements.txt": "foo==1.0\n", "poetry.lock": '[[package]]\nname = "foo"\nversion = "1.0"\n'},
               {"requirements.txt": "foo==1.1\n", "poetry.lock": '[[package]]\nname = "foo"\nversion = "1.2"\n'})
    assert not b and "INCONCLUSIVE_PIN_LOCK_MISMATCH" in a.inconclusive_codes


def test_unreadable_file_is_inconclusive_not_isolated():
    a, b = run([f("poetry.lock")], {}, {})
    assert a.lockfile_status == "UNPARSEABLE_LOCKFILE" and not b
    assert "INCONCLUSIVE_LOCKFILE_UNPARSEABLE" in a.inconclusive_codes


# ---------------------------------------------------------------- file categories
@pytest.mark.parametrize("path,cat", [
    ("requirements.txt", "direct_manifest"),
    ("requirements/base.txt", "direct_manifest"),
    ("requirements-dev.in", "direct_manifest"),
    ("constraints.txt", "direct_manifest"),
    ("docs/requirements.txt", "aux_manifest"),
    ("poetry.lock", "lockfile"),
    ("tests/test_x.py", "non_manifest_code"),
    ("README.md", "doc_or_config"),
    (".github/workflows/ci.yml", "doc_or_config"),
    ("Cargo.lock", "non_manifest_code"),
])
def test_categorize(path, cat):
    assert P.categorize_filename(path) == cat


def test_non_manifest_edit_rejected():
    a, _ = run([f("requirements.txt"), f("src/app.py")],
               {"requirements.txt": "a==1.0\n"}, {"requirements.txt": "a==1.1\n"})
    assert any(r.startswith("EXC-06") for r in a.rejections)


def test_aux_only_manifest_change_has_no_bump():
    a, b = run([f("docs/requirements.txt")], {"docs/requirements.txt": "a==1.0\n"}, {"docs/requirements.txt": "a==1.1\n"})
    assert not b and any(r.startswith("EXC-01") for r in a.rejections)


# ---------------------------------------------------------------- URL parsing
def test_url_canonicalization_and_dedupe():
    urls = m.parse_candidate_urls([
        "https://github.com/Owner/Repo/pull/5",
        "https://github.com/owner/repo/pull/5/files",
        "https://api.github.com/repos/owner/repo/pulls/5",
        "not a url",
    ])
    assert urls == ["https://github.com/Owner/Repo/pull/5"]  # 'not a url' has no http prefix


# ---------------------------------------------------------------- client failure semantics
def _client_with(handler, **kw):
    c = m.GitHubClient(token="x", **kw)
    c._client = httpx.Client(transport=httpx.MockTransport(handler), headers={})
    return c


def test_plain_403_raises_immediately_no_retry(monkeypatch):
    calls = []
    monkeypatch.setattr(m.time, "sleep", lambda s: calls.append(s))

    def h(req):
        return httpx.Response(403, text="Resource not accessible")
    c = _client_with(h)
    with pytest.raises(GitHubAPIError):
        c.get_json("repos/o/r")
    assert calls == []  # not mistaken for a rate limit


def test_rate_limit_over_cap_raises(monkeypatch):
    monkeypatch.setattr(m.time, "sleep", lambda s: None)

    def h(req):
        return httpx.Response(403, headers={"retry-after": "3600"}, text="rate limit")
    with pytest.raises(GitHubAPIError):
        _client_with(h, max_rate_limit_wait=60).get_json("repos/o/r")


def test_pagination_failure_raises_not_truncates():
    def h(req):
        if "page=2" in str(req.url):
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json=[{"filename": "a"}],
                              headers={"link": '<https://api.github.com/x?page=2>; rel="next"'})
    c = _client_with(h, max_retries=1)
    with pytest.raises(GitHubAPIError):
        list(c.paginate("repos/o/r/pulls/1/files"))


def test_404_returns_none_only_when_allowed():
    c = _client_with(lambda req: httpx.Response(404, text="nf"))
    assert c.get_json("repos/o/r", allow_404=True) is None
    with pytest.raises(GitHubAPIError):
        c.get_json("repos/o/r")


# ---------------------------------------------------------------- end-to-end with fake client
class FakeClient:
    def __init__(self, files_before, files_after, *, fail_on=None, tree=None, ci="success", python=True):
        self.fb, self.fa, self.fail_on, self.ci = files_before, files_after, fail_on, ci
        self.tree = tree if tree is not None else ["tests/test_a.py", "src/a.py"]
        self.python = python

    def get_json(self, ep, params=None, allow_404=False):
        if self.fail_on and self.fail_on in ep:
            raise GitHubAPIError("boom")
        if ep.endswith("/pulls/7"):
            return {"base": {"sha": "b" * 40, "ref": "main"},
                    "head": {"sha": "h" * 40, "ref": "dependabot/x", "repo": {"full_name": "o/r"}},
                    "title": "Bump requests", "merged": True, "state": "closed"}
        if ep.endswith("/languages"):
            return {"Python": 900, "Shell": 100} if self.python else {"JavaScript": 1000}
        if ep == "repos/o/r":
            return {"language": "Python", "stargazers_count": 10, "html_url": "https://github.com/o/r"}
        if "/compare/" in ep:
            return {"merge_base_commit": {"sha": "m" * 40}}
        if "/git/trees/" in ep:
            return {"tree": [{"path": p, "type": "blob"} for p in self.tree], "truncated": False}
        if ep.endswith("/status"):
            return {"statuses": []}
        raise AssertionError(ep)

    def get_text(self, ep, params=None, accept=None):
        path = ep.split("/contents/")[1]
        src = self.fb if params["ref"] == "m" * 40 else self.fa
        return src.get(path)

    def paginate(self, ep, params=None):
        if ep.endswith("/files"):
            return iter([{"filename": "requirements.txt", "status": "modified"}])
        if ep.endswith("/check-runs"):
            return iter([{"name": "pytest", "status": "completed", "conclusion": self.ci}])
        raise AssertionError(ep)


def _fc(**kw):
    return FakeClient({"requirements.txt": "requests==2.30.0\n"}, {"requirements.txt": "requests==2.31.0\n"}, **kw)


def test_end_to_end_accepted():
    rec = m.evaluate_candidate_pr(_fc(), "https://github.com/o/r/pull/7")
    assert rec.collection_status == "ACCEPTED_CANDIDATE", (rec.rejection_reasons, rec.inconclusive_reasons)
    assert rec.ground_truth_label is None
    assert rec.pull_request["merge_base_sha"] == "m" * 40
    assert rec.case_id.endswith("hhhhhhhh")


def test_end_to_end_api_failure_is_exception_not_rejection():
    with pytest.raises(GitHubAPIError):
        m.evaluate_candidate_pr(_fc(fail_on="/compare/"), "https://github.com/o/r/pull/7")


def test_end_to_end_no_tests_inconclusive():
    rec = m.evaluate_candidate_pr(_fc(tree=["src/a.py"]), "https://github.com/o/r/pull/7")
    assert rec.collection_status == "INCONCLUSIVE" and "INCONCLUSIVE_NO_TESTS" in rec.inconclusive_reasons


def test_end_to_end_base_ci_failed_inconclusive():
    rec = m.evaluate_candidate_pr(_fc(ci="failure"), "https://github.com/o/r/pull/7")
    assert rec.inconclusive_reason == "INCONCLUSIVE_BASE_CI_FAILED"


def test_end_to_end_non_python_rejected():
    rec = m.evaluate_candidate_pr(_fc(python=False), "https://github.com/o/r/pull/7")
    assert rec.collection_status == "REJECTED" and rec.rejection_reasons[0].startswith("EXC-05")


def test_model_view_excludes_outcome_fields():
    rec = m.evaluate_candidate_pr(_fc(), "https://github.com/o/r/pull/7")
    view = m.model_visible_view(m.asdict(rec))
    blob = json.dumps(view)
    for banned in ("ci_evidence", "merged", "title", "Bump requests", "check", "label"):
        assert banned not in blob
    assert view["package"] == "requests" and view["before_sha"] == "m" * 40


def test_batch_is_write_once(tmp_path):
    rec = m.evaluate_candidate_pr(_fc(), "https://github.com/o/r/pull/7")
    storage = m.DatasetStorage("", "")
    storage.write_immutable_batch("e1", [rec], str(tmp_path))
    files = list(tmp_path.iterdir())
    assert len(files) == 2
    # same execution id + same second would collide -> must refuse, never overwrite
    fixed = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    class FrozenDT(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed
    old = m.datetime
    m.datetime = FrozenDT
    try:
        storage.write_immutable_batch("e2", [rec], str(tmp_path))
        with pytest.raises(FileExistsError):
            storage.write_immutable_batch("e2", [rec], str(tmp_path))
    finally:
        m.datetime = old

