"""PR Comment Markdown Formatter for Phase 6.

Formats structured, developer-friendly GitHub Markdown comments with:
1. Hidden report signature for idempotent upserting.
2. Prominent verdict status headers.
3. Security warning banner when prompt injections are detected.
4. Grounded changelog quotes and repository blast-radius call sites.
5. Collapsible audit provenance metadata.
"""

from typing import Optional
from risk_agent.models.schemas import RiskReport, SeverityVerdict
from risk_agent.security.injection_detector import InjectionResult

REPORT_SIGNATURE = "<!-- dependency-impact-analyzer-report -->"


def format_pr_comment(
    report: RiskReport,
    injection_result: Optional[InjectionResult] = None,
    delivery_id: Optional[str] = None,
    execution_latency_ms: Optional[float] = None,
) -> str:
    """Renders a complete, high-polish GitHub PR comment in Markdown."""
    # 1. Status Pill & Emoji
    verdict = report.verdict
    if verdict == SeverityVerdict.NO_RISK_FOUND:
        header_title = "🟢 Dependency Impact: NO_RISK_FOUND"
        verdict_badge = "**🟢 NO_RISK_FOUND**"
    elif verdict == SeverityVerdict.REVIEW:
        header_title = "🟡 Dependency Impact: REVIEW NEEDED"
        verdict_badge = "**🟡 REVIEW**"
    else:
        header_title = "🔴 Dependency Impact: HIGH RISK"
        verdict_badge = "**🔴 RISKY**"

    lines = [
        REPORT_SIGNATURE,
        f"## {header_title}",
        "",
    ]

    # 2. Injection Warning Banner (if detected)
    if injection_result and injection_result.detected:
        pattern_str = injection_result.pattern_type.value if injection_result.pattern_type else "ADVERSARIAL_INJECTION"
        snippet_str = injection_result.sanitized_snippet or "N/A"
        lines.extend([
            "> [!WARNING]",
            "> ### 🛡️ Security Tripwire: Adversarial Prompt Injection Detected & Quarantined",
            "> **An adversarial prompt injection attempt was detected in this pull request and was safely defused.**",
            f"> - **Pattern Detected:** `{pattern_str}`",
            f"> - **Defanged Excerpt:** `{snippet_str}`",
            "> - **Protection Applied:** The untrusted input was isolated. The policy engine evaluated this PR strictly via deterministic static AST analysis and verified upstream release notes.",
            "",
        ])

    # 3. Upgrade Summary Table
    bump_type_str = report.bump_type.value if hasattr(report.bump_type, "value") else str(report.bump_type)
    lines.extend([
        "| Package | Upgrade | Final Verdict | Risk Floor | Release Notes |",
        "|---|---|---|---|---|",
        f"| `{report.package_name}` | `{report.old_version}` ➔ `{report.new_version}` ({bump_type_str}) | {verdict_badge} | `{report.risk_floor.value}` | {'✅ Available' if report.release_notes_available else '⚠️ Missing'} |",
        "",
    ])

    # 4. Assessment Summary / Reasons
    lines.append("### 📋 Assessment Summary")
    for reason in report.reasons:
        lines.append(f"- {reason}")
    lines.append("")

    # 5. Verified Upstream Breaking Changes / Deprecations
    if report.verified_claims:
        lines.extend([
            "### 🔬 Verified Upstream Changes",
            "| Change Type | Affected API | Grounded Quote from Changelog | Verification |",
            "|---|---|---|---|",
        ])
        for claim in report.verified_claims:
            claim_type = claim.claim_type.value if hasattr(claim.claim_type, "value") else str(claim.claim_type)
            api_str = f"`{claim.affected_api}`" if claim.affected_api else "_N/A_"
            # Defang and truncate quote if needed
            safe_quote = claim.quoted_text.replace("\n", " ").strip()
            if len(safe_quote) > 120:
                safe_quote = safe_quote[:117] + "..."
            lines.append(f"| `{claim_type}` | {api_str} | *\"{safe_quote}\"* | ✅ Grounded |")
        lines.append("")

    # 6. Repository Call Sites & Blast Radius
    lines.append("### 🎯 Blast Radius & Code Usages")
    if report.potential_usages:
        lines.extend([
            "| Repository File | Line | Confidence | Matched Code Symbol |",
            "|---|---|---|---|",
        ])
        for usage in report.potential_usages:
            conf_str = usage.confidence_tier.value if hasattr(usage.confidence_tier, "value") else str(usage.confidence_tier)
            snippet = usage.code_snippet or usage.matched_symbol
            safe_code = snippet.replace("\n", " ").strip()
            if len(safe_code) > 60:
                safe_code = safe_code[:57] + "..."
            lines.append(f"| `{usage.file_path}` | `{usage.line_number}` | `{conf_str}` | `{safe_code}` |")
        lines.append("")
    else:
        lines.extend([
            "_No direct affected usages detected in repository source files._",
            "",
        ])

    # 7. Collapsible Audit & Provenance Metadata
    latency_str = f"{execution_latency_ms:.1f} ms" if execution_latency_ms is not None else "N/A"
    lines.extend([
        "<details>",
        "<summary>⚙️ Analysis & Audit Provenance</summary>",
        "",
        f"- **Analysis Timestamp:** `{report.timestamp}`",
        f"- **Upstream Source URL:** {report.source_url or '_N/A_'}",
        f"- **GitHub Delivery ID:** `{delivery_id or 'N/A'}`",
        f"- **Evaluation Model:** `{report.model_id or 'Vertex AI Gemini'}`",
        f"- **Prompt Template:** `{report.prompt_version or 'v1.0'}`",
        f"- **Execution Latency:** `{latency_str}`",
        "</details>",
        "",
        "---",
        "<sub>*Automated dependency impact evaluation by [Dependency Upgrade Risk Agent](https://github.com/Madhesh4124/dependency-risk-agent).*</sub>",
    ])

    return "\n".join(lines)
