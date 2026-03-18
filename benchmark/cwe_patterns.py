"""CWE-specific pattern detection for evaluating model-generated patches.

Each CWE has a set of regex patterns that indicate the typical fix approach
was applied. These are run against added lines in a patch.

A separate removal registry detects vulnerable code patterns that should
be removed or replaced by a correct fix.
"""

from __future__ import annotations

import re

# Registry: CWE ID → list of compiled regex patterns for FIX detection
CWE_PATTERN_REGISTRY: dict[str, list[re.Pattern]] = {
    "CWE-79": [
        re.compile(r"htmlspecialchars|htmlentities", re.IGNORECASE),
        re.compile(r"html\.escape|markupsafe\.escape|escape_html", re.IGNORECASE),
        re.compile(r"DOMPurify\.sanitize|sanitize[Hh]tml", re.IGNORECASE),
        re.compile(r"encodeURIComponent|encodeURI", re.IGNORECASE),
        re.compile(r"xss|sanitiz[ei]", re.IGNORECASE),
        re.compile(r"\{\{.*\|.*escape", re.IGNORECASE),  # Template escaping
    ],
    "CWE-89": [
        re.compile(r"prepare[d]?\s*\(|\.prepare\(", re.IGNORECASE),
        re.compile(r"bindParam|bind_param|bindValue", re.IGNORECASE),
        re.compile(r"parameterized|placeholder", re.IGNORECASE),
        re.compile(r"\?\s*,|\$\d+|:\w+", re.IGNORECASE),  # Parameterized placeholders
        re.compile(r"cursor\.execute\(.*%s", re.IGNORECASE),
        re.compile(r"sql\.Param|sqlx?\.\w+Query", re.IGNORECASE),
    ],
    "CWE-22": [
        re.compile(r"realpath|os\.path\.realpath|path\.resolve", re.IGNORECASE),
        re.compile(r"normalize|path\.normalize", re.IGNORECASE),
        re.compile(r"startsWith|starts_with|\.startswith\(", re.IGNORECASE),
        re.compile(r"abspath|os\.path\.abspath", re.IGNORECASE),
        re.compile(r"filepath\.Clean|filepath\.Abs", re.IGNORECASE),
        re.compile(r"\.\.[/\\]|path\s*traversal", re.IGNORECASE),
    ],
    "CWE-352": [
        re.compile(r"csrf[_-]?token|anti[_-]?csrf|_token", re.IGNORECASE),
        re.compile(r"verify[_-]?csrf|check[_-]?csrf|validate[_-]?token", re.IGNORECASE),
        re.compile(r"@csrf|csrf_protect|CsrfViewMiddleware", re.IGNORECASE),
        re.compile(r"SameSite|same_site", re.IGNORECASE),
    ],
    "CWE-862": [
        re.compile(r"permission|authorize|isAuthorized|has_perm", re.IGNORECASE),
        re.compile(r"@login_required|@require_auth|@authenticated", re.IGNORECASE),
        re.compile(r"role[_-]?check|access[_-]?control|canAccess", re.IGNORECASE),
        re.compile(r"forbidden|403|Unauthorized", re.IGNORECASE),
    ],
    "CWE-863": [
        re.compile(r"permission|authorize|isAuthorized|has_perm", re.IGNORECASE),
        re.compile(r"role[_-]?check|access[_-]?control", re.IGNORECASE),
        re.compile(r"owner[_-]?check|belongs[_-]?to|user[_-]?id\s*[!=]=", re.IGNORECASE),
    ],
    "CWE-94": [
        re.compile(r"(?<![\w])eval\s*\(", re.IGNORECASE),  # Removal or guarding of eval
        re.compile(r"(?<![\w])exec\s*\(", re.IGNORECASE),
        re.compile(r"sandbox|safeEval|safe_eval", re.IGNORECASE),
        re.compile(r"Function\s*\(|new\s+Function", re.IGNORECASE),
        re.compile(r"child_process|subprocess|spawn|execFile", re.IGNORECASE),
    ],
    "CWE-400": [
        re.compile(r"limit|max[_-]?(size|length|count|items|depth)", re.IGNORECASE),
        re.compile(r"timeout|deadline|time[_-]?limit", re.IGNORECASE),
        re.compile(r"rate[_-]?limit|throttl", re.IGNORECASE),
        re.compile(r"MAX_|LIMIT_|cap\s*=", re.IGNORECASE),
    ],
    "CWE-20": [
        re.compile(r"validate|validator|isValid|is_valid", re.IGNORECASE),
        re.compile(r"re\.match|re\.search|regex|pattern\s*=", re.IGNORECASE),
        re.compile(r"isinstance|type\s*check|typeof\s", re.IGNORECASE),
        re.compile(r"parseInt|parseFloat|Number\(|int\(|float\(", re.IGNORECASE),
        re.compile(r"min\s*=|max\s*=|range\s*check|bounds", re.IGNORECASE),
    ],
    # ── Additional CWEs ──────────────────────────────────────────────────
    "CWE-77": [  # Command injection
        re.compile(r"shlex\.quote|escapeshellarg|escapeshellcmd", re.IGNORECASE),
        re.compile(r"subprocess\.\w+\(.*\bshell\s*=\s*False", re.IGNORECASE),
        re.compile(r"ProcessBuilder|execFile", re.IGNORECASE),
    ],
    "CWE-78": [  # OS command injection
        re.compile(r"shlex\.quote|escapeshellarg|escapeshellcmd", re.IGNORECASE),
        re.compile(r"subprocess\.run\(.*\[", re.IGNORECASE),  # list form = no shell
        re.compile(r"shell\s*=\s*False", re.IGNORECASE),
    ],
    "CWE-74": [  # Injection (general)
        re.compile(r"escape|sanitiz|encode|parameteriz", re.IGNORECASE),
        re.compile(r"prepared?\s*statement|bind", re.IGNORECASE),
    ],
    "CWE-200": [  # Information exposure
        re.compile(r"redact|mask|censor|\*{3,}", re.IGNORECASE),
        re.compile(r"strip.*(?:token|key|secret|password)", re.IGNORECASE),
        re.compile(r"(?:error|exception).*(?:generic|sanitiz)", re.IGNORECASE),
    ],
    "CWE-1321": [  # Prototype pollution
        re.compile(r"__proto__|prototype|constructor", re.IGNORECASE),
        re.compile(r"Object\.freeze|Object\.create\(null\)", re.IGNORECASE),
        re.compile(r"hasOwnProperty|Object\.hasOwn", re.IGNORECASE),
    ],
    "CWE-1333": [  # ReDoS
        re.compile(r"timeout|maxLength|max_length|limit", re.IGNORECASE),
        re.compile(r"re2|RE2|possessive|atomic", re.IGNORECASE),
        re.compile(r"re\.compile.*\{.*\d+\}", re.IGNORECASE),  # bounded quantifier
    ],
    "CWE-601": [  # Open redirect
        re.compile(r"(?:url|redirect).*(?:whitelist|allowlist|startsWith|host)", re.IGNORECASE),
        re.compile(r"(?:validate|check|verify).*(?:url|redirect|host)", re.IGNORECASE),
        re.compile(r"same[_-]?origin|relative[_-]?url", re.IGNORECASE),
    ],
    "CWE-770": [  # Resource allocation without limits
        re.compile(r"limit|max[_-]?(?:size|count|depth|items)", re.IGNORECASE),
        re.compile(r"throttl|rate[_-]?limit|backpressure", re.IGNORECASE),
    ],
    "CWE-674": [  # Uncontrolled recursion
        re.compile(r"max[_-]?depth|recursion[_-]?limit|depth[_-]?limit", re.IGNORECASE),
        re.compile(r"sys\.setrecursionlimit|stack[_-]?(?:size|limit)", re.IGNORECASE),
        re.compile(r"iterative|(?:while|for).*(?:stack|queue)", re.IGNORECASE),
    ],
    "CWE-125": [  # Out-of-bounds read
        re.compile(r"bounds?\s*check|range\s*check|length\s*check", re.IGNORECASE),
        re.compile(r"(?:if|assert).*(?:len|size|count|index)\s*[<>=]", re.IGNORECASE),
    ],
    "CWE-287": [  # Improper authentication
        re.compile(r"authenticat|verify[_-]?(?:password|credentials|token)", re.IGNORECASE),
        re.compile(r"bcrypt|argon2|scrypt|pbkdf2", re.IGNORECASE),
        re.compile(r"constant[_-]?time[_-]?(?:compare|equal)", re.IGNORECASE),
    ],
    "CWE-502": [  # Deserialization of untrusted data
        re.compile(r"safe[_-]?load|yaml\.safe_load|json\.loads", re.IGNORECASE),
        re.compile(r"whitelist|allowlist|allowed[_-]?class", re.IGNORECASE),
        re.compile(r"serialization[_-]?filter|ObjectInputFilter", re.IGNORECASE),
    ],
    "CWE-918": [  # SSRF
        re.compile(r"(?:url|host).*(?:whitelist|allowlist|blocklist|denylist)", re.IGNORECASE),
        re.compile(r"(?:private|internal|loopback|127\.0\.0\.1|0\.0\.0\.0)", re.IGNORECASE),
        re.compile(r"(?:validate|check|verify).*(?:url|host|ip)", re.IGNORECASE),
    ],
    "CWE-434": [  # Unrestricted file upload
        re.compile(r"(?:file|mime)[_-]?type.*(?:check|validate|whitelist|allow)", re.IGNORECASE),
        re.compile(r"(?:allowed|valid)[_-]?(?:extension|type|mime)", re.IGNORECASE),
    ],
    "CWE-476": [  # NULL pointer dereference
        re.compile(r"(?:if|assert|guard).*(?:!=\s*null|!==?\s*null|is\s+not\s+None)", re.IGNORECASE),
        re.compile(r"\?\.|Optional|\.orElse|\.unwrap_or", re.IGNORECASE),
    ],
}

# ── Removal registry: patterns matching VULNERABLE code that should be removed ──

CWE_REMOVAL_REGISTRY: dict[str, list[re.Pattern]] = {
    "CWE-79": [
        re.compile(r"innerHTML\s*[+=]", re.IGNORECASE),
        re.compile(r"document\.write\s*\(", re.IGNORECASE),
        re.compile(r"\.html\s*\(", re.IGNORECASE),  # jQuery .html()
        re.compile(r"v-html|dangerouslySetInnerHTML", re.IGNORECASE),
    ],
    "CWE-89": [
        re.compile(r"[\"'].*\+.*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)", re.IGNORECASE),
        re.compile(r"string\.Format.*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
        re.compile(r"f[\"'].*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
    ],
    "CWE-94": [
        re.compile(r"(?<![\w])eval\s*\(", re.IGNORECASE),
        re.compile(r"(?<![\w])exec\s*\(", re.IGNORECASE),
        re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
        re.compile(r"child_process|subprocess\.call|os\.system", re.IGNORECASE),
    ],
    "CWE-22": [
        re.compile(r"\.\./|\.\.\\\\", re.IGNORECASE),
        re.compile(r"user[_-]?input.*(?:open|read|include|require)", re.IGNORECASE),
    ],
    "CWE-78": [
        re.compile(r"os\.system\s*\(|subprocess\.call\(.*shell\s*=\s*True", re.IGNORECASE),
        re.compile(r"Runtime\.getRuntime\(\)\.exec\(", re.IGNORECASE),
    ],
    "CWE-502": [
        re.compile(r"pickle\.loads?|yaml\.load\(|unserialize\(", re.IGNORECASE),
        re.compile(r"ObjectInputStream|readObject\(", re.IGNORECASE),
    ],
}


def detect_cwe_patterns(
    added_lines: str,
    cwe_ids: list[str],
    removed_lines: str = "",
) -> bool:
    """Check if patch contains fix patterns for any of the given CWEs.

    Checks both added lines (for fix patterns) and removed lines
    (for vulnerable code removal patterns).

    Args:
        added_lines: The concatenated text of lines added by the patch.
        cwe_ids: List of CWE IDs to check patterns for.
        removed_lines: The concatenated text of lines removed by the patch.

    Returns:
        True if at least one CWE pattern is detected.
    """
    # Check added lines against fix patterns
    for cwe in cwe_ids:
        patterns = CWE_PATTERN_REGISTRY.get(cwe, [])
        for pattern in patterns:
            if pattern.search(added_lines):
                return True

    # Check removed lines against vulnerability patterns
    if removed_lines:
        for cwe in cwe_ids:
            patterns = CWE_REMOVAL_REGISTRY.get(cwe, [])
            for pattern in patterns:
                if pattern.search(removed_lines):
                    return True

    return False


def detect_removal_patterns(removed_lines: str, cwe_ids: list[str]) -> bool:
    """Check if removed lines contain vulnerable code patterns for given CWEs.

    Args:
        removed_lines: The concatenated text of lines removed by the patch.
        cwe_ids: List of CWE IDs to check patterns for.

    Returns:
        True if at least one vulnerable code pattern is found in removed lines.
    """
    for cwe in cwe_ids:
        patterns = CWE_REMOVAL_REGISTRY.get(cwe, [])
        for pattern in patterns:
            if pattern.search(removed_lines):
                return True
    return False


def extract_added_lines(diff_text: str) -> str:
    """Extract only the added lines (lines starting with '+') from a unified diff."""
    added = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])  # Strip leading '+'
    return "\n".join(added)
