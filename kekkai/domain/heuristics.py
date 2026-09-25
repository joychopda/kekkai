"""The editable data half of the deterministic layer: token sets and regexes.

Lifted from agent-action-sentinel's `anomaly.py` vocabulary and supply-chain-hunter's env
sentinels, unified into one set. Those two repos carry overlapping regexes that disagree
slightly; this module is the single reconciled vocabulary, so a pattern is fixed in one place.
"""

from __future__ import annotations

import re
import shlex

SECRET_PATTERNS = [
    r"\.env(\.[\w-]+)?$",
    r"\.env\b",
    r"id_rsa",
    r"id_ed25519",
    r"id_ecdsa",
    r"\.ssh/",
    r"\.aws/(credentials|config)",
    r"\.npmrc",
    r"\.pypirc",
    r"\.netrc",
    r"\.kube/config",
    r"\.docker/config\.json",
    r"credentials(\.json|\.yaml|\.yml)?",
    r"secrets?(\.json|\.yaml|\.yml|\.env)?",
    r"\.pem\b",
    r"\.p12\b",
    r"\.pfx\b",
    r"\bAPI[_-]?KEY\b",
    r"\bSECRET[_-]?KEY\b",
    r"\bACCESS[_-]?TOKEN\b",
    r"\bPRIVATE[_-]?KEY\b",
    r"vault",
    r"keychain",
]
SECRET_RE = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)

# Shell utilities are anchored to a command position (start, whitespace, or a shell operator)
# so a path substring like "~/.ssh/id_rsa" does not false-match the ssh client. That bug was
# already found and fixed once in agent-action-sentinel; the anchoring is the fix.
NETWORK_RE = re.compile(
    r"""(?xi)
    (?:^|[\s;&|`(])(?:curl|wget|nc|ncat|telnet|ftp|scp|sftp|ssh|rsync)\b |
    /dev/tcp/ | /dev/udp/ |
    \bInvoke-WebRequest\b | \bInvoke-RestMethod\b |
    requests\.(get|post|put) | \burllib\b | \bhttpx\b | \baiohttp\b |
    \bnpm\s+publish\b | \bgit\s+push\b | \bpip\b\s+.*--index-url |
    \bnpx\b\s+.*http
    """
)

DELETE_RE = re.compile(
    r"""(?xi)
    \brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-rf|-fr|-r|-f)\b |
    \bfind\b.*\-delete |
    \bshred\b |
    \bgit\s+clean\s+-[a-z]*f |
    \bmkfs\b | \bdd\s+if=.*of=/dev/
    """
)

PRIVILEGE_RE = re.compile(
    r"""(?xi)
    (?:^|[\s;&|`(])(?:sudo|doas|su)\b |
    \bchmod\s+(?:[0-7]*777|\+s)\b |
    \bchown\s+root\b |
    \blaunchctl\b | \bsystemctl\b | \bcrontab\b |
    \bdefaults\s+write\b |
    \beval\b | \bexec\b
    """
)

# Piping anything into an interpreter executes content this layer never got to inspect --
# `curl ... | sh`, `base64 -d | sh`. The decode utilities are listed alongside because
# obfuscation is what they are doing here: the payload is deliberately unreadable as text.
DYNAMIC_EXEC_RE = re.compile(
    r"""(?xi)
    \|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b |
    \|\s*(?:python[0-9.]*|perl|ruby|node)\b |
    \bbase64\s+(?:-d|--decode|-D)\b |
    \bxxd\s+-r\b |
    \bopenssl\s+enc\s+-d\b
    """
)

# Shapes that write rather than read. Used to rate writes outside the working tree, and
# writes to credential paths, above the equivalent read.
WRITE_REDIRECT_RE = re.compile(r">>?\s*\S|\btee\b|\bdd\s+of=", re.IGNORECASE)
WRITE_TOOLS = frozenset({"Write", "Edit", "NotebookEdit", "MultiEdit", "create_file", "write_file"})

# Tools that reach the network by their nature, whatever their arguments say.
NETWORK_TOOLS = frozenset({"WebFetch", "WebSearch", "fetch", "browse"})

# Tools that cannot modify state or egress. Membership is what lets the prefilter make a
# *positive* determination of safety, which is what keeps agents working when a classifier is
# down -- absence of findings is not the same as proven safe.
READ_ONLY_TOOLS = frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoRead"})

# Environment variables worth exfiltrating. Split follows supply-chain-hunter: the weak set is
# ubiquitous in CI and benign on its own, so only the strong set raises severity by itself.
WEAK_SENTINELS = frozenset(
    {"CI", "HOME", "PATH", "USER", "SHELL", "PWD", "LANG", "TERM", "GITHUB_ACTIONS", "RUNNER_OS"}
)
STRONG_SENTINELS = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ACCOUNT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCP_PROJECT",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "KUBECONFIG",
        "DOCKER_PASSWORD",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "TWINE_PASSWORD",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "SLACK_TOKEN",
        "STRIPE_SECRET_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "TYPESAFE_API_KEY",
        "HF_TOKEN",
        "DATABASE_URL",
        "REDIS_URL",
        "SENTRY_DSN",
        "PRIVATE_KEY",
        "SSH_AUTH_SOCK",
    }
)

_HOST_RE = re.compile(r"https?://([^/\s\"']+)", re.IGNORECASE)


def is_write_intent(tool_name: str, text: str) -> bool:
    """Whether this call writes rather than only reads."""
    return tool_name in WRITE_TOOLS or bool(WRITE_REDIRECT_RE.search(text))


def split_argv(command: str) -> tuple[tuple[str, ...], bool]:
    """Parse a shell command into argv.

    Returns (argv, parseable). Unparseable input yields `parseable=False` and an empty argv --
    and the caller must treat that as *not safe*, never as safe. Full shell grammar
    (subshells, eval, command substitution) is deliberately out of scope; anything `shlex`
    cannot handle escalates or blocks rather than being waved through.
    """
    try:
        return tuple(shlex.split(command, posix=True)), True
    except ValueError:
        return (), False


def extract_paths(text: str) -> tuple[str, ...]:
    """Best-effort extraction of path-like tokens."""
    argv, ok = split_argv(text)
    tokens = argv if ok else tuple(text.split())
    return tuple(t for t in tokens if not t.startswith("-") and ("/" in t or t.startswith(("~", "$"))))


def extract_hosts(text: str) -> tuple[str, ...]:
    """Hostnames of any URL appearing in the text."""
    return tuple(sorted({m.group(1).split("@")[-1].split(":")[0] for m in _HOST_RE.finditer(text)}))


def mentioned_sentinels(text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Environment variable names present in the text, split weak/strong."""
    found = {name for name in STRONG_SENTINELS | WEAK_SENTINELS if name in text}
    return frozenset(found & STRONG_SENTINELS), frozenset(found & WEAK_SENTINELS)
