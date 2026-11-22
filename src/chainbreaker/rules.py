"""Detection rules.

Every rule reports what an attacker needs before the weakness is usable (``requires``) and
what it hands them once used (``grants``). The chain engine links those together.

Add a line containing ``chainbreaker:ignore`` to silence a finding on that line.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, FrozenSet, Iterable, Iterator, List, Optional, Tuple

from .models import FileContext, Finding

IGNORE_MARK = "chainbreaker:ignore"
CODE_KINDS = ("python", "js")
S = frozenset


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    kinds: Tuple[str, ...]  # empty = every scanned file
    fix: str
    description: str
    func: Callable[[FileContext], Iterable["Hit"]]


@dataclass
class Hit:
    line: int
    evidence: str
    requires: FrozenSet[str]
    grants: FrozenSet[str]
    confidence: float = 0.8
    title: Optional[str] = None
    severity: Optional[str] = None
    fix: Optional[str] = None


RULES: List[Rule] = []


def rule(id: str, title: str, severity: str, kinds: Iterable[str], fix: str, description: str):
    def deco(fn):
        RULES.append(Rule(id, title, severity, tuple(kinds), fix, description, fn))
        return fn

    return deco


def grep(ctx: FileContext, pattern: "re.Pattern[str]") -> Iterator[Tuple[int, str, "re.Match[str]"]]:
    for i, line in enumerate(ctx.lines, 1):
        if IGNORE_MARK in line:
            continue
        m = pattern.search(line)
        if m:
            yield i, line, m


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + f" ({len(value)} chars)"


def snippet(line: str) -> str:
    line = line.strip()
    return line if len(line) <= 140 else line[:137] + "..."


def run_rules(ctx: FileContext) -> Iterator[Finding]:
    for r in RULES:
        if r.kinds and ctx.kind not in r.kinds:
            continue
        for h in r.func(ctx):
            yield Finding(
                rule=r.id,
                title=h.title or r.title,
                severity=h.severity or r.severity,
                file=ctx.path,
                line=h.line,
                evidence=h.evidence[:200],
                fix=h.fix or r.fix,
                requires=S(h.requires),
                grants=S(h.grants),
                confidence=h.confidence,
            )


# ---------------------------------------------------------------- secrets

AWS_KEY = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")


@rule("CB101", "Cloud access key committed", "critical", (),
      "Revoke the key in the cloud console now, then load it from a secret manager or CI secret.",
      "An AWS access key ID is in the repository. Anyone who can read the code can use the account.")
def cloud_key(ctx):
    for n, _line, m in grep(ctx, AWS_KEY):
        yield Hit(n, f"AWS key {redact(m.group(1))}", S({"source_read"}), S({"cloud_creds"}), 0.95)


DB_URL = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|sqlserver)://"
    r"(?P<user>[^:\s/@'\"]+):(?P<pw>[^@\s'\"]+)@(?P<host>[^/\s'\"]+)"
)


@rule("CB102", "Database URL with password committed", "high", (),
      "Rotate the database password and read the URL from the environment or a secret manager.",
      "A connection string with a username and password is in the repository.")
def db_url(ctx):
    for n, _line, m in grep(ctx, DB_URL):
        pw = m.group("pw")
        if pw.startswith(("$", "{", "<", "%")) or pw.lower() in PLACEHOLDERS:
            continue
        ev = f"{m.group('scheme')}://{m.group('user')}:{redact(pw)}@{m.group('host')}"
        yield Hit(n, ev, S({"source_read"}), S({"db_creds"}), 0.9)


PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


@rule("CB103", "Private key committed", "critical", (),
      "Remove the key from the repo and its history, revoke it, and issue a new one.",
      "A private key is in the repository.")
def private_key(ctx):
    for n, _line, _m in grep(ctx, PRIVATE_KEY):
        if "ENCRYPTED" in ctx.lines[n - 1]:
            continue
        yield Hit(n, "private key block (contents hidden)", S({"source_read"}), S({"server_key"}), 0.7)


GENERIC_SECRET = re.compile(
    r"""(?ix)
    (?P<key>[a-z0-9_.\-]*(?:secret|passw(?:or)?d|pwd|token|api[_\-]?key|access[_\-]?key)[a-z0-9_.\-]*)
    ["']?\s*(?::=|=>|=|:)\s*
    (?P<q>["'`]?)(?P<val>[^"'`\s#,;)]{6,})(?P=q)
    """
)
NOT_SECRET_KEY = re.compile(
    r"(?i)(file|path|dir|name|length|len|type|field|header|tokenizer|tokens|expir\w*|ttl|count|"
    r"min|max|policy|prompt|label|placeholder|input|url|uri|endpoint|_id|reset|hash|regex|pattern)$"
)
PLACEHOLDERS = {
    "changeme_in_prod", "xxxxxx", "xxxxxxxx", "placeholder", "example", "redacted", "your_secret",
    "yoursecret", "your-secret", "none", "null", "undefined", "true", "false", "password_here",
    "<secret>", "secret_here", "dummy", "******", "********",
}
DYNAMIC_HINTS = ("os.environ", "getenv", "process.env", "env(", "environ", "config.", "settings.",
                 "secrets.", "vault", "import.meta.env")


def secret_kind(key: str) -> Tuple[str, str, str]:
    k = key.lower()
    if re.search(r"jwt|signing|secret_key|session|cookie|flask_secret|app_secret", k):
        return "jwt_secret", "Hardcoded token-signing secret", "high"
    if re.search(r"postgres|mysql|mariadb|mongo|redis|db_|_db|database|sql", k):
        return "db_creds", "Hardcoded database password", "high"
    if re.search(r"aws|gcp|azure|cloud|s3", k):
        return "cloud_creds", "Hardcoded cloud credential", "critical"
    return "api_token", "Hardcoded credential", "high"


@rule("CB104", "Hardcoded credential", "high", (),
      "Move the value to an environment variable or secret manager, and rotate it since it has been exposed.",
      "A password, token or secret is written directly into a file.")
def generic_secret(ctx):
    for n, line, m in grep(ctx, GENERIC_SECRET):
        key, val, quoted = m.group("key"), m.group("val"), bool(m.group("q"))
        if NOT_SECRET_KEY.search(key):
            continue
        if ctx.kind in CODE_KINDS and not quoted:
            continue  # unquoted in code is a variable or expression, not a literal
        low = val.lower()
        if low in PLACEHOLDERS or val.startswith(("$", "{", "<", "%", "@")) or len(set(val)) < 3:
            continue
        if any(h in line for h in DYNAMIC_HINTS) and not quoted:
            continue
        if DB_URL.search(line) or AWS_KEY.search(line):
            continue  # reported by a more specific rule
        cap, title, sev = secret_kind(key)
        yield Hit(n, f"{key} = {redact(val)}", S({"source_read"}), S({cap}), 0.85, title=title, severity=sev)


# ---------------------------------------------------------------- web apps

FLASK_DEBUG = re.compile(r"\.run\([^)]*debug\s*=\s*True")
ENV_DEBUG = re.compile(r"^\s*(?:export\s+)?(?:FLASK_DEBUG\s*=\s*[\"']?(?:1|true)|FLASK_ENV\s*=\s*[\"']?development)", re.I)


@rule("CB201", "Interactive debugger exposed", "critical", ("python", "env", "shell", "compose", "docker"),
      "Never enable debug mode outside your laptop. Drive it from an env var that defaults to off.",
      "Flask/Werkzeug debug mode serves an in-browser Python console. Its PIN has been bypassed many "
      "times, and anyone who gets past it runs code on the server.")
def flask_debug(ctx):
    pattern = FLASK_DEBUG if ctx.kind == "python" else ENV_DEBUG
    for n, line, _m in grep(ctx, pattern):
        yield Hit(n, snippet(line), S({"internet"}), S({"rce"}), 0.6)


DJANGO_DEBUG = re.compile(r"^\s*DEBUG\s*=\s*True\b")


@rule("CB202", "Django DEBUG enabled", "medium", ("python",),
      "Set DEBUG = False in production settings and serve a custom error page.",
      "Django debug pages show stack traces, settings and SQL to anyone who triggers an error.")
def django_debug(ctx):
    if "settings" not in ctx.path.lower():
        return
    for n, line, _m in grep(ctx, DJANGO_DEBUG):
        yield Hit(n, snippet(line), S({"internet"}), S({"info_leak"}), 0.8)


ROUTE_PY = re.compile(r"""@\s*\w+\.(?:route|get|post|put|patch|delete|api_route)\(\s*["'](?P<path>/[^"']*)["']""")
ROUTE_JS = re.compile(
    r"""\b(?:app|router|server|api)\.(?:get|post|put|patch|delete|all|use)\(\s*["'`](?P<path>/[^"'`]*)["'`]\s*,?(?P<rest>.*)"""
)
ADMIN_PATH = re.compile(r"(?i)/(?:admin|internal|manage|management|superuser|staff)(?:/|$|[^a-z])")
AUTH_HINT = re.compile(
    r"(?i)(login_required|auth|jwt_required|permission|roles?_required|admin_required|requires_|"
    r"current_user|verify|check_admin|is_admin|isadmin|depends\(|security\(|abort\(\s*40[13]|protect|"
    r"passport|ensure|guard|session\[)"
)


@rule("CB203", "Admin route with no authentication", "high", CODE_KINDS,
      "Put the route behind an auth check that also verifies the admin role (decorator or middleware).",
      "A route under /admin (or similar) has no login or role check near it.")
def unauth_admin(ctx):
    text = ctx.text
    if ctx.kind == "python":
        if "before_request" in text and AUTH_HINT.search(text):
            return  # global guard, assume it covers admin routes
        for n, line, m in grep(ctx, ROUTE_PY):
            if not ADMIN_PATH.search(m.group("path") + "/"):
                continue
            block = []
            j = n - 2
            while j >= 0 and ctx.lines[j].strip().startswith("@"):
                block.append(ctx.lines[j])
                j -= 1
            k, body = n, 0
            seen_def = False
            while k < len(ctx.lines) and body < 7:
                cur = ctx.lines[k]
                block.append(cur)
                if cur.strip().startswith(("def ", "async def ")):
                    seen_def = True
                elif seen_def:
                    body += 1
                k += 1
            if AUTH_HINT.search("\n".join(block)):
                continue
            yield Hit(n, snippet(line), S({"internet"}), S({"admin_access"}), 0.8)
    else:
        if re.search(r"\b(?:app|router)\.use\(\s*(?!['\"`])[^)]*(auth|protect|guard|passport|jwt)", text, re.I):
            return  # global auth middleware
        for n, line, m in grep(ctx, ROUTE_JS):
            if not ADMIN_PATH.search(m.group("path") + "/"):
                continue
            if AUTH_HINT.search(m.group("rest")):
                continue
            yield Hit(n, snippet(line), S({"internet"}), S({"admin_access"}), 0.8)


SQLI_PY = re.compile(
    r"""\.(?:execute|executemany|executescript|raw|extra)\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format\())"""
    r"""|\btext\(\s*f["']"""
)
SQLI_JS = re.compile(r"""\.(?:query|execute|raw|unsafe)\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)""")


@rule("CB204", "SQL built from strings", "critical", CODE_KINDS,
      "Use parameterised queries (placeholders + a parameters argument) or the ORM's query builder.",
      "A SQL query is assembled with f-strings, concatenation or formatting, so input can rewrite it.")
def sql_injection(ctx):
    pattern = SQLI_PY if ctx.kind == "python" else SQLI_JS
    for n, line, _m in grep(ctx, pattern):
        yield Hit(n, snippet(line), S({"internet"}), S({"db_read", "db_write"}), 0.75)


CMD_PY = re.compile(
    r"""subprocess\.\w+\([^#]*shell\s*=\s*True"""
    r"""|\bos\.(?:system|popen)\(\s*(?:f["']|[^)]*\+|[^)]*\.format\(|[^)]*%)"""
)
CMD_JS = re.compile(r"""\b(?:exec|execSync)\(\s*(?:`[^`]*\$\{|[^)]*\+)""")
DYNAMIC_STR = re.compile(r"""f["']|\+|\.format\(|%\s*\(|%\s*\w|\$\{""")


@rule("CB205", "Shell command built from input", "critical", CODE_KINDS,
      "Pass arguments as a list without shell=True, and validate input against an allow-list.",
      "A shell command is built from strings, so input can append its own commands.")
def command_injection(ctx):
    pattern = CMD_PY if ctx.kind == "python" else CMD_JS
    for n, line, _m in grep(ctx, pattern):
        if ctx.kind == "python" and "shell" in line and not DYNAMIC_STR.search(line):
            continue
        yield Hit(n, snippet(line), S({"internet"}), S({"rce"}), 0.7)


DESER = [
    (re.compile(r"\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)"), "yaml.load without SafeLoader", 0.6),
    (re.compile(r"\byaml\.unsafe_load\("), "yaml.unsafe_load", 0.7),
    (re.compile(r"\b(?:pickle|cPickle|dill|marshal)\.loads?\("), "pickle/marshal on data", 0.55),
    (re.compile(r"\bjsonpickle\.decode\("), "jsonpickle.decode", 0.6),
    (re.compile(r"\beval\(\s*(?:request|req\.|flask\.request|input\()"), "eval on request data", 0.8),
    (re.compile(r"\b(?:serialize|nodeSerialize|serializer)\.unserialize\("), "node-serialize unserialize", 0.6),
]


@rule("CB206", "Unsafe deserialisation", "critical", CODE_KINDS,
      "Use safe loaders (yaml.safe_load, json) and never unpickle or eval data you did not create.",
      "Loading untrusted data with these functions can construct objects that run code.")
def unsafe_deser(ctx):
    for i, line in enumerate(ctx.lines, 1):
        if IGNORE_MARK in line:
            continue
        for pattern, what, conf in DESER:
            if pattern.search(line):
                yield Hit(i, f"{what}: {snippet(line)}", S({"internet"}), S({"rce"}), conf)
                break


CORS_PATTERNS = [
    re.compile(r"""CORS\([^)]*(?:origins\s*=\s*["']\*|supports_credentials\s*=\s*True)"""),
    re.compile(r"""CORS\(\s*app\s*\)\s*$"""),
    re.compile(r"""\bcors\(\s*\)"""),
    re.compile(r"""\borigin\s*:\s*(?:true|["']\*["'])"""),
    re.compile(r"""Access-Control-Allow-Origin["']?\s*[,:=]\s*["']?\*""", re.I),
    re.compile(r"""CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True"""),
]


@rule("CB207", "CORS open to every origin", "medium", CODE_KINDS + ("config", "yaml"),
      "List the exact origins that may call the API; never combine '*' or reflected origins with credentials.",
      "Any website can call this API from a visitor's browser, and with credentials it can read their data.")
def open_cors(ctx):
    for n, line in enumerate(ctx.lines, 1):
        if IGNORE_MARK in line or not any(p.search(line) for p in CORS_PATTERNS):
            continue
        creds = bool(re.search(r"credentials\s*[:=]\s*true|Allow-Credentials", line, re.I))
        yield Hit(n, snippet(line), S({"internet"}), S({"user_data_theft"}), 0.7 if creds else 0.5)


JWT_NOVERIFY = re.compile(
    r"""verify_signature["']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*[=:]\s*\[[^\]]*["']none["']""",
    re.I,
)


@rule("CB208", "Token signature not verified", "critical", CODE_KINDS,
      "Always verify signatures and pin the expected algorithm, e.g. algorithms=['HS256'].",
      "JWTs are decoded without checking the signature (or 'none' is accepted), so anyone can mint one.")
def jwt_noverify(ctx):
    for n, line, _m in grep(ctx, JWT_NOVERIFY):
        yield Hit(n, snippet(line), S({"internet"}), S({"session_forge"}), 0.85)


# ---------------------------------------------------------------- containers

@rule("CB301", "Container runs as root", "medium", ("docker",),
      "Add a non-root user and switch to it: RUN useradd -m app && USER app",
      "Without a USER instruction, code in the container runs as root, so a code-execution bug "
      "becomes root inside the container.")
def docker_root(ctx):
    froms = [(i, l) for i, l in enumerate(ctx.lines, 1) if re.match(r"\s*FROM\s+", l, re.I)]
    if not froms or any(IGNORE_MARK in l for _, l in froms):
        return
    last_from, from_line = froms[-1]
    if re.search(r"distroless.*nonroot|:nonroot", from_line):
        return
    users = [(i, l) for i, l in enumerate(ctx.lines, 1) if i > last_from and re.match(r"\s*USER\s+", l, re.I)]
    if not users:
        yield Hit(last_from, f"{snippet(from_line)} (no USER instruction)", S({"rce"}), S({"container_root"}), 0.9)
        return
    i, l = users[-1]
    who = l.split(None, 1)[1].strip().split(":")[0] if len(l.split()) > 1 else ""
    if who in ("root", "0"):
        yield Hit(i, snippet(l), S({"rce"}), S({"container_root"}), 0.9)


DOCKER_SOCK = re.compile(r"/var/run/docker\.sock|/run/docker\.sock")


@rule("CB302", "Docker socket mounted into a container", "critical", ("compose", "yaml", "docker", "shell"),
      "Remove the docker.sock mount. If something must manage containers, use a narrowly-scoped proxy.",
      "Whoever controls the Docker socket controls the host: they can start a privileged container "
      "with the host's filesystem mounted.")
def docker_sock(ctx):
    for n, line, _m in grep(ctx, DOCKER_SOCK):
        if line.strip().startswith("#"):
            continue
        yield Hit(n, snippet(line), S({"container_root"}), S({"host_root"}), 0.9)


PRIVILEGED = re.compile(r"privileged\s*:\s*true|--privileged\b|\bSYS_ADMIN\b|hostPID\s*:\s*true", re.I)


@rule("CB303", "Privileged container", "critical", ("compose", "yaml", "docker", "shell"),
      "Drop privileged mode and add only the specific capabilities the container needs.",
      "A privileged container can mount host devices and escape to the host.")
def privileged(ctx):
    for n, line, _m in grep(ctx, PRIVILEGED):
        if line.strip().startswith("#"):
            continue
        yield Hit(n, snippet(line), S({"container_root"}), S({"host_root"}), 0.85)


DB_PORTS = {"5432": "PostgreSQL", "3306": "MySQL", "27017": "MongoDB", "6379": "Redis",
            "9200": "Elasticsearch", "1433": "SQL Server", "5984": "CouchDB", "11211": "Memcached"}
PORT_MAP = re.compile(
    r"""^\s*-\s*["']?(?P<bind>(?:\d{1,3}\.){3}\d{1,3}:)?(?P<host>\d+):(?P<cont>\d+)(?:/tcp)?["']?\s*(?:#.*)?$"""
)


@rule("CB304", "Database port published to the network", "high", ("compose",),
      "Remove the ports: entry (services reach each other on the internal network) or bind to 127.0.0.1.",
      "The database port is published on every interface of the host, so it can be reached from outside.")
def db_port(ctx):
    for n, line, m in grep(ctx, PORT_MAP):
        if m.group("cont") not in DB_PORTS:
            continue
        if (m.group("bind") or "").startswith("127."):
            continue
        yield Hit(n, f"{DB_PORTS[m.group('cont')]}: {snippet(line)}", S({"internet"}), S({"db_network"}), 0.8)


# ---------------------------------------------------------------- dependencies

# A deliberately small list of well-known, exploitable advisories. It is not a replacement for
# pip-audit / npm audit; it exists so dependency risk takes part in the attack chains.
ADVISORIES = [
    # ecosystem, package, affected ranges [introduced, fixed), id, summary, grants, confidence, severity
    ("pypi", "pyyaml", [("0", "5.4")], "CVE-2020-14343", "code execution through full_load", {"rce"}, 0.45, "high"),
    ("pypi", "pyjwt", [("0", "2.4.0")], "CVE-2022-29217", "algorithm confusion lets attackers forge tokens",
     {"session_forge"}, 0.4, "high"),
    ("pypi", "jinja2", [("0", "2.10.1")], "CVE-2019-10906", "sandbox escape", {"rce"}, 0.3, "high"),
    ("pypi", "django", [("0", "3.2.14"), ("4.0", "4.0.6")], "CVE-2022-34265", "SQL injection in Trunc()/Extract()",
     {"db_read", "db_write"}, 0.3, "critical"),
    ("pypi", "pillow", [("0", "9.0.1")], "CVE-2022-22817", "arbitrary expressions in ImageMath.eval",
     {"rce"}, 0.3, "critical"),
    ("npm", "lodash", [("0", "4.17.21")], "CVE-2021-23337", "command injection through template()", {"rce"}, 0.3, "high"),
    ("npm", "jsonwebtoken", [("0", "9.0.0")], "CVE-2022-23540", "signature check bypass with insecure defaults",
     {"session_forge"}, 0.35, "high"),
    ("npm", "node-serialize", [("0", "999")], "CVE-2017-5941", "code execution when unserialising untrusted data",
     {"rce"}, 0.7, "critical"),
    ("npm", "ejs", [("0", "3.1.7")], "CVE-2022-29078", "server-side template injection to code execution",
     {"rce"}, 0.35, "critical"),
]


def vtuple(v: str) -> Tuple[int, ...]:
    parts = [int(x) for x in re.findall(r"\d+", v)[:4]]
    return tuple(parts + [0] * (4 - len(parts)))


def is_affected(version: str, ranges) -> bool:
    v = vtuple(version)
    return any(vtuple(lo) <= v < vtuple(hi) for lo, hi in ranges)


def _advisory_hits(ecosystem: str, name: str, version: str, line: int) -> Iterator[Hit]:
    name = name.lower().replace("_", "-")
    for eco, pkg, ranges, adv, summary, grants, conf, sev in ADVISORIES:
        if eco == ecosystem and pkg == name and is_affected(version, ranges):
            yield Hit(line, f"{name} {version}: {adv} ({summary})", S({"internet"}), S(grants), conf,
                      title=f"Vulnerable dependency: {name} {version}", severity=sev,
                      fix=f"Upgrade {name} past the fixed version for {adv}.")


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#,]*)")


@rule("CB401", "Vulnerable dependency", "high", ("requirements", "package_json"),
      "Upgrade the package to a fixed version.",
      "A pinned dependency has a known, exploitable vulnerability.")
def vulnerable_deps(ctx):
    if ctx.kind == "requirements":
        for n, line, m in grep(ctx, REQ_LINE):
            yield from _advisory_hits("pypi", m.group(1), m.group(2), n)
        return
    try:
        data = json.loads(ctx.text)
    except ValueError:
        return
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            vm = re.search(r"\d+(?:\.\d+)*", str(spec))
            if not vm:
                continue
            line = next((i for i, l in enumerate(ctx.lines, 1) if f'"{name}"' in l), 1)
            if ctx.lines and IGNORE_MARK in ctx.lines[line - 1]:
                continue
            yield from _advisory_hits("npm", name, vm.group(0), line)
