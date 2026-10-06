"""C4 — dangerous code patterns, and C5 — insecure defaults.

Line-based rules for JavaScript/TypeScript (including inline scripts in HTML),
Python, Shell (including Dockerfiles), Terraform and Java (plus Spring config). They look for the *shape* of a risky call, so they are hints for a
reviewer, not proof of a vulnerability; every finding says what to check.

Noise controls: comment lines are skipped, test files report one level lower,
and a line containing `haetae: ignore` is silenced on purpose.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..files import read_lines
from ..models import Finding, Severity
from .secrets import SUPPRESS, is_test_path

# Language tokens; _lang() maps a file to one of them.
JS, PY, SH, TF, JAVA, SPRING = ({"js"}, {"py"}, {"sh"}, {"tf"}, {"java"}, {"spring"})
EXTENSIONS = {
    "js": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte"},
    "py": {".py"},
    "sh": {".sh", ".bash", ".zsh", ".ksh"},
    "tf": {".tf"},
    "java": {".java", ".jsp"},
}
SPRING_CONFIG = re.compile(r"(^|/)application(-[\w.-]+)?\.(properties|ya?ml)$")
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|<!--)")
SQL = r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b"


@dataclass(frozen=True)
class LineRule:
    check: str
    name: str
    langs: frozenset
    pattern: re.Pattern
    severity: Severity
    why: str
    fix: str


def _rule(check, name, langs, regex, severity, why, fix, flags=0) -> LineRule:
    return LineRule(check, name, frozenset(langs), re.compile(regex, flags), severity, why, fix)


RULES: list[LineRule] = [
    # ---------------------------------------------------------------- C4
    _rule("C4", "eval()", JS, r"(?<![\w.$])eval\s*\(", Severity.HIGH,
          "eval runs any string as code; if any part of it comes from a user, they can run code in your app.",
          "Replace it: JSON.parse for data, a lookup table for dynamic behaviour."),
    _rule("C4", "new Function()", JS, r"\bnew\s+Function\s*\(", Severity.HIGH,
          "new Function compiles a string into code, with the same risk as eval.",
          "Replace it with a normal function or a lookup table."),
    _rule("C4", "eval()/exec()", PY, r"(?<![\w.])(?:eval|exec)\s*\(", Severity.HIGH,
          "eval/exec run any string as Python; user-controlled input means remote code execution.",
          "Use ast.literal_eval for data, or explicit code paths instead of generated code."),
    _rule("C4", "Shell command built from variables", JS,
          r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", Severity.HIGH,
          "A shell command assembled from variables lets crafted input run extra commands (command injection).",
          "Use execFile/spawn with an argument array and no shell, and validate every argument."),
    _rule("C4", "Shell command built from variables", PY,
          r"\bos\.(?:system|popen)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))", Severity.HIGH,
          "A shell command assembled from variables lets crafted input run extra commands (command injection).",
          "Use subprocess.run([...]) with an argument list and shell=False."),
    _rule("C4", "subprocess with shell=True", PY, r"\bsubprocess\.\w+\s*\(.*\bshell\s*=\s*True", Severity.MEDIUM,
          "shell=True hands the whole string to a shell, so any variable in it can inject commands.",
          "Pass an argument list and drop shell=True."),
    _rule("C4", "SQL built from strings", JS,
          r"\b(?:query|execute|raw|run|all|get|prepare)\s*\(\s*(?:`\s*" + SQL + r"[^`]*\$\{|['\"]\s*" + SQL + r"[^'\"]*['\"]\s*\+)",
          Severity.HIGH,
          "SQL assembled from variables is the classic SQL injection: input can read or change any data.",
          "Use parameterised queries ($1 / ? placeholders with a values array).", re.IGNORECASE),
    _rule("C4", "SQL built from strings", PY,
          r"\.(?:execute|executemany|raw)\s*\(\s*(?:f['\"]\s*" + SQL + r"|['\"]\s*" + SQL + r"[^'\"]*['\"]\s*(?:%|\+|\.format))",
          Severity.HIGH,
          "SQL assembled from variables is the classic SQL injection: input can read or change any data.",
          "Pass parameters separately: cursor.execute(\"... WHERE id = %s\", (id,)).", re.IGNORECASE),
    _rule("C4", "Unsafe deserialization", PY, r"\b(?:pickle|cPickle|marshal)\.loads?\s*\(", Severity.MEDIUM,
          "Unpickling data from an untrusted source can execute arbitrary code.",
          "Use JSON for data from outside; only unpickle data you created and stored yourself."),
    _rule("C4", "yaml.load without SafeLoader", PY, r"\byaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)", Severity.MEDIUM,
          "yaml.load with the default loader can construct arbitrary Python objects from a document.",
          "Use yaml.safe_load(...)."),

    # ---------------------------------------------------------------- C5
    _rule("C5", "Debug mode on", PY, r"^\s*DEBUG\s*=\s*True\b|\.run\s*\(.*\bdebug\s*=\s*True", Severity.MEDIUM,
          "Debug mode shows stack traces, settings and sometimes an interactive console to anyone who triggers an error.",
          "Read it from the environment and default to off: DEBUG = os.getenv('DEBUG') == '1'."),
    _rule("C5", "CORS open to any origin", JS,
          r"\bcors\s*\(\s*\)|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|\borigin\s*:\s*(?:['\"]\*['\"]|true)\b",
          Severity.MEDIUM,
          "Any website can call this API from a visitor's browser; with credentials allowed, it can act as them.",
          "List the exact origins you trust: cors({ origin: ['https://app.example.com'] })."),
    _rule("C5", "CORS open to any origin", PY,
          r"\bCORS\s*\(\s*app\s*\)|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*['\"]",
          Severity.MEDIUM,
          "Any website can call this API from a visitor's browser; with credentials allowed, it can act as them.",
          "List the exact origins you trust instead of allowing all."),
    _rule("C5", "TLS verification disabled", PY, r"\bverify\s*=\s*False\b", Severity.MEDIUM,
          "Without certificate checks, anyone on the network path can read and alter the traffic.",
          "Remove verify=False; if you use a private CA, pass its bundle: verify='/path/to/ca.pem'."),
    _rule("C5", "TLS verification disabled", JS,
          r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0", Severity.MEDIUM,
          "Without certificate checks, anyone on the network path can read and alter the traffic.",
          "Remove it; for a private CA, pass the CA certificate via the `ca` option."),
    _rule("C5", "Weak default password", JS | PY | JAVA | TF,
          r"""(?i)\b[\w\-]*(?:password|passwd|pwd|pass)\b["']?\s*[:=]\s*["'](password|passw0rd|admin|root|toor|123456|12345678|qwerty|letmein|secret|default|changeme|pass|test123)["']""",
          Severity.HIGH,
          "A well-known default password is the first thing attackers try, and it often survives into production.",
          "Require the password from the environment and refuse to start without one."),

    # ---------------------------------------------------------------- Shell (and Dockerfile RUN lines)
    _rule("C4", "Download piped to a shell", SH,
          r"\b(?:curl|wget)\b[^|#]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|k|da)?sh\b", Severity.HIGH,
          "Whatever the server returns runs immediately, unreviewed; a compromised or spoofed download runs as you.",
          "Download to a file, verify its checksum or signature, then run it."),
    _rule("C4", "eval of a variable", SH, r"\beval\s+[\"']?\$(?!\()", Severity.HIGH,
          "eval re-parses the variable as shell code, so anything in it, including input, runs as a command.",
          "Avoid eval; use arrays for dynamic arguments, or a case statement for dynamic behaviour."),
    _rule("C5", "TLS verification disabled", SH,
          r"\bcurl\b[^#|]*\s(?:--insecure|-[a-zA-Z]*k[a-zA-Z]*)\b|\bwget\b[^#|]*--no-check-certificate"
          r"|\bGIT_SSL_NO_VERIFY\s*=\s*[\"']?(?:1|true)|http\.sslVerify[\s=]+false", Severity.MEDIUM,
          "Without certificate checks, anyone on the network path can swap what you download or send.",
          "Remove the flag; for a private CA, pass it with --cacert (curl) or --ca-certificate (wget)."),
    _rule("C5", "World-writable permissions", SH, r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|o\+w)\b", Severity.MEDIUM,
          "Any user or process on the machine can change these files, including replacing a script that later runs.",
          "Grant only what's needed, e.g. chmod 755 for scripts and 644 for files."),

    # ---------------------------------------------------------------- Terraform
    _rule("C5", "S3 bucket readable by anyone", TF,
          r"\bacl\s*=\s*\"(?:public-read|public-read-write|authenticated-read)\"", Severity.HIGH,
          "A public ACL lets anyone on the internet list or download the bucket's contents.",
          "Use acl = \"private\" and share specific objects with pre-signed URLs or CloudFront."),
    _rule("C5", "S3 public access block disabled", TF,
          r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b",
          Severity.MEDIUM,
          "Turning off S3's public access block removes the safety net that stops a bucket from being made public.",
          "Set all four settings to true unless the bucket is deliberately public (and then document why)."),
    _rule("C5", "Database reachable from the internet", TF, r"\bpublicly_accessible\s*=\s*true\b", Severity.HIGH,
          "The database gets a public address, so its login is the only thing between it and the internet.",
          "Set publicly_accessible = false and reach it through private networking, a bastion or a VPN."),
    _rule("C5", "Encryption at rest disabled", TF,
          r"\b(?:encrypted|storage_encrypted|encrypt_at_rest|kms_encrypted)\s*=\s*false\b", Severity.MEDIUM,
          "Unencrypted disks, snapshots and backups are readable by anyone who gets a copy.",
          "Enable encryption (it's free on most AWS services) and use a KMS key you control."),
    _rule("C5", "IAM policy allows every action", TF,
          r"\"Action\"\s*:\s*(?:\"\*\"|\[\s*\"\*\"\s*\])|\bactions\s*=\s*\[\s*\"\*\"\s*\]", Severity.HIGH,
          "Action \"*\" grants every permission the service has, so one leaked credential can do anything.",
          "List only the actions the role needs (least privilege); IAM Access Analyzer can suggest them."),
    _rule("C5", "EC2 metadata service v1 allowed", TF, r"\bhttp_tokens\s*=\s*\"optional\"", Severity.MEDIUM,
          "IMDSv1 lets a server-side request forgery read the instance's credentials (how the 2019 Capital One breach worked).",
          "Set http_tokens = \"required\" to enforce IMDSv2."),
    _rule("C5", "Port open to the internet", TF,
          r"\b(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*\"(?:0\.0\.0\.0/0|::/0)\"|\bcidr_ipv4\s*=\s*\"0\.0\.0\.0/0\""
          r"|\bcidr_ipv6\s*=\s*\"::/0\"", Severity.MEDIUM,
          "Anyone on the internet can reach this port.",
          "Restrict cidr_blocks to the addresses that need access, or put the service behind a load balancer."),

    # ---------------------------------------------------------------- Java
    _rule("C4", "Command built from variables", JAVA,
          r"\bRuntime\.getRuntime\(\)\.exec\s*\((?!\s*(?:\"[^\"+]*\"\s*\)|new\s+String\s*\[))", Severity.HIGH,
          "A command assembled from a single string is split on spaces, so crafted input can add arguments or commands.",
          "Use ProcessBuilder with a list of arguments, and validate each one."),
    _rule("C4", "Shell invoked via ProcessBuilder", JAVA,
          r"\bnew\s+ProcessBuilder\s*\(\s*(?:List\.of\s*\(|Arrays\.asList\s*\()?\s*\"(?:/bin/)?(?:ba|z)?sh\"\s*,\s*\"-c\"",
          Severity.MEDIUM,
          "sh -c hands the string to a shell, so any variable in it can inject commands.",
          "Run the program directly with an argument list instead of through sh -c."),
    _rule("C4", "SQL built from strings", JAVA,
          r"\b(?:executeQuery|executeUpdate|execute|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery"
          r"|queryForObject|queryForList|query|update)\s*\(\s*(?:\"\s*" + SQL + r"[^\"]*\"\s*\+|String\.format\s*\(\s*\"\s*" + SQL + r")"
          r"|\bString\s+\w*(?:sql|query)\w*\s*=\s*\"\s*" + SQL + r"[^\"]*\"\s*\+",
          Severity.HIGH,
          "SQL assembled from variables is the classic SQL injection: input can read or change any data.",
          "Use a PreparedStatement with ? placeholders and setString/setInt for every value.", re.IGNORECASE),
    _rule("C4", "Unsafe deserialization", JAVA, r"\.readObject\s*\(\s*\)|\bnew\s+XMLDecoder\s*\(", Severity.MEDIUM,
          "Deserializing untrusted bytes can run attacker-chosen code through gadget chains in your dependencies.",
          "Exchange data as JSON; if you must deserialize, use an ObjectInputFilter allowlist."),
    _rule("C4", "Weak encryption", JAVA,
          r"\b(?:Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*\"(?:DES|DESede|RC2|RC4|Blowfish|AES|[^\"]*/ECB/[^\"]*)\"",
          Severity.MEDIUM,
          "DES, RC4 and ECB mode are broken; plain \"AES\" silently means AES/ECB, which leaks patterns in the data.",
          "Use Cipher.getInstance(\"AES/GCM/NoPadding\") with a random 12-byte IV per message."),
    _rule("C4", "Weak hash (MD5/SHA-1)", JAVA, r"\bMessageDigest\.getInstance\s*\(\s*\"(?:MD2|MD5|SHA-?1)\"",
          Severity.LOW,
          "MD5 and SHA-1 have practical collisions: fine for checksums, unsafe for passwords, signatures or tokens.",
          "Use SHA-256 for integrity, and bcrypt, scrypt or Argon2 for passwords."),
    _rule("C5", "TLS verification disabled", JAVA,
          r"\bNoopHostnameVerifier\b|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\s*\(\s*\(?[^)]*\)?\s*->\s*true"
          r"|\bInsecureTrustManagerFactory\b|\btrustAll\w*", Severity.MEDIUM,
          "Without certificate and hostname checks, anyone on the network path can read and alter the traffic.",
          "Remove the custom verifier or trust manager; for a private CA, load it into a trust store instead."),
    _rule("C5", "CORS open to any origin", JAVA,
          r"@CrossOrigin\s*(?:\(\s*\)|$)|@CrossOrigin\s*\(\s*(?:origins\s*=\s*|value\s*=\s*)?\"\*\""
          r"|\.allowedOrigins\s*\(\s*\"\*\"\s*\)|setAllowedOrigins\s*\(\s*(?:List\.of|Arrays\.asList|Collections\.singletonList)\s*\(\s*\"\*\"",
          Severity.MEDIUM,
          "Any website can call this API from a visitor's browser; with credentials allowed, it can act as them.",
          "List the exact origins you trust: @CrossOrigin(origins = \"https://app.example.com\")."),
    _rule("C5", "All Actuator endpoints exposed", SPRING,
          r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*|^\s*include\s*:\s*[\"']\*[\"']", Severity.MEDIUM,
          "Actuator endpoints such as /env, /heapdump and /loggers leak secrets and memory contents if reachable.",
          "Expose only what you need, e.g. include=health,info, and put the rest behind authentication."),
    _rule("C5", "H2 console enabled", SPRING, r"spring\.h2\.console\.enabled\s*[=:]\s*true", Severity.MEDIUM,
          "The H2 web console can run arbitrary SQL, and from there code, if it is reachable outside development.",
          "Enable it only in a local dev profile (application-dev.properties), never in shared config."),
]


def _lang(rel: str) -> frozenset:
    name = rel.rsplit("/", 1)[-1]
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
        return frozenset(SH)       # RUN lines are shell
    if SPRING_CONFIG.search(rel):
        return frozenset(SPRING)
    ext = Path(name).suffix.lower()
    for lang, exts in EXTENSIONS.items():
        if ext in exts:
            return frozenset({lang})
    return frozenset()


def check(files: list[tuple[str, Path]]) -> list[Finding]:
    findings: list[Finding] = []
    for rel, path in files:
        lang = _lang(rel)
        if not lang:
            continue
        rules = [r for r in RULES if r.langs & lang]
        in_test = is_test_path(rel)
        lines = read_lines(path)
        blocks = _tf_blocks(lines) if "tf" in lang else []
        for no, line in enumerate(lines, start=1):
            if SUPPRESS in line or COMMENT.match(line) or len(line) > 2000:   # long lines: minified code
                continue
            for rule in rules:
                m = rule.pattern.search(line)
                if not m:
                    continue
                if rule.name not in MATCHES_STRINGS and _in_string(line, m.start()):
                    continue   # text that mentions the call, e.g. an error message or a rule definition
                name, severity, why, fix = rule.name, rule.severity, rule.why, rule.fix
                if rule.name == "Weak default password" and _is_label(m):
                    continue
                if rule.name == "SQL built from strings" and PARAMETERISED.search(line):
                    name, severity, why, fix = DYNAMIC_IDENTIFIERS
                if rule.name == "IAM policy allows every action" and _tf_denies(lines, blocks, no):
                    continue          # a Deny on "*" is a guardrail, not a grant
                if rule.name == "Port open to the internet":
                    exposure = _tf_exposure(lines, blocks, no)
                    if exposure is None:
                        continue          # egress, or web ports 80/443: normal
                    name, severity, why = exposure
                if in_test:
                    # no user input reaches a test harness: a hint, never a CI failure
                    severity = Severity.LOW
                    why += " (In a test file, so ranked low.)"
                findings.append(Finding(
                    check=rule.check, rule=name, severity=severity, path=rel, line=no,
                    message=f"{name}: `{line.strip()[:120]}`",
                    why=why, fix=fix + f" If this line is safe and reviewed, add a `{SUPPRESS}` comment to it.",
                    extra={"content": hashlib.sha256(line.strip().encode()).hexdigest()[:16]},
                ))
    return findings


# Values are already bound as parameters ($1, $${i}, ?): only identifiers such as
# column names are spliced in. Safe when those come from an allowlist, so this is a
# review prompt, not an injection alarm (seen on a real codebase, 2026-10-06).
# Python's %s counts only when the values follow as a separate argument
# ("... %s", (uid,)); "... %s" % uid is string formatting, i.e. the injection itself.
PARAMETERISED = re.compile(r"\$\d|\$\$\{|\$'\s*\+|=\s*\?|%s['\"]\s*,")
DYNAMIC_IDENTIFIERS = (
    "SQL with dynamic column names", Severity.MEDIUM,
    "The values are parameterised, but column or table names are spliced into the SQL; "
    "if any of those names can come from a request, it's injection.",
    "Check that every spliced name comes from a fixed allowlist in code, never from request fields.",
)


# Rules whose pattern is itself about a string's contents; every other rule matches a
# call or assignment, so a hit inside a string literal is only text that mentions it.
MATCHES_STRINGS = {"Weak default password", "CORS open to any origin"}


def _in_string(line: str, pos: int) -> bool:
    """True if line[pos] sits inside a '...', "..." or `...` literal on this line."""
    quote, i = None, 0
    while i < pos:
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        i += 1
    return quote is not None


UI_KEY = re.compile(r"(?i)label|placeholder|text|title|hint|caption|message|msg|tooltip")


def _is_label(m: re.Match) -> bool:
    """A UI string, not a credential.

    `accPassword: 'Password'` is display text: capitalised like a label and repeating
    the key's own name. `pwdLabel: 'pass'` says so in its key. Real weak defaults are
    lowercase, like a database password set to the literal word itself, and stay flagged.
    """
    value = m.group(1)
    key = m.string[m.start(0):m.start(1)]
    if UI_KEY.search(key):
        return True
    return value[:1].isupper() and value[1:].islower() and value.lower() in key.lower()


# ---------------------------------------------------------------- Terraform ingress context
# `0.0.0.0/0` is only a finding on *ingress*, and how bad it is depends on the port:
# outbound rules are normally open, 80/443 on a public load balancer is the point,
# but SSH, RDP or a database open to the world is a classic breach.

ADMIN_DB_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server",
                  1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB",
                  11211: "Memcached", 2375: "Docker API", 5601: "Kibana"}
WEB_PORTS = {80, 443}


def _tf_blocks(lines: list[str]) -> list[tuple[int, int, str]]:
    """(start, end, header) for every { } block, 1-based line numbers; braces in strings ignored."""
    blocks, stack = [], []
    for no, line in enumerate(lines, start=1):
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line.split("#", 1)[0])
        for ch in code:
            if ch == "{":
                stack.append((no, line.strip()))
            elif ch == "}" and stack:
                start, header = stack.pop()
                blocks.append((start, no, header))
    return blocks


def _tf_denies(lines, blocks, no) -> bool:
    """True if the policy statement around this line has effect Deny."""
    enclosing = [b for b in blocks if b[0] <= no <= b[1]]
    if not enclosing:
        return False
    start, end, _ = min(enclosing, key=lambda b: b[1] - b[0])
    text = "\n".join(lines[start - 1:end])
    return bool(re.search(r'(?i)\beffect"?\s*[:=]\s*"deny"', text))


def _tf_exposure(lines, blocks, no):
    """None if this open CIDR is fine (egress, web ports); else (name, severity, why)."""
    enclosing = [b for b in blocks if b[0] <= no <= b[1]]
    if not enclosing:
        ports_text = lines[no - 1]
    else:
        start, end, _ = min(enclosing, key=lambda b: b[1] - b[0])
        ports_text = "\n".join(lines[start - 1:end])
    headers = " ".join(h for _, _, h in enclosing)
    # "egress" anywhere in an enclosing header: `egress {`, `egress_rules = {`,
    # `resource "aws_vpc_security_group_egress_rule"` (no "ingress" contains it)
    if "egress" in headers.lower() or re.search(r'\btype\s*=\s*"egress"', ports_text):
        return None

    def port(key):
        m = re.search(rf"\b{key}\s*=\s*(-?\d+)", ports_text)
        return int(m.group(1)) if m else None

    lo, hi = port("from_port"), port("to_port")
    all_proto = re.search(r'\b(?:ip_)?protocol\s*=\s*"(?:-1|all)"', ports_text)
    if all_proto or (lo is not None and hi is not None and (hi - lo) >= 1000) or (lo == 0 and hi in (0, 65535)):
        return ("All ports open to the internet", Severity.HIGH,
                "Every port on these resources is reachable from anywhere, including admin and database services.")
    if lo is None:
        return ("Port open to the internet", Severity.MEDIUM,
                "Anyone on the internet can reach this rule's ports; check that is intended.")
    hi = lo if hi is None else hi
    exposed = [label for p, label in ADMIN_DB_PORTS.items() if lo <= p <= hi]
    if exposed:
        return ("Admin or database port open to the internet", Severity.HIGH,
                f"{', '.join(exposed)} reachable from anywhere: login brute-force and exploits of the service itself.")
    if set(range(lo, hi + 1)) <= WEB_PORTS:
        return None
    return ("Port open to the internet", Severity.MEDIUM,
            f"Port {lo if lo == hi else f'{lo}-{hi}'} is reachable from anywhere; check that is intended.")


# ---------------------------------------------------------------- coverage
UNCOVERED = {".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".kt": "Kotlin", ".kts": "Kotlin",
             ".rs": "Rust", ".swift": "Swift", ".c": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
             ".scala": "Scala", ".ex": "Elixir", ".dart": "Dart", ".lua": "Lua", ".pl": "Perl",
             ".groovy": "Groovy", ".ps1": "PowerShell", ".m": "Objective-C"}


def coverage_gaps(files: list[tuple[str, Path]]) -> str | None:
    """A note when real code is in a language C4/C5 have no rules for, so 'clean' isn't over-read."""
    counts: dict[str, int] = {}
    for rel, _ in files:
        lang = UNCOVERED.get(Path(rel).suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    langs = [f"{lang} ({n} files)" for lang, n in sorted(counts.items(), key=lambda kv: -kv[1]) if n >= 3]
    if not langs:
        return None
    return ("C4/C5 have no rules yet for " + ", ".join(langs)
            + ": those files were checked for secrets only, not for risky code or insecure defaults")
