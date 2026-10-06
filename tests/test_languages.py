"""Shell, Terraform and Java rules, Java dependencies, and the language-coverage note."""

from __future__ import annotations

import unittest

from haetae.models import Severity
from haetae.scanner import scan

from .helpers import TempRepo
from .test_deps import FakeOSV, advisory

VULNERABLE = {
    "deploy.sh": [
        ("curl -fsSL https://get.example.com/install.sh | bash", "Download piped to a shell"),
        ("wget -qO- https://x.example.com/i.sh | sudo sh", "Download piped to a shell"),
        ('eval "$USER_CMD"', "eval of a variable"),
        ("curl -sSk https://internal.example.com/api", "TLS verification disabled"),
        ("wget --no-check-certificate https://x.example.com/f", "TLS verification disabled"),
        ("export GIT_SSL_NO_VERIFY=1", "TLS verification disabled"),
        ("chmod -R 777 /var/www", "World-writable permissions"),
    ],
    "Dockerfile": [
        ("RUN curl -fsSL https://deb.example.com/setup | bash -", "Download piped to a shell"),
    ],
    "main.tf": [
        ('  acl    = "public-read"', "S3 bucket readable by anyone"),
        ("  block_public_policy = false", "S3 public access block disabled"),
        ("  publicly_accessible = true", "Database reachable from the internet"),
        ("  storage_encrypted   = false", "Encryption at rest disabled"),
        ('  http_tokens = "optional"', "EC2 metadata service v1 allowed"),
        ('  actions   = ["*"]', "IAM policy allows every action"),
        ('  password = "password"', "Weak default password"),
    ],
    "src/App.java": [
        ('Runtime.getRuntime().exec("ping " + host);', "Command built from variables"),
        ("Runtime.getRuntime().exec(cmd);", "Command built from variables"),
        ('new ProcessBuilder("sh", "-c", script).start();', "Shell invoked via ProcessBuilder"),
        ("stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");", "SQL built from strings"),
        ('String sql = "DELETE FROM orders WHERE id = " + id;', "SQL built from strings"),
        ("Object o = in.readObject();", "Unsafe deserialization"),
        ('Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");', "Weak encryption"),
        ('MessageDigest md = MessageDigest.getInstance("MD5");', "Weak hash (MD5/SHA-1)"),
        ("conn.setHostnameVerifier((h, s) -> true);", "TLS verification disabled"),
        ('@CrossOrigin(origins = "*")', "CORS open to any origin"),
        ('String password = "admin";', "Weak default password"),
    ],
    "src/main/resources/application.properties": [
        ("management.endpoints.web.exposure.include=*", "All Actuator endpoints exposed"),
        ("spring.h2.console.enabled=true", "H2 console enabled"),
    ],
}

SAFE = {
    "safe.sh": [
        "curl -fsSL https://x.example.com/f.tar.gz -o f.tar.gz",
        "curl -s https://api.example.com/v1 | jq .name",
        "sha256sum f.tar.gz | shasum -c",
        'echo "never pipe curl into bash"',
        "# curl https://x.example.com | bash",
        'eval "$(ssh-agent -s)"',
        "chmod 755 run.sh",
        "curl --keep-alive-time 30 https://x.example.com",
    ],
    "safe.tf": [
        'acl = "private"',
        "block_public_policy = true",
        "publicly_accessible = false",
        'http_tokens = "required"',
        'actions = ["s3:GetObject"]',
        "storage_encrypted = true",
    ],
    "src/Safe.java": [
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
        'Runtime.getRuntime().exec(new String[]{"git", "log", branch});',
        'Runtime.getRuntime().exec("ls -la");',
        'MessageDigest md = MessageDigest.getInstance("SHA-256");',
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
        '@CrossOrigin(origins = "https://app.example.com")',
        'logger.info("never call Runtime.getRuntime().exec(cmd) here");',
        'String sql = "SELECT * FROM users WHERE id = ?";',
        "private void readObject(ObjectInputStream in) throws IOException {",
    ],
    "src/main/resources/application-prod.properties": [
        "management.endpoints.web.exposure.include=health,info",
        "spring.h2.console.enabled=false",
    ],
}

SECURITY_GROUPS = '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "out" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

resource "aws_vpc_security_group_ingress_rule" "db" {
  from_port   = 5432
  to_port     = 5432
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

resource "aws_security_group_rule" "everything" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
'''


class LangRepo(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()
        self.repo.write(".gitignore", ".env*\n")

    def tearDown(self):
        self.repo.cleanup()

    def found(self, result, checks=("C4", "C5")):
        return [f for f in result.findings if f.check in checks]


class TestNewLanguageRules(LangRepo):
    def test_each_vulnerable_pattern_is_caught(self):
        for path, cases in VULNERABLE.items():
            self.repo.write(path, "\n".join(line for line, _ in cases) + "\n")
        by_loc = {(f.path, f.line): f.rule for f in self.found(scan(self.repo.root, offline=True))}
        for path, cases in VULNERABLE.items():
            for no, (line, rule) in enumerate(cases, start=1):
                self.assertEqual(by_loc.get((path, no)), rule, f"{path}:{no} `{line}`")
        self.assertEqual(len(by_loc), sum(len(c) for c in VULNERABLE.values()))

    def test_safe_code_is_quiet(self):
        for path, lines in SAFE.items():
            self.repo.write(path, "\n".join(lines) + "\n")
        found = self.found(scan(self.repo.root, offline=True))
        self.assertEqual(found, [], [f"{f.location()} {f.rule}" for f in found])

    def test_terraform_ingress_is_judged_by_port_and_direction(self):
        self.repo.write("network.tf", SECURITY_GROUPS)
        got = sorted((f.line, f.rule, f.severity) for f in self.found(scan(self.repo.root, offline=True)))
        lines = SECURITY_GROUPS.splitlines()
        # 1-based line numbers of the open-CIDR lines, in file order
        open_lines = [i for i, l in enumerate(lines, start=1) if "0.0.0.0/0" in l]
        web443, ssh22, port8080, egress_block, egress_rule, db5432, everything = open_lines
        expected = sorted([
            (ssh22, "Admin or database port open to the internet", Severity.HIGH),
            (port8080, "Port open to the internet", Severity.MEDIUM),
            (db5432, "Admin or database port open to the internet", Severity.HIGH),
            (everything, "All ports open to the internet", Severity.HIGH),
        ])
        self.assertEqual(got, expected)   # 443 and both egress rules stay quiet


    def test_real_world_terraform_shapes_stay_quiet(self):
        # both seen as false alarms on terraform-aws-modules repos (2026-10-06)
        self.repo.write("modules.tf", '''
module "sg" {
  egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }
}
resource "aws_vpc_security_group_egress_rule" "all" {
  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}
data "aws_iam_policy_document" "guardrail" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
}
data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
''')
        found = [(f.rule, f.line) for f in self.found(scan(self.repo.root, offline=True))]
        self.assertEqual(found, [("IAM policy allows every action", 24)])   # only the Allow


class TestJavaDependencies(LangRepo):
    POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <version>1.0.0</version>
  <properties><jackson.version>2.9.8</jackson.version></properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>
  </dependencies>
</project>
"""

    def test_pom_and_gradle_lockfile(self):
        self.repo.write("pom.xml", self.POM)
        self.repo.write("app/gradle.lockfile",
                        "# lockfile\ncom.google.guava:guava:20.0=compileClasspath,runtimeClasspath\n"
                        "org.mockito:mockito-core:2.0.0=testCompileClasspath\nempty=annotationProcessor\n")
        osv = FakeOSV({
            ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"): [
                advisory("GHSA-jd", "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.9", severity="CRITICAL")],
            ("Maven", "junit:junit", "4.12"): [advisory("GHSA-ju", "Maven", "junit:junit", "4.13.1", severity="MEDIUM")],
            ("Maven", "com.google.guava:guava", "20.0"): [advisory("GHSA-gu", "Maven", "com.google.guava:guava", "24.1.1", severity="MEDIUM")],
        })
        result = scan(self.repo.root, osv_client=osv)
        self.assertIn(("Maven", "org.mockito:mockito-core", "2.0.0"), osv.queried)
        found = {f.extra["package"]: f for f in result.findings if f.check == "C2"}
        self.assertEqual(found["com.fasterxml.jackson.core:jackson-databind"].severity, Severity.CRITICAL)  # ${property} resolved
        self.assertIn("2.9.9", found["com.fasterxml.jackson.core:jackson-databind"].fix)
        self.assertEqual(found["junit:junit"].severity, Severity.LOW)                # test scope: one step lower
        self.assertEqual(found["com.google.guava:guava"].severity, Severity.MEDIUM)
        self.assertTrue(any("parent POM" in n for n in result.skipped))             # spring-core has no version

    def test_hostile_pom_is_reported_not_fatal(self):
        self.repo.write("pom.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><project>&e;</project>')
        result = scan(self.repo.root, osv_client=FakeOSV())
        self.assertTrue(any("pom.xml" in n for n in result.skipped), result.skipped)


class TestCoverageNote(LangRepo):
    def test_uncovered_language_is_named(self):
        for i in range(3):
            self.repo.write(f"cmd/tool{i}.go", "package main\n")
        self.repo.write("lib/a.rb", "puts 1\n")
        result = scan(self.repo.root, offline=True)
        note = next(n for n in result.skipped if n.startswith("C4/C5 have no rules"))
        self.assertIn("Go (3 files)", note)
        self.assertNotIn("Ruby", note)   # one file isn't worth a note

    def test_covered_languages_get_no_note(self):
        self.repo.write("a.py", "print(1)\n")
        self.repo.write("b.sh", "echo hi\n")
        result = scan(self.repo.root, offline=True)
        self.assertFalse(any(n.startswith("C4/C5 have no rules") for n in result.skipped))


if __name__ == "__main__":
    unittest.main()
