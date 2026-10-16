import io
import json
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server
import security_enhancements as sec


class ScannerTests(unittest.TestCase):
    def test_detects_common_patterns(self):
        findings = server.scan_sources([("src/app.js", 'eval(userInput);\nnode.innerHTML = userText;\n')])
        ids = {item["id"] for item in findings}
        self.assertIn("EVAL", ids)
        self.assertIn("INNER_HTML", ids)

    def test_redacts_secret_from_saved_finding(self):
        secret = "real_secret_value_123456789"
        findings = server.scan_sources([("src/config.js", f'const API_KEY = "{secret}";')])
        finding = next(item for item in findings if item["id"] == "HARDCODED_SECRET")
        self.assertNotIn(secret, finding["snippet"])
        self.assertIn("[REDACTED]", finding["snippet"])

    def test_redacts_secrets_even_on_another_finding_same_line(self):
        secret = "real_secret_value_987654321"
        findings = server.scan_sources([("src/app.js", f'const API_KEY = "{secret}"; fetch("http://service.example/?token={secret}");')])
        self.assertTrue(findings)
        for finding in findings:
            self.assertNotIn(secret, finding["snippet"])

    def test_yaml_unquoted_secret_is_redacted(self):
        secret = "really_private_value_123"
        findings = server.scan_sources([("config.yml", f"password: {secret}")])
        self.assertTrue(findings)
        for finding in findings:
            self.assertNotIn(secret, finding["snippet"])

    def test_https_is_not_reported_as_plain_http(self):
        findings = server.scan_sources([("src/client.js", 'const endpoint = "https://api.example.com/v1";')])
        self.assertNotIn("HTTP_URL", {f["id"] for f in findings})

    def test_http_is_reported_when_not_placeholder(self):
        findings = server.scan_sources([("src/client.js", 'const endpoint = "http://service.example.net/v1";')])
        self.assertIn("HTTP_URL", {f["id"] for f in findings})

    def test_path_traversal_is_rejected(self):
        self.assertIsNone(server.safe_source_name("../outside.js"))
        self.assertIsNone(server.safe_source_name("/etc/passwd"))
        self.assertIsNone(server.safe_source_name("folder/../../secret.env"))
        self.assertEqual(server.safe_source_name("src/main.js"), "src/main.js")

    def test_additional_file_formats_are_allowed(self):
        for name in ("src/main.rs", "src/main.c", "src/main.cpp", "src/notebook.ipynb", "infra/main.tf", "Dockerfile", "docker-compose.yml", "pnpm-lock.yaml", ".npmrc", "package-lock.json", "templates/page.jinja2", "src/query.scala", "src/app.ex"):
            with self.subTest(name=name):
                self.assertIsNotNone(server.safe_source_name(name))

    def test_zip_skips_path_traversal(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("src/index.html", "<h1>Hello</h1>")
            zf.writestr("../outside.js", "eval(1)")
        items, skipped = server.get_candidate_files_from_zip("project.zip", archive.getvalue())
        self.assertEqual(len(items), 1)
        self.assertEqual(skipped, 1)
        self.assertEqual(items[0][0], "src/index.html")

    def test_docker_configuration_rules(self):
        findings = server.scan_sources([("Dockerfile", "FROM node:latest\nUSER root\nENV API_KEY=abc123456789\n")])
        ids = {f["id"] for f in findings}
        self.assertIn("DOCKER_LATEST", ids)
        self.assertIn("DOCKER_ROOT", ids)
        self.assertIn("DOCKER_SECRET_ENV", ids)

    def test_kubernetes_and_terraform_rules(self):
        k8s = server.scan_sources([("deploy/pod.yml", "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: web\n    securityContext:\n      privileged: true\n")])
        tf = server.scan_sources([("infra/main.tf", 'cidr_blocks = ["0.0.0.0/0"]\nstorage_encrypted = false\n')])
        self.assertIn("K8S_PRIVILEGED", {f["id"] for f in k8s})
        self.assertIn("K8S_HOST_NETWORK", {f["id"] for f in k8s})
        self.assertIn("TF_OPEN_INGRESS", {f["id"] for f in tf})
        self.assertIn("TF_ENCRYPTION_DISABLED", {f["id"] for f in tf})

    def test_github_actions_supply_chain_rules(self):
        findings = server.scan_sources([(".github/workflows/ci.yml", "permissions: write-all\nuses: vendor/action@main\n")])
        ids = {f["id"] for f in findings}
        self.assertIn("GHA_WRITE_ALL", ids)
        self.assertIn("GHA_MUTABLE_REF", ids)

    def test_jupyter_code_cell_is_analyzed(self):
        notebook = json.dumps({"cells": [{"cell_type": "markdown", "source": ["hello"]}, {"cell_type": "code", "source": ["eval(untrusted_input)\n"]}]})
        findings = server.scan_sources([("notebook.ipynb", notebook)])
        self.assertIn("EVAL", {f["id"] for f in findings})

    def test_dependency_version_extraction(self):
        files = [
            ("package-lock.json", json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})),
            ("requirements.txt", "requests==2.31.0\nflask>=2.0\n"),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {}\n"),
        ]
        packages = sec.extract_dependency_versions(files)
        triples = {(x["ecosystem"], x["name"], x["version"]) for x in packages}
        self.assertIn(("npm", "lodash", "4.17.20"), triples)
        self.assertIn(("PyPI", "requests", "2.31.0"), triples)
        self.assertIn(("npm", "lodash", "4.17.21"), triples)
        self.assertNotIn(("PyPI", "flask", "2.0"), triples)

    def test_osv_lookup_can_be_mocked_and_finds_advisory(self):
        package_lock = ("package-lock.json", json.dumps({"packages": {"node_modules/example-lib": {"version": "1.0.0"}}}))
        payload = {"results": [{"vulns": [{"id": "GHSA-TEST-0000", "summary": "Test advisory", "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}]}]}
        with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(payload).encode("utf-8"))):
            result = sec.check_dependencies_osv([package_lock])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["vulnerabilitiesFound"], 1)
        self.assertEqual(result["findings"][0]["id"], "OSV_DEPENDENCY")

    def test_safe_fixes_are_limited_to_known_templates(self):
        files = [
            ("index.html", '<a href="https://example.org" target="_blank">Test</a>'),
            ("src/loader.py", "import yaml\ndata = yaml.load(config)\n"),
            ("src/danger.js", "eval(userInput)\n"),
        ]
        patched, changes = sec.apply_safe_fixes(files)
        contents = dict(patched)
        self.assertIn('rel="noopener noreferrer"', contents["index.html"])
        self.assertIn("yaml.safe_load(config)", contents["src/loader.py"])
        self.assertIn("eval(userInput)", contents["src/danger.js"])
        self.assertEqual(len(changes), 2)

    def test_every_finding_has_explanation_metadata(self):
        findings = server.scan_sources([("app.js", 'element.innerHTML = query;\n')])
        self.assertTrue(findings)
        for finding in findings:
            self.assertTrue(finding.get("description"))
            self.assertTrue(finding.get("fix"))
            self.assertTrue(finding.get("category"))
            self.assertTrue(finding.get("owasp"))

    def test_additional_template_tls_csrf_and_archive_rules(self):
        sources = [
            ("templates/page.html", "{{ profile.bio|safe }}"),
            ("app.py", "render_template_string(request.args['template'])\narchive.extractall(destination)\n@csrf_exempt\ndef update(): pass\nALLOWED_HOSTS = ['*']\n"),
            ("config.env", "NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
            ("client.go", "tls.Config{InsecureSkipVerify: true}"),
            ("client.java", "new NoopHostnameVerifier()"),
            ("include.php", "include $_GET['page'];"),
            ("message.js", "target.postMessage(payload, '*');"),
        ]
        ids = {item["id"] for item in server.scan_sources(sources)}
        for expected in {
            "TEMPLATE_UNSAFE_MARKUP", "PY_RENDER_TEMPLATE_STRING", "PY_TAR_EXTRACTALL",
            "CSRF_PROTECTION_DISABLED", "DJANGO_WILDCARD_ALLOWED_HOSTS", "NODE_TLS_VERIFY_DISABLED",
            "GO_TLS_INSECURE_SKIP_VERIFY", "JAVA_TRUST_ALL_CERTS", "PHP_DYNAMIC_INCLUDE",
            "POSTMESSAGE_WILDCARD_ORIGIN",
        }:
            with self.subTest(rule=expected):
                self.assertIn(expected, ids)

    def test_additional_python_ruby_ejs_and_spring_rules(self):
        sources = [
            ("src/runner.py", "subprocess.run(command, shell=True)"),
            ("src/parser.rb", "YAML.load(input)"),
            ("views/profile.ejs", "<%- profile.description %>"),
            ("application.properties", 'management.endpoints.web.exposure.include="*"'),
        ]
        ids = {item["id"] for item in server.scan_sources(sources)}
        for expected in {"PY_SUBPROCESS_SHELL_TRUE", "RUBY_UNSAFE_YAML_LOAD", "EJS_UNESCAPED_OUTPUT", "SPRING_ACTUATOR_EXPOSE_ALL"}:
            with self.subTest(rule=expected):
                self.assertIn(expected, ids)

    def test_cors_credentials_wildcard_rule(self):
        findings = server.scan_sources([("server.js", "app.use(cors({ origin: '*', credentials: true }));")])
        self.assertIn("CORS_CREDENTIALS_WILDCARD", {f["id"] for f in findings})

    def test_rejects_windows_drive_and_backslash_traversal(self):
        self.assertIsNone(server.safe_source_name(r"C:\temp\secrets.js"))
        self.assertIsNone(server.safe_source_name(r"..\outside.js"))
        self.assertIsNone(server.safe_source_name("uploads/file.js:payload"))
        self.assertIsNone(server.safe_source_name("bad\nname.js"))
        self.assertIsNone(server.safe_source_name("a" * 241 + ".js"))
        self.assertIsNone(server.safe_source_name("Node_Modules/ignored.js"))

    def test_binary_key_container_checks_filename_without_parsing_binary(self):
        files, skipped, label = server.extract_files([("files", "production.p12", b"\x00\xffbinary-private-container")])
        self.assertEqual(skipped, 0)
        self.assertIn("содержимое не разбиралось", files[0][1])
        findings = server.scan_sources(files)
        self.assertIn("PRIVATE_CREDENTIAL_FILE", {f["id"] for f in findings})

    def test_score_is_bounded(self):
        self.assertGreaterEqual(server.score_findings([{"severity": "critical"}] * 9), 0)
        self.assertLessEqual(server.score_findings([]), 100)

    # ---- v2.38: context-aware scanning and the extended automatic fixer -------------------------------------

    def test_docs_tests_and_rule_definitions_are_not_reported_but_real_code_is(self):
        findings = server.scan_sources([
            ("src/app.js", "eval(userInput);\n"),
            ("docs/guide.md", "Never call eval(userInput) in production.\n"),
            ("tests/test_app.js", "eval(sample);\n"),
            ("src/rules.py", '    "description": "eval() runs a string as code.",\n'),
            ("src/ignored.js", "eval(trusted); // shieldcode: ignore\n"),
        ])
        self.assertEqual({(f["file"], f["id"]) for f in findings}, {("src/app.js", "EVAL")})

    def test_real_key_formats_are_still_reported_in_docs_and_tests(self):
        cloud_key = "AKIA" + "A" * 16
        findings = server.scan_sources([("docs/setup.md", f"aws key: {cloud_key}\n"), ("tests/fixture.txt", f"{cloud_key}\n")])
        self.assertEqual({f["file"] for f in findings if f["id"] == "CLOUD_KEY"}, {"docs/setup.md", "tests/fixture.txt"})

    def test_path_name_and_autocomplete_hints_are_not_false_positives(self):
        findings = server.scan_sources([
            ("src/names.py", "label = Path(filename).name\n"),
            ("src/form.js", "field.autocomplete = registering ? 'new-password' : 'current-password';\n"),
        ])
        self.assertEqual(findings, [])

    def test_fixer_never_edits_strings_comments_docs_or_tests(self):
        source = (
            'message = "call yaml.load(config) only on trusted data"\n'
            "# requests.get(url, verify=False)\n"
            'doc = """\n'
            "requests.get(url, verify=False)\n"
            '"""\n'
        )
        files = [
            ("src/messages.py", source),
            ("README.md", 'Use <a href="x" target="_blank">link</a> and yaml.load(config).\n'),
            ("tests/test_x.py", "data = yaml.load(config)\n"),
            ("src/rules.js", 'const text = "el.innerHTML = \'\'";\n'),
        ]
        patched, changes = sec.apply_safe_fixes(files)
        self.assertEqual(dict(patched), dict(files))
        self.assertEqual(changes, [])

    def test_fixer_repairs_common_python_javascript_html_and_compose_issues(self):
        python_source = (
            '"""Service."""\n'
            "from __future__ import annotations\n"
            "import subprocess, tarfile\n"
            "import yaml, requests\n"
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            'API_KEY = "abcd1234efgh5678"\n'
            "data = yaml.load(config)\n"
            'subprocess.run("ls -la /tmp", check=True, shell=True)\n'
            "archive = tarfile.open(path)\n"
            "archive.extractall(destination)\n"
            "requests.get(endpoint, timeout=5, verify=False)\n"
            "app.run(debug=True)\n"
        )
        js_source = (
            "https.request({ host, rejectUnauthorized: false });\n"
            "res.cookie('session', value, { httpOnly: false, secure: false });\n"
            "box.innerHTML = 'Загрузка';\n"
            "list.innerHTML = '';\n"
            "view.innerHTML = userHtml;\n"
            "eval(userInput);\n"
        )
        html_source = '<a href="https://example.org" target="_blank">Open</a>\n'
        compose = "services:\n  web:\n    image: app\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    privileged: true\n"
        files = [("src/app.py", python_source), ("src/client.js", js_source), ("public/index.html", html_source), ("docker-compose.yml", compose)]
        before = {finding["id"] for finding in server.scan_sources(files)}
        patched, changes = sec.apply_safe_fixes(files)
        fixed = dict(patched)
        after = {finding["id"] for finding in server.scan_sources(patched)}

        compile(fixed["src/app.py"], "app.py", "exec")  # still valid Python
        self.assertIn("import os", fixed["src/app.py"])
        self.assertLess(fixed["src/app.py"].index("import os"), fixed["src/app.py"].index("app = Flask"))
        self.assertIn('API_KEY = os.environ.get("API_KEY", "")', fixed["src/app.py"])
        self.assertIn("yaml.safe_load(config)", fixed["src/app.py"])
        self.assertIn("subprocess.run(['ls', '-la', '/tmp'], check=True, shell=False)", fixed["src/app.py"])
        self.assertIn("extractall(destination, filter='data')", fixed["src/app.py"])
        self.assertIn("verify=True", fixed["src/app.py"])
        self.assertIn("app.run(debug=False)", fixed["src/app.py"])
        self.assertIn("rejectUnauthorized: true", fixed["src/client.js"])
        self.assertIn("httpOnly: true, secure: true", fixed["src/client.js"])
        self.assertIn("box.textContent = 'Загрузка';", fixed["src/client.js"])
        self.assertIn("list.textContent = '';", fixed["src/client.js"])
        self.assertIn("view.innerHTML = userHtml;", fixed["src/client.js"])  # needs a human decision
        self.assertIn("eval(userInput);", fixed["src/client.js"])  # needs a human decision
        self.assertIn('rel="noopener noreferrer"', fixed["public/index.html"])
        self.assertNotIn("/var/run/docker.sock", fixed["docker-compose.yml"])
        self.assertIn("# [ShieldCode] volumes:", fixed["docker-compose.yml"])
        self.assertIn("privileged: false", fixed["docker-compose.yml"])
        for rule_id in ("YAML_UNSAFE_LOAD", "TLS_VERIFY_DISABLED", "DEBUG_MODE", "HARDCODED_SECRET", "PY_SUBPROCESS_SHELL_TRUE",
                        "COMMAND_EXEC", "PY_TAR_EXTRACTALL", "COOKIE_HTTPONLY_DISABLED", "COOKIE_SECURE_DISABLED",
                        "TARGET_BLANK", "DOCKER_SOCKET", "K8S_PRIVILEGED"):
            self.assertIn(rule_id, before, rule_id)
            self.assertNotIn(rule_id, after, rule_id)
        self.assertIn("EVAL", after)
        self.assertIn("INNER_HTML", after)
        self.assertTrue(all("file" in change and "line" in change for change in changes))
        # a second pass finds nothing more to change
        again, more_changes = sec.apply_safe_fixes(patched)
        self.assertEqual(dict(again), fixed)
        self.assertEqual(more_changes, [])

    def test_fixer_does_not_add_filter_to_zipfile_extractall(self):
        source = "import zipfile\nwith zipfile.ZipFile(path) as archive:\n    archive.extractall(destination)\n"
        patched, changes = sec.apply_safe_fixes([("src/unzip.py", source)])
        self.assertEqual(dict(patched)["src/unzip.py"], source)
        self.assertEqual(changes, [])

    def test_fixer_keeps_shell_commands_with_metacharacters(self):
        source = 'import subprocess\nsubprocess.run("ls | wc -l", shell=True)\n'
        patched, _ = sec.apply_safe_fixes([("src/run.py", source)])
        self.assertEqual(dict(patched)["src/run.py"], source)

    def test_fixpack_summary_reports_what_is_left(self):
        files = [("src/a.js", "eval(x);\nel.innerHTML = 'ok';\nhttps.request({ rejectUnauthorized: false });\n")]
        patched, changes = sec.apply_safe_fixes(files)
        summary = server.build_fixpack_summary(files, patched, changes)
        self.assertEqual(summary["before"], 3)
        self.assertEqual(summary["after"], 1)
        self.assertEqual(summary["fixed"], 2)
        self.assertEqual(summary["edits"], 2)


if __name__ == "__main__":
    unittest.main()
