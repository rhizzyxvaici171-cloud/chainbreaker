import unittest

import _bootstrap  # noqa: F401
from chainbreaker.models import FileContext
from chainbreaker.rules import is_affected, run_rules


def scan_text(name, kind, text):
    return list(run_rules(FileContext(path=name, abspath=name, text=text, kind=kind)))


def rules_of(findings):
    return {f.rule for f in findings}


class SecretRules(unittest.TestCase):
    def test_cloud_key_is_found_and_redacted(self):
        key = "AKIA" + "QWERTYUIOPASDFGH"  # built at runtime so the repo holds no key-shaped string
        [f] = [f for f in scan_text("cfg.py", "python", f'KEY = "{key}"\n') if f.rule == "CB101"]
        self.assertEqual(f.grants, {"cloud_creds"})
        self.assertNotIn(key, f.evidence)

    def test_db_url_with_password(self):
        found = scan_text(".env", "env", "DATABASE_URL=postgres://app:hunter2hunter@db:5432/app\n")
        self.assertIn("CB102", rules_of(found))

    def test_db_url_from_variable_is_ignored(self):
        found = scan_text(".env", "env", "DATABASE_URL=postgres://app:${DB_PASSWORD}@db/app\n")
        self.assertNotIn("CB102", rules_of(found))

    def test_jwt_secret_is_classified(self):
        [f] = scan_text("app.py", "python", 'JWT_SECRET = "abc-very-secret-123"\n')
        self.assertEqual(f.grants, {"jwt_secret"})

    def test_env_lookups_are_not_secrets(self):
        code = 'SECRET_KEY = os.environ["SECRET_KEY"]\npassword = request.form["password"]\n'
        self.assertEqual(scan_text("app.py", "python", code), [])

    def test_ignore_comment(self):
        code = 'API_KEY = "sk-not-really-123456"  # chainbreaker:ignore\n'
        self.assertEqual(scan_text("app.py", "python", code), [])


class WebRules(unittest.TestCase):
    def test_sql_fstring(self):
        found = scan_text("a.py", "python", 'cur.execute(f"SELECT * FROM t WHERE id={id}")\n')
        self.assertIn("CB204", rules_of(found))

    def test_parameterised_sql_is_fine(self):
        found = scan_text("a.py", "python", 'cur.execute("SELECT * FROM t WHERE id=?", (id,))\n')
        self.assertNotIn("CB204", rules_of(found))

    def test_js_template_sql(self):
        found = scan_text("a.js", "js", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)\n")
        self.assertIn("CB204", rules_of(found))

    def test_unauth_admin_route(self):
        code = '@app.route("/admin/users")\ndef users():\n    return list_users()\n'
        self.assertIn("CB203", rules_of(scan_text("a.py", "python", code)))

    def test_admin_route_with_login_required(self):
        code = '@app.route("/admin/users")\n@login_required\ndef users():\n    return list_users()\n'
        self.assertNotIn("CB203", rules_of(scan_text("a.py", "python", code)))

    def test_express_admin_with_middleware(self):
        code = "app.get('/admin', requireAuth, (req, res) => res.send('ok'))\n"
        self.assertNotIn("CB203", rules_of(scan_text("a.js", "js", code)))

    def test_shell_injection(self):
        code = 'subprocess.run(f"ping {host}", shell=True)\n'
        self.assertIn("CB205", rules_of(scan_text("a.py", "python", code)))

    def test_static_shell_command_is_fine(self):
        code = 'subprocess.run("ls -la", shell=True)\n'
        self.assertNotIn("CB205", rules_of(scan_text("a.py", "python", code)))

    def test_yaml_safe_loader_is_fine(self):
        self.assertEqual(scan_text("a.py", "python", "yaml.load(data, Loader=yaml.SafeLoader)\n"), [])
        self.assertIn("CB206", rules_of(scan_text("a.py", "python", "yaml.load(data)\n")))

    def test_flask_debug(self):
        self.assertIn("CB201", rules_of(scan_text("a.py", "python", "app.run(debug=True)\n")))


class ContainerRules(unittest.TestCase):
    def test_dockerfile_without_user(self):
        self.assertIn("CB301", rules_of(scan_text("Dockerfile", "docker", "FROM python:3.12\nCMD x\n")))

    def test_dockerfile_with_user(self):
        text = "FROM python:3.12\nRUN useradd app\nUSER app\nCMD x\n"
        self.assertNotIn("CB301", rules_of(scan_text("Dockerfile", "docker", text)))

    def test_multistage_only_last_stage_counts(self):
        text = "FROM node AS build\nUSER node\nFROM nginx\nCOPY . .\n"
        self.assertIn("CB301", rules_of(scan_text("Dockerfile", "docker", text)))

    def test_compose_db_port(self):
        text = 'services:\n  db:\n    ports:\n      - "5432:5432"\n'
        self.assertIn("CB304", rules_of(scan_text("docker-compose.yml", "compose", text)))

    def test_compose_db_port_on_localhost(self):
        text = 'services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"\n'
        self.assertNotIn("CB304", rules_of(scan_text("docker-compose.yml", "compose", text)))

    def test_docker_socket(self):
        text = "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n"
        [f] = scan_text("docker-compose.yml", "compose", text)
        self.assertEqual((f.requires, f.grants), ({"container_root"}, {"host_root"}))


class Dependencies(unittest.TestCase):
    def test_version_ranges(self):
        self.assertTrue(is_affected("5.3.1", [("0", "5.4")]))
        self.assertFalse(is_affected("5.4", [("0", "5.4")]))
        self.assertTrue(is_affected("4.0.2", [("0", "3.2.14"), ("4.0", "4.0.6")]))
        self.assertFalse(is_affected("4.1", [("0", "3.2.14"), ("4.0", "4.0.6")]))

    def test_requirements(self):
        found = scan_text("requirements.txt", "requirements", "PyYAML==5.3.1\nrequests==2.32.0\n")
        self.assertEqual([f.line for f in found], [1])

    def test_package_json(self):
        text = '{\n  "dependencies": {\n    "lodash": "^4.17.15",\n    "express": "^4.19.0"\n  }\n}\n'
        [f] = scan_text("package.json", "package_json", text)
        self.assertEqual((f.line, f.grants), (3, {"rce"}))


if __name__ == "__main__":
    unittest.main()
