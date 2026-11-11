"""Unit tests: each rule must fire on bad code and stay silent on the fixed version."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scr.pyast import analyze
from scr.regex_rules import scan_text


def rules(src):
    return {f.rule_id for f in analyze("t.py", src)}


class PythonRules(unittest.TestCase):
    def test_sqli_fstring_tainted(self):
        bad = 'from flask import request\ndef f():\n    u=request.args["u"]\n    db.execute(f"SELECT * FROM t WHERE u=\'{u}\'")\n'
        self.assertIn("PY-SQLI", rules(bad))
        good = 'def f(u):\n    db.execute("SELECT * FROM t WHERE u=?", (u,))\n'
        self.assertNotIn("PY-SQLI", rules(good))

    def test_sqli_through_variable(self):
        bad = 'def f(u):\n    q = "SELECT * FROM t WHERE u=" + u\n    cur.execute(q)\n'
        self.assertIn("PY-SQLI", rules(bad))

    def test_cmdi(self):
        self.assertIn("PY-CMDI", rules('import os\ndef f(h):\n    os.system("ping " + h)\n'))
        self.assertNotIn("PY-CMDI", rules('import subprocess\nsubprocess.run(["ping", h])\n'))

    def test_taint_sanitizer_int(self):
        bad = 'from flask import request\ndef f():\n    x=int(request.args["x"])\n    open(x)\n'
        self.assertNotIn("PY-PATH", rules(bad))

    def test_path_traversal_and_secure_filename(self):
        bad = 'from flask import request, send_file\ndef f():\n    return send_file(request.args["f"])\n'
        self.assertIn("PY-PATH", rules(bad))
        good = 'from flask import request, send_file\ndef f():\n    return send_file(secure_filename(request.args["f"]))\n'
        self.assertNotIn("PY-PATH", rules(good))

    def test_deser_yaml(self):
        self.assertIn("PY-DESER", rules("import pickle\npickle.loads(b)\n"))
        self.assertIn("PY-YAML", rules("import yaml\nyaml.load(s)\n"))
        self.assertNotIn("PY-YAML", rules("import yaml\nyaml.safe_load(s)\n"))
        self.assertNotIn("PY-YAML", rules("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"))

    def test_ssti(self):
        bad = 'from flask import request\ndef f():\n    return render_template_string("<h1>"+request.args["n"])\n'
        self.assertIn("PY-SSTI", rules(bad))
        self.assertNotIn("PY-SSTI", rules('def f(n):\n    return render_template_string("<h1>{{n}}</h1>", n=n)\n'))

    def test_secret_and_placeholder(self):
        self.assertIn("PY-SECRET", rules('password = "hunter2hunter2"\n'))
        self.assertNotIn("PY-SECRET", rules('password = os.environ["PW"]\n'))
        self.assertNotIn("PY-SECRET", rules('PASSWORD_FIELD = "password"\n'))

    def test_idor(self):
        bad = '@app.route("/u/<int:uid>")\ndef p(uid):\n    return db.execute("SELECT 1 WHERE id=?", (uid,)).fetchone()\n'
        self.assertIn("PY-IDOR", rules(bad))
        good = '@app.route("/u/<int:uid>")\ndef p(uid):\n    if uid != session["uid"]:\n        abort(403)\n    return db.execute("SELECT 1 WHERE id=?", (uid,)).fetchone()\n'
        self.assertNotIn("PY-IDOR", rules(good))

    def test_misc(self):
        self.assertIn("PY-DEBUG", rules("app.run(debug=True)\n"))
        self.assertIn("PY-TLS", rules("requests.get(u, verify=False)\n"))
        self.assertIn("PY-HASH", rules("import hashlib\nhashlib.md5(b)\n"))
        self.assertNotIn("PY-HASH", rules("import hashlib\nhashlib.md5(b, usedforsecurity=False)\n"))

    def test_ignore_comment(self):
        self.assertNotIn("PY-DEBUG", rules("app.run(debug=True)  # scr:ignore\n"))


class RegexRules(unittest.TestCase):
    def ids(self, ext, src):
        return {f.rule_id for f in scan_text("x" + ext, ext, src)}

    def test_secrets(self):
        self.assertIn("SEC-KEY", self.ids(".env", "AWS=AKIAIOSFODNN7EXAMPLE\n"))
        self.assertIn("SEC-KEY", self.ids(".txt", "-----BEGIN RSA PRIVATE KEY-----\n"))

    def test_secret_is_redacted(self):
        f = scan_text("a.env", ".env", "k=AKIAIOSFODNN7EXAMPLE\n")[0]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f.snippet)

    def test_php_js_c(self):
        self.assertIn("PHP-SQLI", self.ids(".php", 'mysqli_query($c, "SELECT * FROM u WHERE id=".$_GET["id"]);\n'))
        self.assertIn("JS-EVAL", self.ids(".js", "eval(userInput)\n"))
        self.assertIn("C-UNSAFE", self.ids(".c", "strcpy(a,b);\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
