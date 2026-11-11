"""Python analyzer: AST walk + lightweight intra-procedural taint tracking.

Sources : flask/django `request.*`, input(), sys.argv, route parameters
Sinks   : SQL execute, os.system/popen, subprocess(shell=True), eval/exec, pickle/yaml,
          render_template_string, open/send_file, requests (SSRF), redirect ...
Sanitizers (break taint): int(), float(), secure_filename(), escape(), shlex.quote(), ...
"""
import ast
import re
from .core import make

SECRET_NAME = re.compile(r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key)", re.I)
STRONG_SECRET = re.compile(r"(pass|secret|private|api[_-]?key)", re.I)
NOT_SECRET_SUFFIX = re.compile(r"(file|path|url|uri|header|field|name|type|prefix|env|label|min|max|length|len|param|key_id|expiry|ttl|timeout|endpoint)$", re.I)
PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|\{\{.*\}\}|x{3,}|\*+|your[-_ ].*|\.\.\.)$", re.I)
SQL_RE = re.compile(r"\b(select|insert|update|delete|drop|create|alter|where|from|union)\b", re.I)
AUTH_DECO = re.compile(r"(login_required|jwt_required|permission|roles?_required|authenticated|requires?_auth|auth_required)", re.I)

REQUEST_ROOTS = {"request"}
SANITIZERS = {"int", "float", "bool", "len", "secure_filename", "escape", "quote", "quote_plus",
              "clean", "uuid4", "UUID", "fullmatch", "basename", "isdigit", "isalnum", "bleach"}
ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch"}
SUBPROC = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "extra", "RawSQL"}
LOOKUP_METHODS = {"execute", "get", "filter", "filter_by", "query", "first", "one", "find_one",
                  "get_or_404", "first_or_404", "select", "find", "fetchone", "fetchall"}
HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}
FILE_SINKS = {"send_file", "open", "io.open", "os.remove", "os.unlink", "shutil.rmtree",
              "shutil.copy", "shutil.move", "os.rename", "os.listdir"}


def dotted(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        b = dotted(n.value)
        return f"{b}.{n.attr}" if b else n.attr
    if isinstance(n, ast.Call):
        return dotted(n.func)
    return ""


def is_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def is_const(n, val):
    return isinstance(n, ast.Constant) and n.value is val


def walk_scope(nodes):
    """Yield nodes of one scope without descending into nested functions."""
    stack = [n for n in nodes if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    while stack:
        n = stack.pop()
        yield n
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            stack.append(c)


class PyAnalyzer:
    def __init__(self, path, source):
        self.path = path
        self.lines = source.splitlines()
        self.tree = ast.parse(source)
        self.findings = []

    # ---------- helpers ----------
    def line_text(self, lineno):
        return self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""

    def add(self, rule, node, severity, message="", confidence="MEDIUM"):
        text = self.line_text(node.lineno)
        if "scr:ignore" in text or "nosec" in text:
            return
        self.findings.append(make(rule, severity, self.path, node.lineno, text.strip()[:200], message, "ast", confidence))

    def tainted(self, n, T):
        if isinstance(n, ast.Call):
            nm = dotted(n.func).split(".")[-1]
            if nm in SANITIZERS:
                return False
            if dotted(n.func) in ("input", "sys.stdin.read", "sys.stdin.readline"):
                return True
        if isinstance(n, ast.Name):
            return n.id in T
        if isinstance(n, ast.Attribute):
            root = n
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                return root.id in REQUEST_ROOTS or root.id in T or dotted(n) == "sys.argv"
            return self.tainted(root, T)
        return any(self.tainted(c, T) for c in ast.iter_child_nodes(n))

    def dyn_text(self, n, dyn):
        """Return the constant text of a dynamically built string, or None if not dynamic."""
        if isinstance(n, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in n.values):
                return " ".join(v.value for v in n.values if is_str(v))
            return None
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            if is_str(n.left) and is_str(n.right):
                return None
            l, r = self.dyn_text(n.left, dyn), self.dyn_text(n.right, dyn)
            lc = n.left.value if is_str(n.left) else None
            rc = n.right.value if is_str(n.right) else None
            if any(x is not None for x in (lc, rc, l, r)):
                return " ".join(x for x in (lc, rc, l, r) if x)
            return None
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format"
                and is_str(n.func.value) and (n.args or n.keywords)):
            return n.func.value.value
        if isinstance(n, ast.Name) and n.id in dyn:
            return dyn[n.id]
        return None

    # ---------- driver ----------
    def run(self):
        self.scope(list(self.tree.body), set(), None)
        for fn in ast.walk(self.tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.function(fn)
        return self.findings

    def function(self, fn):
        routes = [d for d in fn.decorator_list if isinstance(d, ast.Call)
                  and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_METHODS]
        params, int_params = set(), set()
        if routes:
            path = next((a.value for a in routes[0].args if is_str(a)), "")
            int_params = set(re.findall(r"<int:(\w+)>", path))
            params = {a.arg for a in fn.args.args if a.arg not in int_params and a.arg not in ("self", "cls")}
        for d in fn.decorator_list:
            if dotted(d).endswith("csrf_exempt"):
                self.add("PY-CSRF", fn, "MEDIUM", f"@csrf_exempt on '{fn.name}'")
        self.scope(fn.body, params, fn)
        if routes:
            self.check_idor(fn, routes, int_params)

    def scope(self, body, params, fn):
        nodes = list(walk_scope(body))
        T, dyn = set(params), {}
        for _ in range(3):  # small fixed-point to propagate through assignments
            for n in nodes:
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    names = [t.id for tg in targets for t in ast.walk(tg) if isinstance(t, ast.Name)]
                    if self.tainted(n.value, T):
                        T.update(names)
                    txt = self.dyn_text(n.value, dyn)
                    if txt is not None:
                        for nm in names:
                            dyn[nm] = txt
                elif isinstance(n, (ast.For, ast.AsyncFor)) and self.tainted(n.iter, T):
                    T.update(t.id for t in ast.walk(n.target) if isinstance(t, ast.Name))
                elif isinstance(n, ast.With):
                    for it in n.items:
                        if it.optional_vars is not None and self.tainted(it.context_expr, T):
                            T.update(t.id for t in ast.walk(it.optional_vars) if isinstance(t, ast.Name))
        scope_has_password = any(
            (is_str(n) and re.search(r"pass|pwd", n.value, re.I)) or (isinstance(n, ast.Name) and re.search(r"pass|pwd", n.id, re.I))
            for n in nodes)
        for n in nodes:
            if isinstance(n, ast.Call):
                self.check_call(n, T, dyn, scope_has_password)
            elif isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                self.check_assign(n)
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if is_str(k) and is_str(v):
                        self.maybe_secret(k.value, v.value, v)

    # ---------- checks ----------
    def check_call(self, n, T, dyn, scope_has_password):
        name = dotted(n.func)
        last = name.split(".")[-1]
        a0 = n.args[0] if n.args else None
        kw = {k.arg: k.value for k in n.keywords if k.arg}
        t0 = a0 is not None and self.tainted(a0, T)
        sev = lambda hi, lo: hi if t0 else lo

        if name in ("eval", "exec") and a0 is not None and not is_str(a0):
            self.add("PY-EXEC", n, sev("CRITICAL", "HIGH"), "Dynamic code execution" + (" with user-controlled input" if t0 else ""))

        if name in ("os.system", "os.popen", "commands.getoutput") and a0 is not None:
            if self.dyn_text(a0, dyn) is not None or t0:
                self.add("PY-CMDI", n, sev("CRITICAL", "HIGH"), "Shell command built from dynamic string" + (" containing user input" if t0 else ""), "HIGH" if t0 else "MEDIUM")

        if name.startswith("subprocess.") and last in SUBPROC:
            if is_const(kw.get("shell"), True):
                if a0 is not None and (self.dyn_text(a0, dyn) is not None or t0):
                    self.add("PY-CMDI", n, sev("CRITICAL", "HIGH"), "subprocess shell=True with dynamic command" + (" from user input" if t0 else ""), "HIGH")
                else:
                    self.add("PY-SHELL", n, "LOW", "shell=True with a constant command")

        if last in SQL_METHODS and "." in name and a0 is not None:
            txt = self.dyn_text(a0, dyn)
            if txt is not None and SQL_RE.search(txt):
                self.add("PY-SQLI", n, sev("CRITICAL", "HIGH"), "SQL statement built by string formatting" + (" from user input" if t0 else ""), "HIGH" if t0 else "MEDIUM")

        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "dill.load",
                    "marshal.loads", "jsonpickle.decode", "pickle.Unpickler"):
            self.add("PY-DESER", n, sev("HIGH", "MEDIUM"), f"{name}() on " + ("user-controlled data" if t0 else "data of unknown origin"))

        if name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load"):
            loader = kw.get("Loader") or (n.args[1] if len(n.args) > 1 else None)
            safe = loader is not None and dotted(loader).split(".")[-1] in ("SafeLoader", "CSafeLoader", "BaseLoader")
            if name == "yaml.unsafe_load" or not safe:
                self.add("PY-YAML", n, sev("HIGH", "MEDIUM"), "yaml load without SafeLoader")

        weak = name in ("hashlib.md5", "hashlib.sha1") or (name == "hashlib.new" and is_str(a0) and a0.value.lower() in ("md5", "sha1"))
        if weak and not is_const(kw.get("usedforsecurity"), False):
            self.add("PY-HASH", n, "HIGH" if scope_has_password else "MEDIUM",
                     "MD5/SHA-1 used" + (" in password-handling code" if scope_has_password else ""))

        if kw.get("verify") is not None and is_const(kw["verify"], False) and not name.startswith("jwt"):
            self.add("PY-TLS", n, "HIGH", "verify=False disables certificate validation", "HIGH")
        if name in ("ssl._create_unverified_context",) or is_const(kw.get("check_hostname"), False):
            self.add("PY-TLS", n, "HIGH", "Unverified SSL context")

        if last == "run" and is_const(kw.get("debug"), True):
            self.add("PY-DEBUG", n, "HIGH", "app.run(debug=True) exposes the interactive debugger (remote code execution)", "HIGH")
        if last == "run" and is_str(kw.get("host")) and kw["host"].value == "0.0.0.0":
            self.add("PY-BIND", n, "MEDIUM", "Service listens on 0.0.0.0")

        if last == "render_template_string" and a0 is not None and (self.dyn_text(a0, dyn) is not None or t0):
            self.add("PY-SSTI", n, sev("CRITICAL", "HIGH"), "Template string built dynamically" + (" with user input (SSTI/XSS)" if t0 else ""), "HIGH")
        if last in ("Markup", "mark_safe", "SafeString") and a0 is not None and (t0 or self.dyn_text(a0, dyn) is not None):
            self.add("PY-XSS", n, sev("HIGH", "MEDIUM"), f"{last}() on dynamic data")

        if name in FILE_SINKS and t0:
            self.add("PY-PATH", n, "HIGH", f"{name}() with user-controlled path", "HIGH")

        is_http = (name.split(".")[0] in ("requests", "httpx") and last in HTTP_METHODS) or last == "urlopen"
        if is_http and t0:
            self.add("PY-SSRF", n, "HIGH", "Outbound request to user-controlled URL")
        if last == "redirect" and t0:
            self.add("PY-REDIR", n, "MEDIUM", "Redirect to user-controlled target")
        if name == "tempfile.mktemp":
            self.add("PY-TMP", n, "MEDIUM", "tempfile.mktemp() is race-prone")
        if name.endswith("jwt.decode") or name == "jwt.decode":
            if re.search(r"verify_signature['\"]\s*:\s*False|verify\s*=\s*False", ast.unparse(n)):
                self.add("PY-JWT", n, "HIGH", "JWT decoded without signature verification")
        if name in ("os.chmod", "os.makedirs") and len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and n.args[1].value in (0o777, 0o666):
            self.add("PY-PERM", n, "MEDIUM", "World-writable permissions")
        for k in n.keywords:
            if k.arg and is_str(k.value):
                self.maybe_secret(k.arg, k.value.value, n)

    def maybe_secret(self, label, value, node):
        if (len(value) < 4 or PLACEHOLDER.match(value) or not SECRET_NAME.search(label)
                or NOT_SECRET_SUFFIX.search(label) or value.lower() == label.lower() or (" " in value and len(value) > 30)):
            return
        self.add("PY-SECRET", node, "HIGH" if STRONG_SECRET.search(label) else "MEDIUM",
                 f"Hardcoded value assigned to '{label}'", "HIGH" if STRONG_SECRET.search(label) else "MEDIUM")

    def check_assign(self, n):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        for t in targets:
            label = None
            if isinstance(t, ast.Name):
                label = t.id
            elif isinstance(t, ast.Attribute):
                label = t.attr
            elif isinstance(t, ast.Subscript) and is_str(t.slice):
                label = t.slice.value
            if not label:
                continue
            if is_str(n.value):
                self.maybe_secret(label, n.value.value, n)
            if label == "DEBUG" and is_const(n.value, True):
                self.add("PY-DEBUG", n, "MEDIUM", "DEBUG = True")
            if label == "ALLOWED_HOSTS" and isinstance(n.value, (ast.List, ast.Tuple)) and any(is_str(e) and e.value == "*" for e in n.value.elts):
                self.add("PY-HOSTS", n, "MEDIUM", "ALLOWED_HOSTS contains '*'")
            if label in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY") and is_const(n.value, False):
                self.add("PY-COOKIE", n, "MEDIUM", f"{label} = False")

    def check_idor(self, fn, routes, int_params):
        id_params = set(int_params) | {a.arg for a in fn.args.args if re.search(r"(^|_)id$", a.arg, re.I)}
        if not id_params:
            return
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        uses_identity = bool(names & {"session", "current_user", "g"}) or any(
            isinstance(n, ast.Attribute) and n.attr in ("user", "current_user") for n in ast.walk(fn))
        lookup = any(isinstance(n, ast.Call) and dotted(n.func).split(".")[-1] in LOOKUP_METHODS for n in ast.walk(fn))
        if lookup and not uses_identity:
            self.add("PY-IDOR", fn, "MEDIUM",
                     f"Route '{fn.name}' loads an object by user-supplied id ({', '.join(sorted(id_params))}) "
                     "but never checks session/current_user ownership (heuristic)", "LOW")


def analyze(path, source):
    return PyAnalyzer(path, source).run()
