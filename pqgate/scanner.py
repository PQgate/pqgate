"""Detection layers.

Layer 1 - dependency manifests (requirements.txt, go.mod, pom.xml)
Layer 2 - source code. Python uses a real AST pass (stdlib `ast`) with string-constant
          tracking; Go/Java use comment-stripped regex until the tree-sitter pass lands.
Layer 3 - committed private key material.
Layer 4 - configuration and infrastructure-as-code. Cipher choice, key rotation and
          crypto periods live here, not in application source.
Layer 5 - cryptographic module validation (FIPS 140-2/140-3, CMVP).

Layers 4 and 5 exist because SC-12 asks a different question from SC-13: not "which
algorithm did you pick" but "where did the key come from, in what validated module,
and what happens to it over its life".
"""
import ast
import os
import re

from .rules import load_cmvp, load_file_rules, load_manifests, load_rules

KEY_FILE_EXT = {".pem", ".key", ".p12", ".jks", ".pfx"}
PRIVKEY_RE = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".tox", ".venv",
             "venv", "dist", "build", ".mypy_cache", ".pytest_cache", ".terraform"}
MAX_FILE_BYTES = 2 * 1024 * 1024

_LINE_COMMENT = re.compile(r"(^|\s)(//|#).*$")

# Non-approved RNG calls are only a key-management finding when the value is actually
# used as key material. Without this, every temp-filename suffix in every CLI library
# becomes an SP 800-133 violation.
# Matching is on identifier *tokens*, not substrings: 'iv' must not fire on
# 'private', and 'mac' must not fire on 'machine'.
KEY_TOKENS = {
    "key", "keys", "secret", "secrets", "token", "nonce", "iv", "salt", "seed",
    "password", "passwd", "passphrase", "crypt", "crypto", "cipher", "encrypt",
    "decrypt", "sign", "signing", "signature", "hmac", "mac", "auth", "session",
    "otp", "challenge", "kdf", "derive", "keygen", "keypair",
}
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def key_context_tokens(name):
    return {t.lower() for t in _TOKEN_SPLIT.split(name or "") if t}


def is_key_context(name):
    return bool(key_context_tokens(name) & KEY_TOKENS)


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def mk(rule_id, cls, msg, path, line, snippet, detector="regex",
       controls=(), standards=(), remediation=""):
    return {
        "rule": rule_id,
        "classification": cls,
        "message": msg,
        "file": os.path.normpath(path),
        "line": line,
        "evidence": snippet.strip()[:160],
        "detector": detector,
        "controls": list(controls),
        "standards": list(standards),
        "remediation": remediation,
    }


def _from_rule(rule, cls, msg, path, line, snippet, detector="regex"):
    return mk(rule.id, cls, msg, path, line, snippet, detector=detector,
              controls=rule.controls, standards=rule.standards,
              remediation=rule.remediation)


def classify_pqc(profile, text):
    """Resolve a pqc-safe hit against the profile's required parameter sets."""
    blob = text.upper()
    has_ok = any(tok in blob for tok in profile.get("pqc_ok", ()))
    has_low = any(tok in blob for tok in profile.get("pqc_low", ()))
    if has_low and not has_ok:
        return "pqc-below-profile", "PQC present but below profile parameter set"
    if has_ok:
        return "pqc-safe", "meets profile parameter set"
    return "pqc-safe", "PQC detected (parameter set unresolved - verify)"


# --------------------------------------------------------------------------
# Layer 2a: Python AST
# --------------------------------------------------------------------------
def _dotted(node):
    """Resolve a call target to a dotted name: Attribute(Name(rsa), gen) -> rsa.gen"""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return None
    return ".".join(reversed(parts))


class _PyVisitor(ast.NodeVisitor):
    """Collects crypto call sites and tracks string constants assigned to names."""

    def __init__(self, rules):
        self.rules = [r for r in rules if r.ast_calls]
        self.consts = {}
        self.hits = []
        self.scope = []      # enclosing function/class names
        self.target = None   # assignment target currently being evaluated

    def _in_key_context(self):
        names = [n for n in self.scope if n] + ([self.target] if self.target else [])
        return any(is_key_context(n) for n in names)

    def visit_FunctionDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.consts[tgt.id] = node.value.value
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        previous, self.target = self.target, (names[0] if names else None)
        self.generic_visit(node)
        self.target = previous

    def visit_AnnAssign(self, node):
        if (node.value is not None and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and isinstance(node.target, ast.Name)):
            self.consts[node.target.id] = node.value.value
        self.generic_visit(node)

    def _literal(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        return None

    def visit_Call(self, node):
        name = _dotted(node.func)
        if name:
            for rule in self.rules:
                if not any(name == c or name.endswith("." + c) for c in rule.ast_calls):
                    continue
                text = name
                if rule.ast_literal_arg is not None and len(node.args) > rule.ast_literal_arg:
                    lit = self._literal(node.args[rule.ast_literal_arg])
                    if lit:
                        text = name + "(" + lit + ")"
                if rule.key_context and not self._in_key_context():
                    continue
                self.hits.append((rule, node.lineno, text))
        self.generic_visit(node)


def _scan_python_ast(path, content, rules, profile):
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None  # unparseable: caller falls back to regex
    visitor = _PyVisitor(rules)
    visitor.visit(tree)
    lines = content.splitlines()
    out = []
    for rule, lineno, text in visitor.hits:
        cls, msg = rule.classification, rule.message
        if cls == "pqc-safe":
            cls, note = classify_pqc(profile, text)
            msg = rule.message + " - " + note
        snippet = lines[lineno - 1] if 0 < lineno <= len(lines) else text
        out.append(_from_rule(rule, cls, msg, path, lineno, snippet, detector="ast"))
    return out


# --------------------------------------------------------------------------
# Layer 2b / 4: comment-stripped regex
# --------------------------------------------------------------------------
def _blank_block_comments(content):
    """Blank out /* ... */ bodies while preserving the newlines inside them.

    Deleting the match outright collapses multi-line comments and shifts every
    subsequent line number - which silently puts SARIF annotations on the wrong line
    in any Java or Go file with a licence header.
    """
    return _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), content)


def _scan_regex(path, content, rules, profile, skip_rule_ids=()):
    out = []
    content = _blank_block_comments(content)
    for lineno, line in enumerate(content.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*")):
            continue
        code = _LINE_COMMENT.sub("", line)
        for rule in rules:
            if rule.id in skip_rule_ids:
                continue
            m = rule.regex.search(code)
            if not m:
                continue
            cls, msg = rule.classification, rule.message
            if cls == "pqc-safe":
                groups = m.groupdict()
                text = groups.get("alg") or groups.get("param") or m.group(0)
                cls, note = classify_pqc(profile, text)
                msg = rule.message + " - " + note
            out.append(_from_rule(rule, cls, msg, path, lineno, line))
    return out


# --------------------------------------------------------------------------
# Layer 1 + 5: manifests and module validation
# --------------------------------------------------------------------------
def _scan_manifest(path, kb, cmvp):
    content = _read(path)
    if content is None:
        return []
    out, modules_seen = [], set()
    for lineno, line in enumerate(content.splitlines(), 1):
        for pkg, meta in kb.items():
            if pkg not in line:
                continue
            out.append(mk("dep-" + pkg, meta["class"],
                          meta["message"] + " (dependency: " + pkg + ")",
                          path, lineno, line,
                          controls=meta["controls"], standards=meta["standards"]))
            module_id = meta.get("module")
            if module_id and module_id not in modules_seen:
                modules_seen.add(module_id)
                finding = _module_finding(module_id, cmvp, path, lineno, line, pkg)
                if finding:
                    out.append(finding)
    return out


def _module_finding(module_id, cmvp, path, lineno, line, pkg):
    """Layer 5: turn 'this library is present' into a validation posture (SC-12 / IA-7)."""
    module = cmvp.get(module_id)
    if module is None:
        return None

    status = module.get("status")
    if status == "historical":
        detail = ("Cryptographic module certificate is on the CMVP historical list"
                  + (" (cert " + str(module["cert"]) + ")" if module.get("cert") else "")
                  + (", sunset " + str(module["sunset"]) if module.get("sunset") else ""))
        return mk("module-" + module_id, "module-cert-historical", detail, path, lineno,
                  line, controls=("SC-12", "IA-7"), standards=("FIPS 140-3",),
                  remediation="Re-validate against FIPS 140-3 or migrate to a currently "
                              "validated module.")

    if not module["validated"]:
        detail = module["name"] + " is not a CMVP-validated cryptographic module"
        if module.get("instead_of"):
            alt = cmvp.get(module["instead_of"], {}).get("name", module["instead_of"])
            detail += "; the validated distribution is " + alt
        return mk("module-" + module_id, "module-not-validated", detail, path, lineno, line,
                  controls=("SC-12", "IA-7"), standards=("FIPS 140-3",),
                  remediation=module.get("note", "").strip() or
                              "Ship the validated module, or record the boundary in an exception.")

    if module.get("cert") is None:
        # Validated distribution, but no CMVP export loaded — say so rather than guess.
        return mk("module-" + module_id, "module-not-validated",
                  module["name"] + " is a validated distribution, but no CMVP certificate "
                  "has been imported — status unverified",
                  path, lineno, line, controls=("SC-12", "IA-7"),
                  standards=("FIPS 140-3",),
                  remediation="Run: pqgate cmvp import <validated-modules.json>")
    return None


def _scan_key_material(path, ext):
    if ext not in KEY_FILE_EXT and ext not in (".txt", "", ".pub", ".crt"):
        return []
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096).decode("utf-8", errors="ignore")
    except OSError:
        return []
    if PRIVKEY_RE.search(head):
        return [mk("committed-private-key", "committed-key",
                   "Private key material committed to repository", path, 1,
                   "-----BEGIN ... PRIVATE KEY-----",
                   controls=("SC-12", "SC-28"), standards=("SP 800-57",),
                   remediation="Revoke the key, rotate it, and purge it from history.")]
    return []


# --------------------------------------------------------------------------
def scan_tree(root, profile, rules_by_ext=None, manifest_kb=None,
              file_rules=None, cmvp=None):
    rules_by_ext = rules_by_ext if rules_by_ext is not None else load_rules()
    manifest_kb = manifest_kb if manifest_kb is not None else load_manifests()
    file_rules = file_rules if file_rules is not None else load_file_rules()
    cmvp = cmvp if cmvp is not None else load_cmvp()
    findings = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1]

            rules = rules_by_ext.get(ext)
            if rules:
                content = _read(path)
                if content is not None:
                    ast_hits = _scan_python_ast(path, content, rules, profile) if ext == ".py" else None
                    if ast_hits is None:
                        findings += _scan_regex(path, content, rules, profile)
                    else:
                        findings += ast_hits
                        covered = {r.id for r in rules if r.ast_calls}
                        findings += _scan_regex(path, content, rules, profile,
                                                skip_rule_ids=covered)

            # Layer 4: configuration and IaC, matched by filename.
            applicable = [r for r in file_rules if r.matches_file(name)]
            if applicable:
                content = _read(path)
                if content is not None:
                    findings += _scan_regex(path, content, applicable, profile)

            kb = manifest_kb.get(name)
            if kb:
                findings += _scan_manifest(path, kb, cmvp)

            findings += _scan_key_material(path, ext)

    return dedupe(findings)


def dedupe(findings):
    """AST hits win over regex hits at the same site."""
    order = {"ast": 0, "regex": 1}
    findings = sorted(findings, key=lambda f: order.get(f.get("detector"), 9))
    seen, out = set(), []
    for f in findings:
        key = (f["file"], f["line"], f["rule"]) if f["line"] else (f["file"], f["rule"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return sorted(out, key=lambda f: (f["file"], f["line"], f["rule"]))
