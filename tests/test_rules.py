"""Every rule gets a positive fixture and, where FPs are likely, a negative one."""
import os

import pytest

from pqgate.profiles import get_profile
from pqgate.rules import RuleSetError, all_rules, load_manifests, load_rules
from pqgate.scanner import classify_pqc, scan_tree

CNSA = get_profile("cnsa-2.0")
BASELINE = get_profile("nist-baseline")

# rule id -> (filename, source that must trigger it)
POSITIVE = {
    "py-rsa-keygen": ("a.py", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"),
    "py-ec-keygen": ("a.py", "k = ec.generate_private_key(ec.SECP384R1())\n"),
    "py-dh": ("a.py", "p = dh.generate_parameters(generator=2, key_size=2048)\n"),
    "py-md5": ("a.py", "import hashlib\nd = hashlib.md5(b'x').hexdigest()\n"),
    "py-sha1": ("a.py", "import hashlib\nd = hashlib.sha1(b'x').hexdigest()\n"),
    "py-sha256-sig": ("a.py", "sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())\n"),
    "py-3des": ("a.py", "c = algorithms.TripleDES(key)\n"),
    "py-aes-128": ("a.py", "cipher = build(name='AES-128-GCM')\n"),
    "py-jwt-classical": ("a.py", "tok = jwt.encode(claims, key, algorithm='RS256')\n"),
    "py-pqc-oqs": ("a.py", "kem = oqs.KeyEncapsulation('ML-KEM-1024')\n"),
    "go-rsa-keygen": ("a.go", "k, _ := rsa.GenerateKey(rand.Reader, 2048)\n"),
    "go-ecdsa-keygen": ("a.go", "k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n"),
    "go-ed25519": ("a.go", "pub, priv, _ := ed25519.GenerateKey(rand.Reader)\n"),
    "go-md5": ("a.go", "h := md5.New()\n"),
    "go-sha1": ("a.go", "h := sha1.New()\n"),
    "go-des": ("a.go", "c, _ := des.NewTripleDESCipher(key)\n"),
    "go-pqc-mlkem": ("a.go", "kem := mlkem1024.Scheme()\n"),
    "java-rsa": ("A.java", "KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n"),
    "java-ec": ("A.java", "KeyPairGenerator g = KeyPairGenerator.getInstance(\"ECDSA\");\n"),
    "java-md5": ("A.java", "MessageDigest d = MessageDigest.getInstance(\"MD5\");\n"),
    "java-sha1": ("A.java", "MessageDigest d = MessageDigest.getInstance(\"SHA-1\");\n"),
    "java-des": ("A.java", "Cipher c = Cipher.getInstance(\"DESede/CBC/PKCS5Padding\");\n"),
    "java-pqc-bc": ("A.java", "Signature s = Signature.getInstance(\"ML-DSA-87\", \"BC\");\n"),
}

# Sources that must produce ZERO findings — the false-positive gate.
NEGATIVE = [
    ("clean.py", "import hashlib\nd = hashlib.sha384(b'x').hexdigest()\n"),
    ("comment.py", "# k = rsa.generate_private_key(65537, 2048)\nx = 1\n"),
    ("docstring.py", '"""Do not use rsa.generate_private_key here."""\nx = 1\n'),
    ("string.py", "MSG = 'call rsa.generate_private_key to make a key'\n"),
    ("name.py", "def md5_is_banned():\n    return True\n"),
    ("comment.go", "// k, _ := rsa.GenerateKey(rand.Reader, 2048)\npackage main\n"),
    ("block.java", "/* KeyPairGenerator.getInstance(\"RSA\"); */\nclass A {}\n"),
    ("trailing.go", "x := 1 // md5.New() was removed\n"),
]


def _scan_source(tmp_path, filename, source, profile=CNSA):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    return scan_tree(str(tmp_path), profile)


def test_every_algorithm_rule_has_a_positive_fixture():
    """SC-13 rules live here; the SC-12 packs are covered by test_rules_sc12.py."""
    from tests.test_rules_sc12 import POSITIVE as SC12_POSITIVE
    ids = {r.id for r in all_rules()}
    missing = ids - set(POSITIVE) - set(SC12_POSITIVE)
    assert not missing, "rules with no positive fixture: " + str(sorted(missing))


@pytest.mark.parametrize("rule_id", sorted(POSITIVE))
def test_rule_fires(tmp_path, rule_id):
    filename, source = POSITIVE[rule_id]
    findings = _scan_source(tmp_path, filename, source)
    assert rule_id in {f["rule"] for f in findings}, [f["rule"] for f in findings]


@pytest.mark.parametrize("filename,source", NEGATIVE, ids=[n for n, _ in NEGATIVE])
def test_no_false_positives(tmp_path, filename, source):
    findings = _scan_source(tmp_path, filename, source)
    assert findings == [], [(f["rule"], f["evidence"]) for f in findings]


def test_false_positive_rate_under_five_percent(tmp_path):
    """Release blocker per CLAUDE.md rule 4: FP rate <5% on the corpus."""
    for i, (name, source) in enumerate(NEGATIVE):
        (tmp_path / (str(i) + "_" + name)).write_text(source, encoding="utf-8")
    for i, (name, source) in enumerate(POSITIVE.values()):
        (tmp_path / ("p" + str(i) + "_" + name)).write_text(source, encoding="utf-8")
    findings = scan_tree(str(tmp_path), CNSA)
    false_positives = [f for f in findings if os.path.basename(f["file"])[0].isdigit()]
    rate = len(false_positives) / max(len(findings), 1)
    assert rate < 0.05, "FP rate " + str(round(rate * 100, 1)) + "%: " + str(
        [(f["rule"], f["file"]) for f in false_positives])


# --------------------------------------------------------------------------
def test_ast_resolves_constant_before_call(tmp_path):
    src = "ALG = 'ML-KEM-768'\nkem = oqs.KeyEncapsulation(ALG)\n"
    findings = _scan_source(tmp_path, "k.py", src)
    hit = [f for f in findings if f["rule"] == "py-pqc-oqs"][0]
    assert hit["detector"] == "ast"
    assert hit["classification"] == "pqc-below-profile"


def test_ast_wins_over_regex_at_same_site(tmp_path):
    findings = _scan_source(tmp_path, "k.py", "k = rsa.generate_private_key(65537, 2048)\n")
    assert [f["detector"] for f in findings] == ["ast"]


def test_regex_fallback_on_syntax_error(tmp_path):
    src = "def broken(:\n    k = rsa.generate_private_key(65537, 2048)\n"
    findings = _scan_source(tmp_path, "k.py", src)
    assert {f["rule"] for f in findings} == {"py-rsa-keygen"}
    assert findings[0]["detector"] == "regex"


@pytest.mark.parametrize("text,expected", [
    ("ML-KEM-1024", "pqc-safe"),
    ("ML-DSA-87", "pqc-safe"),
    ("LMS", "pqc-safe"),
    ("ML-KEM-768", "pqc-below-profile"),
    ("Kyber512", "pqc-below-profile"),
    ("Dilithium3", "pqc-below-profile"),
])
def test_cnsa_parameter_set_exactness(text, expected):
    assert classify_pqc(CNSA, text)[0] == expected


def test_baseline_accepts_lower_parameter_sets():
    assert classify_pqc(BASELINE, "ML-KEM-768")[0] == "pqc-safe"


def test_committed_private_key_detected(tmp_path):
    (tmp_path / "id_rsa.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n")
    findings = scan_tree(str(tmp_path), CNSA)
    assert findings[0]["classification"] == "committed-key"


def test_manifest_layer(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\nliboqs-python==0.10.0\n")
    findings = scan_tree(str(tmp_path), CNSA)
    rules = {f["rule"] for f in findings}
    assert {"dep-cryptography", "dep-liboqs-python"} <= rules
    assert all(f["line"] > 0 for f in findings), "manifest findings need real line numbers"


def test_skip_dirs_are_not_scanned(tmp_path):
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "x.py").write_text("k = rsa.generate_private_key(65537, 2048)\n")
    assert scan_tree(str(tmp_path), CNSA) == []


def test_rule_data_is_validated(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("version: 1\nrules:\n  - id: x\n    lang: ['.py']\n    regex: '('\n"
                   "    class: weak-hash\n    message: m\n")
    with pytest.raises(RuleSetError):
        load_rules(str(bad))


def test_duplicate_rule_ids_rejected(tmp_path):
    bad = tmp_path / "dup.yml"
    bad.write_text(
        "version: 1\nrules:\n"
        "  - {id: x, lang: ['.py'], regex: 'a', class: weak-hash, message: m}\n"
        "  - {id: x, lang: ['.py'], regex: 'b', class: weak-hash, message: m}\n")
    with pytest.raises(RuleSetError):
        load_rules(str(bad))


def test_manifest_kb_loads():
    kb = load_manifests()
    assert "requirements.txt" in kb and "go.mod" in kb and "pom.xml" in kb
