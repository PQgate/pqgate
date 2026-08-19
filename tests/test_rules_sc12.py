"""SC-12 rules: key generation, key establishment, module validation, key lifecycle.

Every rule in the keygen, keyestab, config and iac packs gets a positive fixture here,
and the negatives encode the precision decisions that keep these rules usable.
"""
import pytest

from pqgate.profiles import get_profile
from pqgate.rules import KEY_CLASSES, all_rules
from pqgate.scanner import is_key_context, scan_tree

CNSA = get_profile("cnsa-2.0")
FIPS = get_profile("fips-140-3")

# rule id -> (filename, source). Filenames matter: the config and IaC layers match on
# basename rather than extension.
POSITIVE = {
    # ---- SP 800-133 / SP 800-90A: key generation ----
    "py-keygen-weak-rbg": ("a.py", "import random\ndef session_key():\n    return random.randint(0, 255)\n"),
    "py-keygen-seeded-rbg": ("a.py", "import random\ndef make_key():\n    random.seed(42)\n"),
    "py-hardcoded-key": ("a.py", "secret_key = 'hunter2hunter2hunter2'\n"),
    "py-hardcoded-key-material": ("a.py", "SIGNING_KEY = '0123456789abcdef0123456789abcdef'\n"),
    "py-hardcoded-iv": ("a.py", "iv = 'abcdefghijkl'\n"),
    "py-pbkdf-not-approved": ("a.py", "k = bcrypt.kdf(password=p, salt=s)\n"),
    "go-keygen-weak-rbg": ("a.go", "sessionKey := mathrand.Intn(256)\n"),
    "go-hardcoded-key": ("a.go", 'privateKey = []byte("0123456789abcdefghij")\n'),
    "java-keygen-weak-rbg": ("A.java", "Random r = new Random();\n"),
    "java-securerandom-seeded": ("A.java", "SecureRandom r = new SecureRandom(seedBytes);\n"),
    "java-hardcoded-key": ("A.java", 'String signingKey = "0123456789abcdefghij";\n'),

    # ---- SP 800-56A/B/C: key establishment ----
    "py-rsa-pkcs1v15-encrypt": ("a.py", "ct = pub.encrypt(k, padding.PKCS1v15())\n"),
    "py-ecdh-raw-secret": ("a.py", "z = priv.exchange(ec.ECDH(), peer)\n"),
    "py-dh-raw-secret": ("a.py", "p = dh.DHParameterNumbers(pval, g)\n"),
    "py-static-ecdh-key": ("a.py", "STATIC_DH_PRIVATE_KEY = load()\n"),
    "go-rsa-pkcs1v15-encrypt": ("a.go", "ct, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, cek)\n"),
    "go-ecdh-raw-secret": ("a.go", "z, _ := priv.ECDH(peer)\n"),
    "java-rsa-pkcs1v15-encrypt": ("A.java", 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n'),
    "java-ecdh-raw-secret": ("A.java", "byte[] z = ka.generateSecret();\n"),

    # ---- Layer 4: configuration ----
    "cfg-tls-weak-cipher": ("nginx.conf", "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"),
    "cfg-tls-classical-kex": ("nginx.conf", "ssl_ecdh_curve prime256v1;\n"),
    "cfg-tls-old-protocol": ("nginx.conf", "ssl_protocols TLSv1.1 TLSv1.2;\n"),
    "cfg-ssh-weak-kex": ("sshd_config", "KexAlgorithms diffie-hellman-group14-sha1\n"),
    "cfg-ssh-weak-cipher": ("sshd_config", "Ciphers aes128-ctr,3des-cbc\n"),
    "cfg-ssh-weak-mac": ("sshd_config", "MACs hmac-sha1\n"),
    "cfg-ssh-rsa-hostkey": ("sshd_config", "HostKeyAlgorithms ssh-rsa\n"),
    "cfg-java-weak-allowed": ("java.security", "jdk.tls.disabledAlgorithms=SSLv3, RC4\n"),
    "cfg-java-jks-keystore": ("java.security", "keystore.type=jks\n"),
    "cfg-openssl-fips-off": ("openssl.cnf", "default = default_sect\n"),

    # ---- Layer 4: infrastructure-as-code (SP 800-57) ----
    "iac-kms-rotation-disabled": ("main.tf", "enable_key_rotation = false\n"),
    "iac-kms-rotation-absent": ("main.tf", 'resource "aws_kms_key" "a" {}\n'),
    "iac-key-spec-classical": ("main.tf", 'customer_master_key_spec = "RSA_2048"\n'),
    "iac-tls-policy-weak": ("main.tf", 'ssl_policy = "ELBSecurityPolicy-2016-08"\n'),
    "iac-secret-in-plaintext": ("main.tf", 'password = "correcthorsebattery"\n'),
    "iac-k8s-secret-plaintext": ("secret.yaml", "kind: Secret\n"),

    # ---- unaudited implementations (SC-12 / IA-7) ----
    "py-unaudited-pqc-impl": ("a.py", "from dilithium_py.ml_dsa import ML_DSA_87\n"),
}

# Sources that must produce ZERO findings. Each one encodes a precision decision.
NEGATIVE = [
    ("tmpname.py", "import random\n"
                   "def _atomic_open(filename):\n"
                   "    return '.tmp%08x' % random.randrange(1 << 32)\n"),
    ("shuffle.go", "func shuffleResults(rows []Row) { rand.Shuffle(len(rows), swap) }\n"),
    ("getter.java", "SecureRandom r = ensureSecureRandom(request);\n"),
    ("plain.tf", 'resource "aws_s3_bucket" "b" { bucket = "logs" }\n'),
    ("plain.conf", "worker_processes auto;\n"),
    ("notes.txt", "MACs hmac-sha1 and ssl_ciphers AES128 are bad, see ticket SEC-9\n"),
]

SC12_RULES = [r for r in all_rules()
              if r.classification in KEY_CLASSES
              or r.id.startswith(("cfg-", "iac-", "py-keygen", "py-hardcoded",
                                  "go-keygen", "java-keygen"))]


def scan_source(tmp_path, filename, source, profile=CNSA):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    return scan_tree(str(tmp_path), profile)


# --------------------------------------------------------------------------
def test_every_sc12_rule_has_a_positive_fixture():
    missing = {r.id for r in SC12_RULES} - set(POSITIVE)
    assert not missing, "SC-12 rules with no fixture: " + str(sorted(missing))


@pytest.mark.parametrize("rule_id", sorted(POSITIVE))
def test_rule_fires(tmp_path, rule_id):
    filename, source = POSITIVE[rule_id]
    findings = scan_source(tmp_path, filename, source)
    assert rule_id in {f["rule"] for f in findings}, sorted(f["rule"] for f in findings)


@pytest.mark.parametrize("filename,source", NEGATIVE, ids=[n for n, _ in NEGATIVE])
def test_no_false_positives(tmp_path, filename, source):
    findings = scan_source(tmp_path, filename, source)
    assert findings == [], [(f["rule"], f["evidence"]) for f in findings]


# --------------------------------------------------------------------------
# Precision: the key-context gate
# --------------------------------------------------------------------------
def test_key_context_matches_tokens_not_substrings():
    """'iv' must not fire on 'private'; 'mac' must not fire on 'machine'."""
    assert is_key_context("session_key")
    assert is_key_context("deriveIV")
    assert is_key_context("wrap_key")
    assert not is_key_context("private")
    assert not is_key_context("machine")
    assert not is_key_context("_atomic_open")
    assert not is_key_context("rsa_recover_prime_factors")


def test_rng_only_fires_in_key_context(tmp_path):
    source = (
        "import random\n"
        "def temp_name():\n"
        "    return random.randrange(1 << 32)\n"
        "def session_key():\n"
        "    return random.randint(0, 255)\n"
    )
    findings = scan_source(tmp_path, "a.py", source)
    hits = [f for f in findings if f["rule"] == "py-keygen-weak-rbg"]
    assert [f["line"] for f in hits] == [5], "only the key-shaped function should fire"


def test_rng_fires_on_key_shaped_assignment_target(tmp_path):
    findings = scan_source(tmp_path, "a.py", "import random\nnonce = random.getrandbits(96)\n")
    assert {f["rule"] for f in findings} == {"py-keygen-weak-rbg"}


# --------------------------------------------------------------------------
# Correctness: block comments must not move line numbers
# --------------------------------------------------------------------------
def test_block_comments_do_not_shift_line_numbers(tmp_path):
    source = (
        "/*\n"
        " * Copyright someone\n"
        " * Licensed under something\n"
        " */\n"
        "package main\n"
        'import "crypto/md5"\n'
        "func D(b []byte) []byte { h := md5.New(); return h.Sum(b) }\n"
    )
    findings = scan_source(tmp_path, "a.go", source)
    hits = [f for f in findings if f["rule"] == "go-md5"]
    assert len(hits) == 1
    assert hits[0]["line"] == 7, "a licence header must not move the finding"


def test_block_comment_contents_are_still_ignored(tmp_path):
    source = "/*\n * rsa.GenerateKey(rand.Reader, 2048)\n */\npackage main\n"
    assert scan_source(tmp_path, "a.go", source) == []


# --------------------------------------------------------------------------
# The control axis
# --------------------------------------------------------------------------
def test_findings_carry_controls_and_standards(tmp_path):
    findings = scan_source(tmp_path, "a.py", "ct = pub.encrypt(k, padding.PKCS1v15())\n")
    f = next(x for x in findings if x["rule"] == "py-rsa-pkcs1v15-encrypt")
    assert "SC-12" in f["controls"]
    assert "SP 800-56B" in f["standards"]
    assert f["remediation"], "SC-12 findings must say what to do instead"


def test_every_sc12_rule_declares_a_control():
    for rule in SC12_RULES:
        assert rule.controls, rule.id + " has no control mapping"


def test_config_layer_matches_by_filename(tmp_path):
    (tmp_path / "sshd_config").write_text("MACs hmac-sha1\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("MACs hmac-sha1\n", encoding="utf-8")
    hits = scan_tree(str(tmp_path), CNSA)
    assert len(hits) == 1 and hits[0]["file"].endswith("sshd_config")


# --------------------------------------------------------------------------
# Layer 5: cryptographic module validation
# --------------------------------------------------------------------------
def test_module_validation_flags_non_fips_distribution(tmp_path):
    findings = scan_source(
        tmp_path, "pom.xml",
        "<dependency><artifactId>bcprov-jdk18on</artifactId></dependency>\n")
    hits = [f for f in findings if f["classification"] == "module-not-validated"]
    assert len(hits) == 1
    assert "BC-FJA" in hits[0]["message"] or "bc-fips" in hits[0]["message"]
    assert "IA-7" in hits[0]["controls"]


def test_validated_module_without_cmvp_import_says_unverified(tmp_path):
    """Never assert a certificate is current when no export has been loaded."""
    findings = scan_source(
        tmp_path, "pom.xml",
        "<dependency><artifactId>bc-fips</artifactId></dependency>\n")
    hits = [f for f in findings if f["classification"] == "module-not-validated"]
    assert hits and "unverified" in hits[0]["message"]


def test_historical_certificate_is_reported(tmp_path):
    from pqgate.rules import load_cmvp
    cmvp = load_cmvp()
    cmvp["bc-fips"].update({"cert": "9999", "status": "historical", "sunset": "2026-09-21"})
    (tmp_path / "pom.xml").write_text(
        "<dependency><artifactId>bc-fips</artifactId></dependency>\n", encoding="utf-8")
    findings = scan_tree(str(tmp_path), CNSA, cmvp=cmvp)
    hits = [f for f in findings if f["classification"] == "module-cert-historical"]
    assert len(hits) == 1
    assert "9999" in hits[0]["message"] and "2026-09-21" in hits[0]["message"]


def test_fips_profile_blocks_unvalidated_modules(tmp_path):
    from pqgate.policy import apply_policy, load_policy
    (tmp_path / "pom.xml").write_text(
        "<dependency><artifactId>bcprov-jdk18on</artifactId></dependency>\n", encoding="utf-8")

    findings = scan_tree(str(tmp_path), CNSA)
    kept, _ = apply_policy(findings, load_policy(None))
    module = next(f for f in kept if f["classification"] == "module-not-validated")
    assert module["action"] == "warn", "cnsa-2.0 treats validation as advisory"

    findings = scan_tree(str(tmp_path), FIPS)
    kept, _ = apply_policy(findings, load_policy(None, profile_override="fips-140-3"))
    module = next(f for f in kept if f["classification"] == "module-not-validated")
    assert module["action"] == "block", "fips-140-3 blocks it"


def test_fips_and_cnsa_profiles_are_orthogonal(tmp_path):
    """A validated module can still use quantum-vulnerable algorithms, and vice versa."""
    from pqgate.policy import apply_policy, load_policy
    (tmp_path / "a.py").write_text(
        "k = rsa.generate_private_key(65537, 3072)\n", encoding="utf-8")
    findings = scan_tree(str(tmp_path), FIPS)
    kept, _ = apply_policy(findings, load_policy(None, profile_override="fips-140-3"))
    assert kept[0]["action"] == "warn", "FIPS validation says nothing about quantum resistance"
