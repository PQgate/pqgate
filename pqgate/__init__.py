"""PQgate — CNSA 2.0 crypto-compliance gate.

Reference implementation. The Go port (release 0.1) must match this behavior
byte-for-byte on CBOM/SARIF output and exit codes.
"""
VERSION = "0.5.0"
EXIT_PASS, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2
