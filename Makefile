# Public Makefile. Only targets whose files actually ship in this repository —
# the private one carries the server, the web app and the seed data, and a target
# that fails in a fresh clone is worse than a target that isn't there.
PY ?= python

.PHONY: help install test corpus-fetch corpus-snapshot corpus-test packs
.PHONY: release release-unsigned clean

help:
	@echo "make install          install python dependencies"
	@echo "make test             run the test suite"
	@echo "make corpus-fetch     clone the pinned OSS corpus into testdata/"
	@echo "make corpus-snapshot  re-record corpus snapshots (review the diff)"
	@echo "make corpus-test      regression + false-positive gate"
	@echo "make packs            show installed rule packs and their age"
	@echo "make release          build signed release artifacts into dist/"
	@echo "make release-unsigned build release artifacts with no signing key"

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest tests -q

corpus-fetch:
	$(PY) scripts/corpus.py fetch

corpus-snapshot:
	$(PY) scripts/corpus.py snapshot

corpus-test:
	$(PY) scripts/corpus.py check

packs:
	$(PY) -m pqgate packs

release:
	$(PY) scripts/release.py

release-unsigned:
	$(PY) scripts/release.py --unsigned

clean:
	rm -rf dist .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
