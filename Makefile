# PQgate — Phase 1
PY ?= python

.PHONY: help install test corpus-fetch corpus-snapshot corpus-test web serve
.PHONY: seed seed-small linkcheck sitemap demo clean release release-unsigned packs

help:
	@echo "make install         install python + node dependencies"
	@echo "make test            fast test suite (offline)"
	@echo "make corpus-fetch    clone the pinned OSS corpus into testdata/"
	@echo "make corpus-test     regression + false-positive gate on the corpus"
	@echo "make web             build the frontend bundle into web/dist"
	@echo "make serve           run the evidence server on 127.0.0.1:8000"
	@echo "make seed            push demo scans into a running server"
	@echo "make linkcheck       verify every route and internal link resolves"
	@echo "make sitemap         regenerate sitemap.xml and robots.txt"
	@echo "make release         build signed release artifacts into dist/"
	@echo "make release-unsigned build release artifacts with no signing key"
	@echo "make packs           show installed rule packs and their age"
	@echo "make demo            build web, seed, and serve"

install:
	$(PY) -m pip install -r requirements.txt
	cd web && npm install --no-audit --no-fund

test:
	$(PY) -m pytest tests -q

corpus-fetch:
	$(PY) scripts/corpus.py fetch

corpus-snapshot:
	$(PY) scripts/corpus.py snapshot

corpus-test:
	$(PY) scripts/corpus.py check

web:
	cd web && npm run build

serve:
	$(PY) serve.py

seed:
	$(PY) scripts/seed.py --sign

seed-small:
	$(PY) server/seed_demo.py

linkcheck:
	$(PY) scripts/linkcheck.py check

sitemap:
	$(PY) scripts/linkcheck.py sitemap

demo: web
	@echo "start the server with 'make serve' in another shell, then 'make seed'"

release:
	$(PY) scripts/release.py

release-unsigned:
	$(PY) scripts/release.py --unsigned

packs:
	$(PY) -m pqgate packs

clean:
	rm -rf web/dist dist pqgate.db .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
