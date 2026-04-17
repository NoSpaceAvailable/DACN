.PHONY: install test run benchmark

install:
	pip install -e .

test:
	PYTHONPATH=src pytest -q

run:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli run --fixture data/fixtures/challenge_idor_01 --profile-set mixed_default

benchmark:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli benchmark --out outputs/benchmark_results.json
