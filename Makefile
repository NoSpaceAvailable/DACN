.PHONY: install test run run-ollama llm-test benchmark

install:
	pip install -e .
	pip install -r requirements.txt

test:
	PYTHONPATH=src pytest -q

run:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli run --fixture data/fixtures/challenge_idor_01 --profile-set mixed_default --llm rule

run-ollama:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli run --fixture data/fixtures/challenge_idor_01 --profile-set mixed_default --llm ollama:gemma4:e2b

llm-test:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli llm-test --llm ollama:gemma4:e2b

benchmark:
	PYTHONPATH=src python -m vapt_orchestrator_safe.cli benchmark --out outputs/benchmark_results.json --llm rule
