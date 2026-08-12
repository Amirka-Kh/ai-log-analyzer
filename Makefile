.PHONY: test lint fmt demo-cli install

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check ai_ops_agent tests
	mypy ai_ops_agent

fmt:
	ruff check --fix ai_ops_agent tests

demo-cli:
	@echo "=== clean log ==="
	-ai-ops analyze --source tests/fixtures/logs/clean.log --no-llm
	@echo
	@echo "=== incident log (json lines, OOM + pool exhaustion) ==="
	-ai-ops analyze --source tests/fixtures/logs/json_lines.log --no-llm
	@echo
	@echo "=== nginx access log (scanning + sqli) ==="
	-ai-ops analyze --source tests/fixtures/logs/nginx_access.log --no-llm --verbose
