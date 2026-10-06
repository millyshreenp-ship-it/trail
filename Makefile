.PHONY: install test run sandbox walkthrough docker evaluate
install: ; pip install -r requirements.txt
test:    ; cd backend && python -m pytest -q
run:     ; uvicorn app.main:app --app-dir backend --reload
sandbox: ; PYTHONPATH=backend python scripts/seed_sandbox.py
walkthrough: ; PYTHONPATH=backend python scripts/walkthrough.py
docker:  ; docker compose up --build
evaluate: ; PYTHONPATH=backend python scripts/run_evaluation.py
