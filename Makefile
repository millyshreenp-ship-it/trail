.PHONY: install test run sandbox walkthrough docker evaluate evaluate-v1 evaluate-smoke research-smoke compile
PYTHON ?= .venv/Scripts/python.exe
BACKEND_PYTHON ?= ../.venv/Scripts/python.exe

install: ; $(PYTHON) -m pip install -r requirements.txt
test:    ; cd backend && $(BACKEND_PYTHON) -m pytest -q
run:     ; $(PYTHON) -m uvicorn app.main:app --app-dir backend --reload
sandbox: ; PYTHONPATH=backend $(PYTHON) scripts/seed_sandbox.py
walkthrough: ; PYTHONPATH=backend $(PYTHON) scripts/walkthrough.py
docker:  ; docker compose up --build
evaluate-v1: ; cd backend && $(BACKEND_PYTHON) -m app.evaluation.run_synthetic --mode v1 --seed 7 --days 24
evaluate: ; cd backend && $(BACKEND_PYTHON) -m app.evaluation.run_synthetic --mode sim2 --seeds 7,11,23,47,89 --story-count 3000 --calendar-days 180 --institutions BANK_A,BANK_B,BANK_C --held-out-morphology split_value
evaluate-smoke: ; cd backend && $(BACKEND_PYTHON) -m app.evaluation.run_synthetic --mode sim2 --seed 7 --story-count 20 --calendar-days 45 --held-out-morphology split_value
research-smoke: ; $(PYTHON) research/kaggle/smoke.py
compile: ; $(PYTHON) -m compileall -q backend
