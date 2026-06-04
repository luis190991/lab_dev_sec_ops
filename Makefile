.PHONY: setup db run frontend sast dast all clean

setup:
	bash .devcontainer/setup.sh

db:
	python app/backend/init_db.py

# Frontend is served by Flask at http://localhost:5000
run: db
	python app/backend/app.py

sast:
	bash scripts/run_sast.sh

dast:
	python scripts/run_dast.py --url http://localhost:5000

# SAST then DAST (starts API automatically)
all: sast db
	@echo ">>> Starting API in background..."
	@python app/backend/app.py & echo $$! > /tmp/lab_api.pid
	@sleep 2
	$(MAKE) dast
	@kill $$(cat /tmp/lab_api.pid) 2>/dev/null || true

clean:
	rm -rf reports/ app/backend/lab.db __pycache__ app/backend/__pycache__
