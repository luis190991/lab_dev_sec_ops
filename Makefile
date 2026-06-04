.PHONY: setup db run sast dast all clean

setup:
	pip install -r app/backend/requirements.txt -r requirements-dev.txt

db:
	python app/backend/init_db.py

run: db
	python app/backend/app.py

sast:
	bash scripts/run_sast.sh

dast:
	python scripts/run_dast.py --url http://localhost:5000

# Run SAST first, then start the API and run DAST
all: sast
	@echo "\n>>> Starting API in background..."
	python app/backend/app.py &
	@sleep 2
	$(MAKE) dast

clean:
	rm -rf reports/ app/backend/lab.db __pycache__ app/backend/__pycache__
