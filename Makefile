.PHONY: setup run test docker
setup:
	python3 -m pip install -r requirements.txt
run:
	python3 -m cryptoguard.app
test:
	python3 -m pytest -q
docker:
	docker compose up --build -d
