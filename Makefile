.PHONY: test lint run-web

test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall auditor.py engine tests

run-web:
	python3 auditor.py --config config.json --web
