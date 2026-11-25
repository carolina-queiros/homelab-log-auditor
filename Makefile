.PHONY: test lint run-web demo clean

test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall auditor.py engine scripts tests

run-web:
	python3 auditor.py --config config.json --web

demo:
	mkdir -p /tmp/sim_logs && touch /tmp/sim_logs/auth.log /tmp/sim_logs/access.log
	python3 scripts/simulate_attacks.py --auth-log /tmp/sim_logs/auth.log --access-log /tmp/sim_logs/access.log --delay 0.05

clean:
	rm -rf /tmp/sim_logs auditor_state.db
