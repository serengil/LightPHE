test:
	python -m pytest tests/ -s

lint:
	python -m pylint lightphe.py src/ --fail-under=10