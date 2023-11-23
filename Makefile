test:
	python -m pytest tests/ -s

lint:
	python -m pylint lightphe/ --fail-under=10