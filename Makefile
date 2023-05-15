# Delete target on error.
# https://www.gnu.org/software/make/manual/html_node/Errors.html#Errors
# > This is almost always what you want make to do, but it is not historical
# > practice; so for compatibility, you must explicitly request it
.DELETE_ON_ERROR:

# Global tasks.
# =============================================================================
PYTHON_VERSION := python3.11
PGDATABASE ?= inclusion_connect
ifeq ($(shell uname -s),Linux)
	REQUIREMENTS_PATH := requirements/dev.txt
else
	REQUIREMENTS_PATH := requirements/dev.in
endif

VIRTUAL_ENV ?= .venv
export PATH := $(VIRTUAL_ENV)/bin:$(PATH)

.PHONY: run venv clean quality fix pylint compile-deps

# Run Docker images
run:
	docker compose up

runserver: $(VIRTUAL_ENV)
	$(VIRTUAL_ENV)/bin/python manage.py runserver

$(VIRTUAL_ENV): $(REQUIREMENTS_PATH)
	$(PYTHON_VERSION) -m venv $@
	$@/bin/pip install -r $^
ifeq ($(shell uname -s),Linux)
	$@/bin/pip-sync $^
endif
	touch $@

venv: $(VIRTUAL_ENV)

PIP_COMPILE_FLAGS := --upgrade --allow-unsafe --generate-hashes
compile-deps: $(VIRTUAL_ENV)
	pip-compile $(PIP_COMPILE_FLAGS) -o requirements/base.txt requirements/base.in
	pip-compile $(PIP_COMPILE_FLAGS) -o requirements/dev.txt requirements/dev.in

clean:
	find . -type d -name "__pycache__" -depth -exec rm -rf '{}' \;

quality: $(VIRTUAL_ENV)
	black --check inclusion_connect
	isort --check inclusion_connect
	flake8 --count --show-source --statistics inclusion_connect
	djlint --lint --check inclusion_connect
	django-admin makemigrations --check --dry-run --noinput

fix: $(VIRTUAL_ENV)
	black inclusion_connect
	isort inclusion_connect
	djlint --reformat inclusion_connect

pylint: $(VIRTUAL_ENV)
	pylint inclusion_connect

# Django.
# =============================================================================

.PHONY: django_admin populate_db

# make django_admin
# make django_admin COMMAND=dbshell
# make django_admin COMMAND=createsuperuser
django_admin:
	django-admin $(COMMAND)

populate_db:
	bash -c "ls -d inclusion_connect/fixtures/django/* | xargs ./manage.py loaddata"

# Tests.
# =============================================================================

.PHONY: coverage test

test: $(VIRTUAL_ENV)
	pytest --numprocesses=logical --create-db $(TARGET)

coverage: $(VIRTUAL_ENV)
	coverage run -m pytest

# Docker shell.
# =============================================================================

.PHONY: shell_on_postgres_container

shell_on_postgres_container:
	docker exec -ti inclusion_connect_postgres /bin/bash

# Deployment
# =============================================================================

.PHONY: deploy_prod
deploy_prod:
	./scripts/deploy_prod.sh
