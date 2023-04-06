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

ifeq ($(USE_VENV),1)
	EXEC_CMD :=
else
	EXEC_CMD := docker exec -ti inclusion_connect_django
endif

.PHONY: run venv clean cdsitepackages quality fix pylint compile-deps

# Run Docker images
run:
	docker compose up

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

cdsitepackages:
	docker exec -ti -w /usr/local/lib/$(PYTHON_VERSION)/site-packages inclusion_connect_django /bin/bash

quality: $(VIRTUAL_ENV)
	black --check inclusion_connect
	isort --check inclusion_connect
	flake8 --count --show-source --statistics inclusion_connect
	djlint --lint --check inclusion_connect

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
	$(EXEC_CMD) django-admin $(COMMAND)

populate_db:
	$(EXEC_CMD) bash -c "ls -d inclusion_connect/fixtures/django/* | xargs ./manage.py loaddata"

# Tests.
# =============================================================================

.PHONY: coverage test

test: $(VIRTUAL_ENV)
	$(EXEC_CMD) pytest --numprocesses=logical --create-db $(TARGET)

coverage:
	$(EXEC_CMD) coverage run -m pytest

# Docker shell.
# =============================================================================

.PHONY: shell_on_django_container shell_on_django_container_as_root shell_on_postgres_container

shell_on_django_container:
	docker exec -ti inclusion_connect /bin/bash

shell_on_django_container_as_root:
	docker exec -ti --user root inclusion_connect /bin/bash

shell_on_postgres_container:
	docker exec -ti inclusion_connect_postgres /bin/bash

# Postgres CLI.
# =============================================================================

.PHONY: psql_inclusion_connect psql_root psql_to_csv

# Connect to the `inclusion_connect` database as the `inclusion_connect` user.
psql:
	docker exec -ti -e PGPASSWORD=password inclusion_connect_postgres psql -U inclusion_connect -d inclusion_connect

# Postgres (backup / restore).
# Inspired by:
# https://cookiecutter-django.readthedocs.io/en/latest/docker-postgres-backups.html
# =============================================================================

.PHONY: postgres_backup postgres_backups_cp_locally postgres_backups_list postgres_backup_restore postgres_restore_latest_backup postgres_backups_clean postgres_dump_cities

postgres_backup:
	docker compose exec postgres backup

postgres_backups_cp_locally:
	docker cp itou_postgres:/backups ~/Desktop/backups

postgres_backups_list:
	docker compose exec postgres backups

# Deployment
# =============================================================================

.PHONY: deploy_prod
deploy_prod:
	./scripts/deploy_prod.sh
