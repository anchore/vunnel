TEMP_DIR = ./.tmp
BIN_DIR = ./bin
ABS_BIN_DIR = $(shell realpath $(BIN_DIR))

# path to the grype repo, defaults to ../grype if not set in the GRYPE_PATH environment variable (same for the grype-db repo)
GRYPE_PATH ?= ../grype
GRYPE_DB_PATH ?= ../grype-db

CRANE = $(TEMP_DIR)/crane
CHRONICLE = $(TEMP_DIR)/chronicle
GLOW = $(TEMP_DIR)/glow
IMAGE_NAME = ghcr.io/anchore/vunnel

# formatting support
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
ERROR := $(BOLD)$(RED)

# this is the python package version for vunnel, based off of the git state
# note: this should always have a prefixed "v"
PACKAGE_VERSION = v$(shell poetry run dunamai from git --style semver --dirty --no-metadata)
COMMIT = $(shell git rev-parse HEAD)
COMMIT_TAG = git-$(COMMIT)

CHRONICLE_VERSION = v0.6.0
GLOW_VERSION = v1.4.1
CRANE_VERSION = v0.12.1


ifndef PACKAGE_VERSION
	$(error PACKAGE_VERSION is not set)
endif

.DEFAULT_GOAL := all

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: dev
dev:  ## Get a development shell with locally editable grype, grype-db, and vunnel repos
	@DEV_VUNNEL_BIN_DIR=$(ABS_BIN_DIR) .github/scripts/dev-shell.sh $(provider) $(providers)

.PHONY: build-grype
build-grype: $(TEMP_DIR) ## Build grype for local development
	@cd $(GRYPE_PATH) && go build -o $(ABS_BIN_DIR)/grype .

.PHONY: build-grype-db
build-grype-db: $(TEMP_DIR) ## Build grype-db for local development
	@cd $(GRYPE_DB_PATH) && go build -o $(ABS_BIN_DIR)/grype-db ./cmd/grype-db

.PHONY: update-db
update-db: check-dev-shell ## Build and import a grype database based off of the current configuration
	@.github/scripts/update-dev-db.sh

.PHONY: check-dev-shell
check-dev-shell:
	@test -n "$$DEV_VUNNEL_SHELL" || (echo "$(RED)DEV_VUNNEL_SHELL is not set. Run 'make dev provider=\"...\"' first$(RESET)" && exit 1)

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: bootstrap
bootstrap: $(TEMP_DIR)  ## Download and install all tooling dependencies
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)

.PHONY: test
test: unit  ## Run all tests

.PHONY: static-analysis
static-analysis: virtual-env-check  ## Run all static analyses
	pre-commit run -a --hook-stage push

.PHONY: lint-fix
lint-fix: virtual-env-check  ## Fix linting issues (ruff)
	ruff check . --fix

.PHONY: format
format: virtual-env-check  ## Format all code (black)
	black src tests

.PHONY: check-types
check-types: virtual-env-check  ## Run type checks (mypy)
	mypy --config-file ./pyproject.toml src/vunnel

.PHONY: unit
unit: virtual-env-check  ## Run unit tests
	pytest --cov-report html --cov vunnel -v tests/unit/

.PHONY: version
version:
	@echo $(PACKAGE_VERSION)

.PHONY: build
build:  ## Run build assets
	git fetch --tags
	rm -rf dist
	poetry build
	docker build \
		-t $(IMAGE_NAME):$(COMMIT_TAG) \
		.

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

.PHONY: ci-publish-commit
ci-publish-commit: ci-check
	docker push $(IMAGE_NAME):$(COMMIT_TAG)

.PHONY: ci-promote-release
ci-promote-release: ci-check
	$(CRANE) tag $(IMAGE_NAME):$(COMMIT_TAG) $(PACKAGE_VERSION)
	$(CRANE) tag $(IMAGE_NAME):$(COMMIT_TAG) latest

.PHONY: changelog
changelog:
	@$(CHRONICLE) -vvv -n . > CHANGELOG.md
	@$(GLOW) CHANGELOG.md

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

virtual-env-check:
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		echo "$(ERROR)Not in a virtual environment. Try running with 'poetry run' or enter a 'poetry shell' session.$(RESET)"; \
		exit 1; \
	fi

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
