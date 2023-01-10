TEMP_DIR = ./.tmp
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

# this is the python package version for vunnel, based off of the git state
# note: this should always have a prefixed "v"
PACKAGE_VERSION = v$(shell poetry run dunamai from git --style semver --dirty --no-metadata)
COMMIT = $(shell git rev-parse HEAD)
COMMIT_TAG = git-$(COMMIT)

CHRONICLE_VERSION = v0.4.2
GLOW_VERSION = v1.4.1
CRANE_VERSION = v0.12.1


ifndef PACKAGE_VERSION
	$(error PACKAGE_VERSION is not set)
endif


$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

.PHONY: bootstrap
bootstrap: $(TEMP_DIR)  ## Download and install all tooling dependencies
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)
	GOBIN="$(abspath $(TEMP_DIR))" go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)

.PHONY: all
all: static-analysis test  ## Run all validations

.PHONY: test
test: unit  ## Run all tests

.PHONY: static-analysis
static-analysis:  ## Run all static analyses
	poetry run pre-commit run -a --hook-stage push

.PHONY: unit
unit:  ## Run unit tests
	poetry run pytest --cov vunnel -v tests/unit/

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
ci-publish-commit: ci-check  ## Publish a commit (for use in CI only)
	docker push $(IMAGE_NAME):$(COMMIT_TAG)

.PHONY: ci-promote-release
ci-promote-release: ci-check  ## Promote an existing commit build as a release (for use in CI only)
	$(CRANE) tag $(IMAGE_NAME):$(COMMIT_TAG) $(PACKAGE_VERSION)
	$(CRANE) tag $(IMAGE_NAME):$(COMMIT_TAG) latest

.PHONY: changelog
changelog:
	@$(CHRONICLE) -n . > CHANGELOG.md
	@$(GLOW) CHANGELOG.md

.PHONY: trigger-release
trigger-release:
	@.github/scripts/trigger-release.sh

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
