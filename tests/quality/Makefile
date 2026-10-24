GRYPE_DB_DATA_DIR = data
GRYPE_DB_BUILD_DIR = build
BIN_DIR = bin
TEST_DB_ARCHIVE = $(GRYPE_DB_BUILD_DIR)/grype-db.tar.zst

# override to use a locally built yardstick, e.g. make validate YARDSTICK=~/code/yardstick/bin/yardstick
YARDSTICK ?= .tool/yardstick
GATE = gates/$(provider).yaml


# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)


.PHONY: all
all: capture validate ## Fetch or capture all data and run all quality checks

.PHONY: validate
validate: tools  ## Score the collected scans for the given provider against the labels (exit 1 when the gate fails)
	$(YARDSTICK) score $(GATE)


## Data management targets #################################

.PHONY: tools
tools: ## Install yardstick and grype main from this directory's .binny.yaml (a no-op when they're current)
	$(MAKE) -C ../.. tools
	../../.tool/binny install -c .binny.yaml

.PHONY: capture
capture: clear-data clear-results configure build-db scans ## Build a DB for the given provider and scan its images with it and the reference DB

.PHONY: show-changes
show-changes: ## Show the current file changeset
	uv run python ./configure.py -v show-changes
	uv run python ./configure.py select-providers

.PHONY: all-providers
all-providers: ## Select all providers for testing
	@uv run python ./configure.py all-providers --json $(if $(TAG),-t $(TAG)) 2>/dev/null

.PHONY: select-providers
select-providers: ## Determine the provider(s) to use for testing based on the file changeset
	@uv run python ./configure.py select-providers --json $(if $(TAG),-t $(TAG)) 2>/dev/null

.PHONY: validate-test-tool-versions
validate-test-tool-versions: ## Pass/Fail to determine if we're using the production versions of grype and grype-db
	@uv run python ./configure.py validate-test-tool-versions

.PHONY: configure
configure: tools ## write yardstick and grype configuration files relative to the given provider
	uv run python ./configure.py configure $(provider)

.PHONY: build-db
build-db:  ## Build a grype database for the given provider
	uv run python ./configure.py build-db

.PHONY: scans
scans: tools ## Get SBOMs for the given provider's images and scan them with both setups
	$(YARDSTICK) collect scans $(GATE)


## Cleanup targets #################################

.PHONY: clean
clean: clear-bin clear-results clear-db clear-data ## Clear all local data
	find -iname "*.pyc" -delete

.PHONY: clear-results
clear-results: ## Clear all yardstick scans and generated gates
	rm -rf .yardstick gates

.PHONY: clear-data
clear-data: ## Delete existing vunnel data cache
	rm -rf $(GRYPE_DB_DATA_DIR)

.PHONY: clear-bin
clear-bin: ## Delete local bin directory
	rm -rf $(BIN_DIR)

.PHONY: clear-db
clear-db: ## Delete existing test grype-db
	rm -f $(TEST_DB_ARCHIVE)
	rm -rf $(GRYPE_DB_BUILD_DIR)


## Halp! #################################

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
