GRYPE_DB_DATA_DIR = data
GRYPE_DB_BUILD_DIR = build
BIN_DIR = bin
YARDSTICK_RESULT_DIR = .yardstick/result
YARDSTICK_LABELS_DIR = .yardstick/labels
TEST_DB_ARCHIVE = $(GRYPE_DB_BUILD_DIR)/grype-db.tar.zst

SBOM_STORE_TAG = md5-$(shell md5sum .yardstick.yaml | cut -d' ' -f1)
SBOM_STORE_IMAGE = ghcr.io/anchore/grype/quality-test-sbom-store:$(SBOM_STORE_TAG)
RESULT_SET = pr_vs_latest_via_sbom


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
validate:  ## Run all quality checks against already collected data
	uv run yardstick validate --result-set $(RESULT_SET)_$(provider)


## Data management targets #################################

.PHONY: capture
capture: clear-data clear-results configure sboms build-db vulns ## Collect and store all syft and grype results relative to the given provider

.PHONY: show-changes
show-changes: ## Show the current file changeset
	uv run python ./configure.py -v show-changes
	uv run python ./configure.py select-providers

.PHONY: all-providers
all-providers: ## Select all providers for testing
	@uv run python ./configure.py all-providers --json 2>/dev/null

.PHONY: select-providers
select-providers: ## Determine the provider(s) to use for testing based on the file changeset
	@uv run python ./configure.py select-providers --json 2>/dev/null

.PHONY: validate-test-tool-versions
validate-test-tool-versions: ## Pass/Fail to determine if we're using the production versions of grype and grype-db
	@uv run python ./configure.py validate-test-tool-versions

.PHONY: configure
configure: ## write yardstick and grype configuration files relative to the given provider
	uv run python ./configure.py configure $(provider)

.PHONY: build-db
build-db:  ## Build a grype database for the given provider
	uv run python ./configure.py build-db

.PHONY: vulns
vulns: ## Collect and store all grype results
	uv run yardstick -v result capture -r $(RESULT_SET)_$(provider)

.PHONY: sboms
sboms: $(YARDSTICK_RESULT_DIR) clear-results ## Collect and store all syft results (deletes all existing results)
	bash -c "make download-sboms || (uv run yardstick -v result capture -r $(RESULT_SET)_$(provider) --only-producers)"

.PHONY: download-sboms
download-sboms:
	cd vulnerability-match-labels && make venv
	bash -c "export ORAS_CACHE=$(shell pwd)/.oras-cache && . vulnerability-match-labels/venv/bin/activate && ./vulnerability-match-labels/sboms.py download -r $(RESULT_SET)_$(provider)"

$(YARDSTICK_RESULT_DIR):
	mkdir -p $(YARDSTICK_RESULT_DIR)

.PHONY: update-labels
update-labels:  ## Update vulnerability-match-labels submodule to grab the latest labels on the main branch
	git submodule update --remote vulnerability-match-labels


## Cleanup targets #################################

.PHONY: clean
clean: clear-bin clear-results clear-db clear-data ## Clear all local data
	find -iname "*.pyc" -delete

.PHONY: clear-results
clear-results: ## Clear all existing yardstick results
	uv run yardstick result clear

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
