# formatting support
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

.PHONY: all
all: static-analysis test ## Run all validations

.PHONY: test
test: unit ## Run all tests

.PHONY: static-analysis
static-analysis: ## Run all static analyses
	poetry install && poetry run pre-commit run -a --hook-stage push

.PHONY: unit
unit: ## Run unit tests
	poetry install && poetry run tox

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
