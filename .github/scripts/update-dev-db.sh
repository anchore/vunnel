#!/usr/bin/env bash
set -euo pipefail

BIN_DIR=./.tool
GRYPE=${BIN_DIR}/grype
GRYPE_DB=${BIN_DIR}/grype-db

BOLD="\033[1m"
RED="\033[31m"
MAGENTA="\033[35m"
RESET="\033[0m"

function step() {
  echo -e "${MAGENTA}• $*${RESET} ..."
}

function title() {
  echo -e "${BOLD}$*${RESET}"
}

function error() {
  echo -e "${RED}$*${RESET}"
}

step "Updating vunnel providers"
${GRYPE_DB} pull -v

rm -rf build

step "Building grype-db"
${GRYPE_DB} build -vvv

step "Packaging grype-db"
${GRYPE_DB} package
GRYPE_DB_TAR=build/grype-db.tar.zst
mv build/vulnerability-db_*.tar.zst ${GRYPE_DB_TAR}

step "Importing DB into grype"
${GRYPE} db import ${GRYPE_DB_TAR}
