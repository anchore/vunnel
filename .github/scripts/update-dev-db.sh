set -euo pipefail

BIN_DIR=./bin
GRYPE=${BIN_DIR}/grype
GRYPE_DB=${BIN_DIR}/grype-db

BOLD="\033[1m"
RED="\033[31m"
MAGENTA="\033[35m"
RESET="\033[0m"

function step() {
  echo "${MAGENTA}• $*${RESET} ..."
}

function title() {
  echo "${BOLD}$*${RESET}"
}

function error() {
  echo "${RED}$*${RESET}"
}

step "Updating vunnel providers"
${GRYPE_DB} pull -v

rm -rf build

step "Building grype-db"
${GRYPE_DB} build

step "Packaging grype-db"
${GRYPE_DB} package
GRYPE_DB_TAR=build/grype-db.tar.gz
mv build/vulnerability-db_*.tar.gz ${GRYPE_DB_TAR}

step "Importing DB into grype"
${GRYPE} db import ${GRYPE_DB_TAR}
