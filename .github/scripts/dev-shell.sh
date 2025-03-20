#!/usr/bin/env bash
set -euo pipefail

DEV_VUNNEL_PROVIDERS=$@
GRYPE_CONFIG=$(pwd)/.grype.yaml
GRYPE_DB_CONFIG=$(pwd)/.grype-db.yaml
DEV_PYTHON_ENV_PATH=$(pwd)/.venv

BOLD="\033[1m"
UNDERLINE="\033[4m"
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

if [ -z  "$*" ]
then
    error "At least one provider must be specified"
    echo "examples:"
    echo "   make dev provider=\"nvd\""
    echo "   make dev providers=\"oracle wolfi\""

    exit 1
fi

set +u
if [ -n "${DEV_VUNNEL_SHELL:-}" ]; then
    error "Already in a vunnel development shell"
    exit 0
fi
set -u

function finish {
    error "Unable to setup development shell. Bailing..."
}
trap finish EXIT


title "Entering vunnel development shell..."

if [ -f .env ]; then
    step "Sourcing .env file"
    set -o allexport
    source .env
    set +o allexport
fi

step "Configuring with providers: $DEV_VUNNEL_PROVIDERS"

step "Writing grype config: $GRYPE_CONFIG"
cat << EOF > "$GRYPE_CONFIG"
check-for-app-update: false
db:
  auto-update: false
  validate-age: false
  cache-dir: $(pwd)/.cache/grype
EOF
export GRYPE_CONFIG

step "Writing grype-db config: $GRYPE_DB_CONFIG"
cat << EOF > "$GRYPE_DB_CONFIG"
pull:
  parallelism: 1
provider:
  root: ./data
  vunnel:
    executor: local
    env:
      GITHUB_TOKEN: \$GITHUB_TOKEN
      NVD_API_KEY: \$NVD_API_KEY
  configs:
EOF
for provider in $DEV_VUNNEL_PROVIDERS; do
  echo "    - name: $provider" >> "$GRYPE_DB_CONFIG"
done
export GRYPE_DB_CONFIG

step "Activating virtual env: $DEV_PYTHON_ENV_PATH"
test -d "$DEV_PYTHON_ENV_PATH" || uv run vunnel --version
source "$DEV_PYTHON_ENV_PATH/bin/activate"

pids=""

step "Installing editable version of vunnel"
pip install -e . > /dev/null &
pids="$pids $!"

step "Building grype"
make build-grype &
pids="$pids $!"

step "Building grype-db"
make build-grype-db &
pids="$pids $!"

wait $pids

export PATH=${DEV_VUNNEL_BIN_DIR}:$PATH
export DEV_VUNNEL_SHELL=true

echo
echo -e "Note: development builds ${UNDERLINE}grype${RESET} and ${UNDERLINE}grype-db${RESET} are now available in your path."
echo -e "To update these builds run '${UNDERLINE}make build-grype${RESET}' and '${UNDERLINE}make build-grype-db${RESET}' respectively."
echo -e "To run your provider and update the grype database run '${UNDERLINE}make update-db${RESET}'."
echo -e "Type '${UNDERLINE}exit${RESET}' to exit the development shell."

# we were able to setup everything, no need to detect failures from this point on...
trap - EXIT

$SHELL

unset DEV_VUNNEL_SHELL
unset DEV_VUNNEL_PROVIDERS

title "Exiting vunnel development shell 👋"
