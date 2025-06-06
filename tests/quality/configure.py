from __future__ import annotations
import dataclasses
import enum
import fnmatch
import glob
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

import click
import mergedeep
import requests
import yaml
from mashumaro.mixins.dict import DataClassDictMixin
from yardstick.cli.config import (
    ResultSet,
    ScanMatrix,
    Tool,
    Validation,
)
from yardstick.cli.config import Application as YardstickApplication

BIN_DIR = "./bin"
CLONE_DIR = f"{BIN_DIR}/grype-db-src"
GRYPE_DB = f"{BIN_DIR}/grype-db"


class Application(YardstickApplication, DataClassDictMixin):
    pass


@dataclass
class ConfigurationState(DataClassDictMixin):
    uncached_providers: list[str] = field(default_factory=list)
    cached_providers: list[str] = field(default_factory=list)


@dataclass
class Yardstick:
    default_max_year: int = 2021
    tools: list[Tool] = field(default_factory=list)


@dataclass
class AdditionalProvider:
    name: str
    use_cache: bool = False


@dataclass
class Test:
    provider: str
    use_cache: bool = False
    images: list[str] = field(default_factory=list)
    validations: list[Validation] = field(default_factory=list)
    additional_providers: list[AdditionalProvider] = field(default_factory=list)
    additional_trigger_globs: list[str] = field(default_factory=list)
    expected_namespaces: list[str] = field(default_factory=list)


@dataclass
class GrypeDB:
    version: str = "latest"


@dataclass
class Config(DataClassDictMixin):
    yardstick: Yardstick = field(default_factory=Yardstick)
    grype_db: GrypeDB = field(default_factory=GrypeDB)
    tests: list[Test] = field(default_factory=list)

    @classmethod
    def load(cls, path: str = "") -> "Config":
        if not path:
            path = "config.yaml"

        try:
            with open(path, encoding="utf-8") as f:
                app_object = yaml.safe_load(f.read()) or {}
                # we need a full default application config first then merge the loaded config on top.
                # Why? cls.from_dict() will create instances from the dataclass default
                # and NOT the field definition from the container. So it is possible to specify a
                # single field in the config and all other fields would be set to the default value
                # based on the dataclass definition and not any field(default_factory=...) hints
                # from the containing class.
                instance = cls().to_dict()

                mergedeep.merge(instance, app_object)
                cfg = cls.from_dict(instance)
                if cfg is None:
                    raise FileNotFoundError("parsed empty config")
        except FileNotFoundError:
            cfg = cls()

        return cfg

    def yardstick_application_config(self, test_configurations: list[Test]) -> Application:
        # tests is the set of providers explicitly requested
        # each provider is associated with the set of images it needs to scan
        # and the set of validations it needs to perform.
        images = []
        for test in test_configurations:
            images += test.images
            for validation in test.validations:
                if test.expected_namespaces:
                    validation.allowed_namespaces = test.expected_namespaces

        def result_set_from_test(t: Test) -> ResultSet:
            return ResultSet(
                description=f"latest vulnerability data vs current vunnel data with latest grype tooling (via SBOM ingestion) for {test.provider}",
                validations=test.validations,
                matrix=ScanMatrix(
                    images=t.images,
                    tools=self.yardstick.tools,
                ),
            )

        result_sets = {f"pr_vs_latest_via_sbom_{test.provider}": result_set_from_test(test) for test in test_configurations}
        return Application(
            default_max_year=self.yardstick.default_max_year,
            result_sets=result_sets,
        )

    def test_configuration_by_provider(self, provider: str) -> Test | None:
        for test in self.tests:
            if test.provider == provider:
                return test
        return None

    def provider_data_source(self, providers: list[str]) -> tuple[list[str], list[str], Application]:
        cached_providers = []
        uncached_providers = []

        tests = []
        providers_under_test_that_require_cache = set()
        for provider in providers:
            test = self.test_configuration_by_provider(provider)
            if test is None:
                logging.warning(f"no test configuration found for provider {provider}")
                continue

            tests.append(test)

            # note: we always include the subject in the uncached providers, but also add it to the cached providers.
            # the subject must always be run even when cache is involved.
            uncached_providers.append(test.provider)
            if test.use_cache:
                providers_under_test_that_require_cache.add(test.provider)
                cached_providers.append(test.provider)

            if test.additional_providers:
                for additional_provider in test.additional_providers:
                    if additional_provider.use_cache:
                        cached_providers.append(additional_provider.name)
                    else:
                        uncached_providers.append(additional_provider.name)

        for provider in uncached_providers:
            if provider in cached_providers and provider not in providers_under_test_that_require_cache:
                cached_providers.remove(provider)

        return cached_providers, uncached_providers, self.yardstick_application_config(tests)


@click.option("--verbose", "-v", default=False, help="show more logs", is_flag=True)
@click.option("--config", "-c", "config_path", default="config.yaml", help="override config path")
@click.group(help="Manage yardstick configuration that drives the quality gate testing")
@click.pass_context
def cli(ctx, verbose: bool, config_path: str):
    # pylint: disable=redefined-outer-name, import-outside-toplevel
    import logging.config

    # initialize yardstick based on the current configuration and
    # set the config object to click context to pass to subcommands
    ctx.obj = Config.load(config_path)

    log_level = "INFO"
    if verbose:
        log_level = "DEBUG"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    # [%(module)s.%(funcName)s]
                    # "format": "%(asctime)s [%(levelname)s] %(message)s",
                    "format": "[%(levelname)s] %(message)s",
                    "datefmt": "",
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        },
    )


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: Config):
    logging.info("showing application config")

    class IndentDumper(yaml.Dumper):
        def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: ARG002
            return super().increase_indent(flow, False)

    def enum_asdict_factory(data: list[tuple[str, Any]]) -> dict[Any, Any]:
        # prevents showing oddities such as
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #       existing_results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - delete-before-write
        #       on_error:
        #           action: !!python/object/apply:vunnel.provider.OnErrorAction
        #           - fail
        #           input: !!python/object/apply:vunnel.provider.InputStatePolicy
        #           - keep
        #           results: !!python/object/apply:vunnel.provider.ResultStatePolicy
        #           - keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: !!python/object/apply:vunnel.result.StoreStrategy
        #           - flat-file
        #
        # and instead preferring:
        #
        #   wolfi:
        #       request_timeout: 125
        #       runtime:
        #       existing_input: keep
        #       existing_results: delete-before-write
        #       on_error:
        #           action: fail
        #           input: keep
        #           results: keep
        #           retry_count: 3
        #           retry_delay: 5
        #       result_store: flat-file

        def convert_value(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            return obj

        return {k: convert_value(v) for k, v in data}

    cfg_dict = dataclasses.asdict(cfg, dict_factory=enum_asdict_factory)
    print(yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False))


def write_config_state(cached_providers: list[str], uncached_providers: list[str], path: str = ".state.yaml"):
    logging.info(f"writing configuration state to {path!r}")

    with open(path, "w") as f:
        f.write(yaml.dump(ConfigurationState(cached_providers=cached_providers, uncached_providers=uncached_providers).to_dict()))


def read_config_state(path: str = ".state.yaml"):
    logging.info(f"reading config state from {path!r}")

    try:
        with open(path) as f:
            return ConfigurationState.from_dict(yaml.safe_load(f.read()))
    except FileNotFoundError:
        return ConfigurationState()


def write_yardstick_config(cfg: Application, path: str = ".yardstick.yaml"):
    logging.info(f"writing yardstick config to {path!r}")

    with open(path, "w") as f:
        f.write(yaml.dump(cfg.to_dict()))


def write_grype_db_config(providers: set[str], path: str = ".grype-db.yaml"):
    logging.info(f"writing grype-db config to {path!r}")
    with open(path, "w") as f:
        f.write(
            """
pull:
  parallelism: 1
provider:
  root: ./data
  configs:
"""
            + "\n".join([f"    - name: {provider}" for provider in providers]),
        )


@cli.command(name="show-changes", help="show the current file changeset")
@click.pass_obj
def show_changes(_: Config):
    changes()


def changes():
    logging.info("determining providers affected by the current file changeset")

    # TODO: refactor for forking workflow
    base_ref = os.environ.get("GITHUB_BASE_REF", "origin/main")
    if not base_ref:
        base_ref = "origin/main"

    if "/" not in base_ref:
        base_ref = f"origin/{base_ref}"

    # get list of files changed with git diff
    changed_files = subprocess.check_output(["git", "diff", "--name-only", base_ref]).decode("utf-8").splitlines()

    logging.info(f"changed files: {len(changed_files)}")
    for changed_file in changed_files:
        logging.debug(f"  {changed_file}")

    return changed_files


def yardstick_version_changed():
    logging.info("determining whether yardstick version changed")

    base_ref = os.environ.get("GITHUB_BASE_REF", "origin/main")
    if not base_ref:
        base_ref = "origin/main"

    if "/" not in base_ref:
        base_ref = f"origin/{base_ref}"

    # get list of files changed with git diff
    changes = subprocess.check_output(["git", "diff", base_ref]).decode("utf-8").splitlines()
    for line in changes:
        if not line.strip().startswith(("-", "+")):
            # this line is in the output of `git diff`, but is just context, not a change
            continue

        if 'git = "https://github.com/anchore/yardstick"' in line:
            return True

    return False


@cli.command(name="select-providers", help="determine the providers to test from a file changeset")
@click.option("--json", "-j", "output_json", help="output result as json list (useful for CI)", is_flag=True)
@click.pass_obj
def select_providers(cfg: Config, output_json: bool):
    changed_files = changes()

    selected_providers = set()

    # look for gate changes, if any, then run all providers
    gate_globs = ["tests/quality/*.py", "tests/quality/*.yaml", "tests/quality/vulnerability-match-labels/**"]

    for search_glob in gate_globs:
        for changed_file in changed_files:
            if fnmatch.fnmatch(changed_file, search_glob):
                selected_providers = {test.provider for test in cfg.tests}

    if yardstick_version_changed():
        selected_providers = {test.provider for test in cfg.tests}

    if not selected_providers:
        # there are no gate changes, so look for provider-specific changes
        for test in cfg.tests:
            if not test.provider:
                continue

            search_globs = [f"src/vunnel/providers/{test.provider}/**"]

            for additional_provider in test.additional_providers:
                search_globs.append(f"src/vunnel/providers/{additional_provider.name}/**")

            for g in test.additional_trigger_globs:
                search_globs.append(g)

            for search_glob in search_globs:
                for changed_file in changed_files:
                    if fnmatch.fnmatch(changed_file, search_glob):
                        logging.debug(f"provider {test.provider} is affected by file change {changed_file}")
                        selected_providers.add(test.provider)
                        break

    sorted_providers = sorted(selected_providers)

    if output_json:
        print(json.dumps(sorted_providers))
    else:
        for provider in sorted_providers:
            print(provider)


@cli.command(name="all-providers", help="show all providers available to test")
@click.option("--json", "-j", "output_json", help="output result as json list (useful for CI)", is_flag=True)
@click.pass_obj
def all_providers(cfg: Config, output_json: bool):
    selected_providers = {test.provider for test in cfg.tests}
    sorted_providers = sorted(selected_providers)

    if output_json:
        print(json.dumps(sorted_providers))
    else:
        for provider in sorted_providers:
            print(provider)


@cli.command(
    name="validate-test-tool-versions",
    help="Pass/Fail to indicate if production versions of grype and grype-db are used when testing",
)
@click.pass_obj
def validate_test_tool_versions(cfg: Config):
    logging.info("validating test tool versions")

    reasons = []

    logging.info(f"grype-db version: {cfg.grype_db.version!r}")
    if cfg.grype_db.version != "main":
        reasons.append("grype-db version is not main")

    for idx, tool in enumerate(cfg.yardstick.tools):
        if tool.name != "grype":
            continue

        label = tool.label
        if not label:
            label = ""

        logging.info(f"grype version (index={idx+1} label={label}): {tool.version!r}")

        if tool.version != "main" and not tool.version.startswith("main+"):
            reasons.append(f"grype version is not main (index {idx+1})")

    for reason in reasons:
        logging.error(reason)

    if reasons:
        print("FAIL")
        sys.exit(1)
    print("PASS")


@cli.command(name="configure", help="setup yardstick and grype-db configurations for building a DB")
@click.argument("provider_names", metavar="PROVIDER", nargs=-1, required=True)
@click.pass_obj
def configure(cfg: Config, provider_names: list[str]):
    logging.info(f"preparing yardstick and grype-db configurations with {provider_names!r}")

    cached_providers, uncached_providers, yardstick_app_cfg = cfg.provider_data_source(provider_names)

    logging.info(f"providers uncached={uncached_providers!r} cached={cached_providers!r}")

    if not cached_providers and not uncached_providers:
        logging.error(f"no test configuration found for provider {provider_names!r}")
        return [], []

    providers = set(cached_providers + uncached_providers)

    logging.info(f"writing grype-db config for {' '.join(providers)}")
    write_grype_db_config(providers)
    write_yardstick_config(yardstick_app_cfg)

    write_config_state(cached_providers, uncached_providers)

    _install_grype_db(cfg.grype_db.version)

    return cached_providers, uncached_providers


@cli.command(name="install", help="install tooling (currently only grype-db)")
@click.pass_obj
def install(cfg: Config):
    _install_grype_db(cfg.grype_db.version)


def _install_grype_db(input: str):
    os.makedirs(BIN_DIR, exist_ok=True)

    version = input
    is_semver = re.match(r"v\d+\.\d+\.\d+", input)
    repo_user_and_name = "anchore/grype-db"
    using_local_file = input.startswith("file://")
    clone_dir = CLONE_DIR

    if using_local_file:
        clone_dir = os.path.expanduser(input.replace("file://", ""))
    else:
        if "/" in input:
            # this is a fork...
            if "@" in input:
                # ... with a branch specification
                repo_user_and_name, version = input.split("@")
            else:
                repo_user_and_name = input
                version = "main"

    repo_url = f"https://github.com/{repo_user_and_name}"

    if input == "latest":
        version = (
            requests.get("https://github.com/anchore/grype-db/releases/latest", headers={"Accept": "application/json"})
            .json()
            .get("tag_name", "")
        )
        logging.info(f"latest released grype-db version is {version!r}")

    elif is_semver:
        install_version = version
        if os.path.exists(GRYPE_DB):
            existing_version = (
                subprocess.check_output([f"{BIN_DIR}/grype-db", "--version"]).decode("utf-8").strip().split(" ")[-1]
            )
            if existing_version == install_version:
                logging.info(f"grype-db already installed at version {install_version!r}")
                return
            else:
                logging.info(f"updating grype-db from version {existing_version!r} to {install_version!r}")

    if using_local_file:
        _install_from_user_source(bin_dir=BIN_DIR, clone_dir=clone_dir)
    else:
        _install_from_clone(
            bin_dir=BIN_DIR, checkout=version, clone_dir=clone_dir, repo_url=repo_url, repo_user_and_name=repo_user_and_name
        )


def _install_from_clone(bin_dir: str, checkout: str, clone_dir: str, repo_url: str, repo_user_and_name: str):
    logging.info(f"creating grype-db repo at {clone_dir!r} from {repo_url}")

    if os.path.exists(clone_dir):
        remote_url = subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=clone_dir).decode().strip()
        if not remote_url.endswith(repo_user_and_name) or remote_url.endswith(repo_user_and_name + ".git"):
            logging.info(f"removing grype-db clone at {clone_dir!r} because remote url does not match {repo_url!r}")
            shutil.rmtree(clone_dir)

    if not os.path.exists(clone_dir):
        subprocess.run(["git", "clone", repo_url, clone_dir], check=True)
    else:
        subprocess.run(["git", "fetch", "--all"], cwd=clone_dir, check=True)

    subprocess.run(["git", "checkout", checkout], cwd=clone_dir, check=True)

    install_version = subprocess.check_output(["git", "describe", "--always", "--tags"], cwd=clone_dir).decode("utf-8").strip()

    _build_grype_db(bin_dir=bin_dir, install_version=install_version, clone_dir=clone_dir)


def _install_from_user_source(bin_dir: str, clone_dir: str):
    logging.info(f"using user grype-db repo at {clone_dir!r}")
    install_version = subprocess.check_output(["git", "describe", "--always", "--tags"], cwd=clone_dir).decode("utf-8").strip()
    _build_grype_db(bin_dir=bin_dir, install_version=install_version, clone_dir=clone_dir)


def _build_grype_db(bin_dir: str, install_version: str, clone_dir: str):
    logging.info(f"installing grype-db at version {install_version!r}")

    abs_bin_path = os.path.abspath(bin_dir)
    cmd = f"go build -v -ldflags=\"-X 'github.com/anchore/grype-db/cmd/grype-db/application.version={install_version}'\" -o {abs_bin_path} ./cmd/grype-db"

    logging.info(f"building grype-db: {cmd}")

    subprocess.run(shlex.split(cmd), cwd=clone_dir, env=os.environ, check=True)


@cli.command(name="build-db", help="build a DB consisting of one or more providers")
@click.pass_obj
def build_db(cfg: Config):
    state = read_config_state()

    if not state.cached_providers and not state.uncached_providers:
        logging.error("no providers configured")
        return

    logging.info(f"preparing data directory for uncached={state.uncached_providers!r} cached={state.cached_providers!r}")

    cache_file = "grype-db-cache.tar.gz"
    data_dir = "data"
    build_dir = "build"
    db_archive = f"{build_dir}/grype-db.tar.zst"

    # clear data directory
    logging.info("clearing existing data")
    shutil.rmtree(data_dir, ignore_errors=True)
    shutil.rmtree(build_dir, ignore_errors=True)

    # fetch cache for other providers
    for provider in state.cached_providers:
        logging.info(f"fetching cache for {provider!r}")
        subprocess.run(["oras", "pull", f"ghcr.io/anchore/grype-db/data/{provider}:latest"], check=True)
        subprocess.run([GRYPE_DB, "cache", "restore", "--path", cache_file], check=True)
        os.remove(cache_file)

    # run providers
    for provider in state.uncached_providers:
        logging.info(f"running provider {provider!r}")
        subprocess.run(["vunnel", "-v", "run", provider], check=True)

    logging.info("building DB")
    subprocess.run([GRYPE_DB, "build", "-s", "6", "-v", "-c", ".grype-db.yaml"], check=True)
    subprocess.run([GRYPE_DB, "package", "-v", "-c", ".grype-db.yaml"], check=True)

    archives = glob.glob(f"{build_dir}/*.tar.zst")
    if not archives:
        logging.error("no DB archive found")
        return
    if len(archives) > 1:
        logging.error("multiple DB archives found")
        return

    archive = archives[0]

    shutil.move(archive, db_archive)


if __name__ == "__main__":
    cli()
