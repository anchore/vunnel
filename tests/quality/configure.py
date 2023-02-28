import logging
import shutil
import subprocess
import os
import glob
import json
import fnmatch
from dataclasses import dataclass, field
from typing import Optional

import click
import mergedeep
import yaml
from dataclass_wizard import asdict, fromdict, DumpMeta
from yardstick.cli.config import (
    Application,
    Tool,
    ScanMatrix,
    ResultSet,
)


@dataclass
class ConfigurationState:
    uncached_providers: list[str] = field(default_factory=list)
    cached_providers: list[str] = field(default_factory=list)


@dataclass
class Yardstick:
    default_max_year: int = 2021


@dataclass
class AdditionalProvider:
    name: str
    use_cache: bool = False


@dataclass
class Test:
    provider: str
    images: list[str] = field(default_factory=list)
    additional_providers: list[AdditionalProvider] = field(default_factory=list)
    additional_trigger_globs: list[str] = field(default_factory=list)


@dataclass
class Config:
    yardstick: Yardstick = field(default_factory=Yardstick)
    tools: list[Tool] = field(default_factory=list)
    tests: list[Test] = field(default_factory=list)

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        try:
            with open(path, encoding="utf-8") as f:
                app_object = yaml.safe_load(f.read()) or {}
                # we need a full default application config first then merge the loaded config on top.
                # Why? dataclass_wizard.fromdict() will create instances from the dataclass default
                # and NOT the field definition from the container. So it is possible to specify a
                # single field in the config and all other fields would be set to the default value
                # based on the dataclass definition and not any field(default_factory=...) hints
                # from the containing class.
                instance = asdict(cls())

                mergedeep.merge(instance, app_object)
                cfg = fromdict(
                    cls,
                    instance,
                )
                if cfg is None:
                    raise FileNotFoundError("parsed empty config")
        except FileNotFoundError:
            cfg = cls()

        return cfg

    def yardstick_application_config(self, test_configurations: list[Test]) -> Application:
        images = []
        for test in test_configurations:
            images += test.images
        return Application(
            default_max_year=self.yardstick.default_max_year,
            result_sets={
                "pr_vs_latest_via_sbom": ResultSet(
                    description="latest vulnerability data vs current vunnel data with latest grype tooling (via SBOM ingestion)",
                    matrix=ScanMatrix(
                        images=images,
                        tools=self.tools,
                    ),
                )
            },
        )

    def test_configuration_by_provider(self, provider: str) -> Optional[Test]:
        for test in self.tests:
            if test.provider == provider:
                return test
        return None

    def provider_data_source(self, providers: list[str]) -> tuple[list[str], list[str], Application]:
        cached_providers = []
        uncached_providers = []

        tests = []
        for provider in providers:
            test = self.test_configuration_by_provider(provider)
            if test is None:
                logging.warning(f"no test configuration found for provider {provider}")
                continue

            tests.append(test)

            uncached_providers.append(test.provider)
            if test.additional_providers:
                for additional_provider in test.additional_providers:
                    if additional_provider.use_cache:
                        cached_providers.append(additional_provider.name)
                    else:
                        uncached_providers.append(additional_provider.name)

        for provider in uncached_providers:
            if provider in cached_providers:
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
        }
    )


def write_config_state(cached_providers: list[str], uncached_providers: list[str], path: str = ".state.yaml"):
    logging.info(f"writing configuration state to {path!r}")

    with open(path, "w") as f:
        f.write(yaml.dump(asdict(ConfigurationState(cached_providers=cached_providers, uncached_providers=uncached_providers))))


def read_config_state(path: str = ".state.yaml"):
    logging.info(f"reading config state from {path!r}")

    try:
        with open(path, "r") as f:
            return fromdict(ConfigurationState, yaml.safe_load(f.read()))
    except FileNotFoundError:
        return ConfigurationState()


def write_yardstick_config(cfg: Application, path: str = ".yardstick.yaml"):
    logging.info(f"writing yardstick config to {path!r}")

    DumpMeta(key_transform="SNAKE", skip_defaults=True).bind_to(Application)

    with open(path, "w") as f:
        f.write(yaml.dump(asdict(cfg)))


def write_grype_db_config(providers: set[str], path: str = ".grype-db.yaml"):
    with open(path, "w") as f:
        f.write(
            """
pull:
  parallelism: 1
provider:
  root: ./data
  configs:
"""
            + "\n".join([f"    - name: {provider}" for provider in providers])
        )


@cli.command(name="show-changes", help="show the current file changeset")
@click.pass_obj
def show_changes(_: Config):
    changes()


def changes():
    logging.info("determining providers affected by the current file changeset")

    base_ref = os.environ.get("GITHUB_BASE_REF", "main")

    # get list of files changed with git diff
    changed_files = subprocess.check_output(["git", "diff", "--name-only", base_ref]).decode("utf-8").splitlines()

    logging.info(f"changed files: {len(changed_files)}")
    for changed_file in changed_files:
        logging.debug(f"  {changed_file}")

    return changed_files


@cli.command(name="select-providers", help="determine the providers to test from a file changeset")
@click.option("--json", "-j", "output_json", help="output result as json list (useful for CI)", is_flag=True)
@click.pass_obj
def select_providers(cfg: Config, output_json: bool):
    changed_files = changes()

    selected_providers = set()
    for test in cfg.tests:
        if not test.provider:
            continue

        search_globs = [f"src/vunnel/providers/{test.provider}/**"]

        for additional_provider in test.additional_providers:
            search_globs.append(f"src/vunnel/providers/{additional_provider.name}/**")

        for search_glob in search_globs:
            for changed_file in changed_files:
                if fnmatch.fnmatch(changed_file, search_glob):
                    logging.debug(f"provider {test.provider} is affected by file change {changed_file}")
                    selected_providers.add(test.provider)
                    break

    sorted_providers = sorted(list(selected_providers))

    if output_json:
        print(json.dumps(sorted_providers))
    else:
        for provider in sorted_providers:
            print(provider)


@cli.command(name="configure", help="setup yardstick and grype-db configurations for building a DB")
@click.argument("provider_names", metavar="PROVIDER", nargs=-1, required=True)
@click.pass_obj
def configure(cfg: Config, provider_names: list[str]):
    logging.info(f"preparing yardstick and grype-db configurations with {provider_names!r}")

    cached_providers, uncached_providers, yardstick_app_cfg = cfg.provider_data_source(provider_names)

    if not cached_providers and not uncached_providers:
        logging.error(f"no test configuration found for provider {provider_names!r}")
        return [], []

    providers = set(cached_providers + uncached_providers)

    write_grype_db_config(providers)
    write_yardstick_config(yardstick_app_cfg)

    write_config_state(cached_providers, uncached_providers)

    return cached_providers, uncached_providers


@cli.command(name="build-db", help="build a DB consisting of one or more providers")
@click.pass_obj
def build_db(_: Config):
    state = read_config_state()

    if not state.cached_providers and not state.uncached_providers:
        logging.error(f"no providers configured")
        return

    logging.info(f"preparing data directory for uncached={state.uncached_providers!r} cached={state.cached_providers!r}")

    cache_file = "grype-db-cache.tar.gz"
    grype_db = "bin/grype-db"
    data_dir = "data"
    build_dir = "build"
    db_archive = f"{build_dir}/grype-db.tar.gz"

    # clear data directory
    logging.info(f"clearing existing data")
    shutil.rmtree(data_dir, ignore_errors=True)
    shutil.rmtree(build_dir, ignore_errors=True)

    # run providers
    for provider in state.uncached_providers:
        logging.info(f"running provider {provider!r}")
        subprocess.run(["vunnel", "-v", "run", provider], check=True)

    # fetch cache for other providers
    for provider in state.cached_providers:
        logging.info(f"fetching cache for {provider!r}")
        subprocess.run(["oras", "pull", f"ghcr.io/anchore/grype-db/data/{provider}:latest"], check=True)
        subprocess.run([grype_db, "cache", "restore", "--path", cache_file], check=True)
        os.remove(cache_file)

    logging.info("building DB")
    subprocess.run([grype_db, "build", "-v"], check=True)
    subprocess.run([grype_db, "package", "-v"], check=True)

    archives = glob.glob(f"{build_dir}/*.tar.gz")
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
