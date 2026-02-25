from __future__ import annotations

import dataclasses
import datetime
import enum
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from importlib.metadata import version
from typing import Any

import click
import yaml

from vunnel import __name__ as package_name
from vunnel import provider, providers, result, workspace
from vunnel.cli import config


@click.option("--verbose", "-v", default=False, help="show logs", count=True)
@click.option("--config", "-c", "config_path", default=".vunnel.yaml", help="override config path")
@click.group(help="Tool for pulling and parsing vulnerability data for use with grype-db.")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.core.Context, verbose: bool, config_path: str) -> None:
    import logging.config  # noqa: PLC0415 - intentional: avoid polluting logging state when vunnel is used as a library

    # TODO: config parsing
    ctx.obj = config.load(path=config_path)

    log_level = ctx.obj.log.level
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"

    if ctx.obj.log.slim:
        timestamp_format = ""
        level_format = ""
    else:
        timestamp_format = "%(asctime)s "
        if not ctx.obj.log.show_timestamp:
            timestamp_format = ""

        level_format = "[%(levelname)-5s] "
        if not ctx.obj.log.show_level:
            level_format = ""

    log_format = f"%(log_color)s{timestamp_format}{level_format}%(message)s"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    "()": "colorlog.ColoredFormatter",  # colored output
                    # [%(module)s.%(funcName)s]
                    "format": log_format,
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                    "log_colors": {
                        "TRACE": "purple",
                        "DEBUG": "cyan",
                        "INFO": "reset",
                        "WARNING": "yellow",
                        "ERROR": "red",
                        "CRITICAL": "red,bg_white",
                    },
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    # "class": "logging.StreamHandler",
                    "class": "colorlog.StreamHandler",
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

    logging.debug("vunnel@%s", version("vunnel"))

    providers.load_plugins()


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: config.Application) -> None:
    logging.info("showing application config")

    class IndentDumper(yaml.Dumper):
        def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
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


@cli.command(name="run", help="run a vulnerability provider")
@click.argument("provider_name", metavar="PROVIDER")
@click.option("--skip-download", is_flag=True, help="skip downloading data", default=False)
@click.pass_obj
def run_provider(cfg: config.Application, provider_name: str, skip_download: bool) -> None:
    logging.info(f"running {provider_name} provider in {cfg.root}")
    config = cfg.providers.get(provider_name)
    # technically config has type Any | None, so double check to appease mypy
    if config and config.runtime and hasattr(config.runtime, "skip_download"):
        config.runtime.skip_download = skip_download

    with providers.create(provider_name, cfg.root, config=config) as provider:
        provider.run()


@cli.command(name="clear", help="clear provider state")
@click.argument("provider_names", metavar="PROVIDER", nargs=-1)
@click.option("--input", "-i", "_input", is_flag=True, help="clear only the input state")
@click.option("--result", "-r", is_flag=True, help="clear only the result state")
@click.pass_obj
def clear_provider(cfg: config.Application, provider_names: str, _input: bool, result: bool) -> None:
    if not provider_names:
        logging.warning("no providers specified, bailing...")
        sys.exit(1)
    for provider_name in provider_names:
        logging.info(f"clearing {provider_name} provider state")

        with providers.create(provider_name, cfg.root, config=cfg.providers.get(provider_name)) as provider:
            if not _input and not result:
                provider.workspace.clear()
            elif _input:
                provider.workspace.clear_input()
            elif result:
                provider.workspace.clear_results()


@cli.command(name="status", help="describe current provider state")
@click.argument("provider_names", metavar="PROVIDER", nargs=-1)
@click.option("--show-empty", default=False, is_flag=True, help="show providers with no state")
@click.option("--json", "output_json", default=False, is_flag=True, help="output as JSON")
@click.pass_obj
def status_provider(cfg: config.Application, provider_names: str, show_empty: bool, output_json: bool) -> None:  # noqa: C901
    selected_names = provider_names if provider_names else providers.names()

    @dataclass
    class CurrentState:
        count: int | None = None
        date: str | None = None
        error: str | None = None
        enabled: bool = True

        def format(self, fill: str) -> str:
            if self.error:
                return f"""\
{fill}      unable to load state: {self.error}"""

            if self.count is None and self.date is None:
                return f"""\
{fill}      (no state found)"""

            return f"""\
{fill}      results: {self.count}
{fill}      from:    {self.date}"""

        def to_dict(self) -> dict[str, Any]:
            return {
                "count": self.count,
                "date": self.date,
                "error": self.error,
                "enabled": self.enabled,
            }

    # first pass: find the results that exist (which may be fewer than what is selected)
    results = {}
    for _idx, name in enumerate(selected_names):
        try:
            with providers.create(name, cfg.root, config=cfg.providers.get(name)) as provider:
                state = provider.workspace.state()
                if not state:
                    raise FileNotFoundError("no state found")
                results[name] = CurrentState(
                    count=state.result_count(provider.workspace.path),
                    date=state.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                )
        except FileNotFoundError:
            if not show_empty:
                continue
            results[name] = CurrentState(enabled=False)
        except Exception as e:
            results[name] = CurrentState(enabled=False, error=str(e))

    # if --json is requested, output as JSON
    if output_json:
        json_output = {
            "root": cfg.root,
            "providers": [
                {"name": name, **result.to_dict()}  # unpack to a dict
                for name, result in sorted(results.items())
            ],
        }
        print(json.dumps(json_output, indent=2))  # noqa: TID251 # TID251: json.dumps() isn't needed for this use case
    # otherwise, output as a tree structure
    else:
        # existing tree output
        print(cfg.root)
        for idx, (name, result) in enumerate(sorted(results.items())):
            branch = "├──"
            fill = "│"
            if idx == len(results) - 1:
                branch = "└──"
                fill = " "

            node = result.format(fill)

            print(f"""{branch} {name}\n{node}""")


@cli.command(name="list", help="list available providers")
@click.option(
    "--tag",
    "-t",
    "tags",
    multiple=True,
    help="filter by tag (can repeat). Prefix with '!' to exclude (e.g., -t !auxiliary)",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["list", "json"]),
    default="list",
    help="output format",
)
@click.pass_obj
def list_providers(cfg: config.Application, tags: tuple[str, ...], output_format: str) -> None:
    try:
        provider_names = providers.providers_with_tags(list(tags)) if tags else providers.names()
    except ValueError as e:
        raise click.ClickException(str(e)) from e

    if output_format == "json":
        output: dict[str, list[dict[str, Any]]] = {"providers": []}
        for name in provider_names:
            cls = providers.provider_class(name)
            schema = cls.schema()
            output["providers"].append(
                {
                    "name": name,
                    "version": cls.version(),
                    "schema": {
                        "name": schema.name if schema else "",
                        "version": schema.version if schema else "",
                    },
                    "tags": provider.get_provider_tags(cls),
                },
            )
        print(json.dumps(output, indent=2))  # noqa: TID251
    else:
        for p in provider_names:
            print(p)


# fixed timestamp: Sept 16, 1987 midnight UTC (indicates synthetic/derived data)
SYNTHETIC_TIMESTAMP = datetime.datetime(1987, 9, 16, 0, 0, 0, tzinfo=datetime.UTC)


def _extract_literal_substring(pattern: str) -> str | None:
    """Extract the longest literal substring from a regex for pre-filtering.

    Returns None if no useful literal substring can be extracted.
    """
    # find all contiguous literal character sequences
    literals = []
    current: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c in r".*+?^${}[]|()\\":
            if current:
                literals.append("".join(current))
                current = []
        else:
            current.append(c)
        i += 1
    if current:
        literals.append("".join(current))

    # return the longest literal substring (most selective for filtering)
    if literals:
        return max(literals, key=len)
    return None


@cli.command(name="workspace-select", help="select results by ID pattern into a new workspace")
@click.option(
    "--provider",
    "-p",
    "provider_names",
    multiple=True,
    required=True,
    help="provider name(s) to select from (can repeat)",
)
@click.option(
    "--id",
    "-i",
    "id_pattern",
    required=True,
    help="regex pattern to match result identifiers",
)
@click.option(
    "--replace",
    is_flag=True,
    default=False,
    help="replace existing results at output path (default: append)",
)
@click.option(
    "--store",
    "store_strategy",
    type=click.Choice(["flat-file", "sqlite"]),
    default="flat-file",
    help="output storage format (default: flat-file)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="show matching IDs without writing results",
)
@click.argument("output_path", type=click.Path())
@click.pass_obj
def workspace_select(  # noqa: C901, PLR0913
    cfg: config.Application,
    provider_names: tuple[str, ...],
    id_pattern: str,
    replace: bool,
    store_strategy: str,
    dry_run: bool,
    output_path: str,
) -> None:
    """Select results by ID pattern into a new workspace."""
    # compile regex with case-insensitive flag
    # auto-wrap pattern with .* if not anchored for substring matching
    try:
        effective_pattern = id_pattern
        if not effective_pattern.startswith("^") and not effective_pattern.startswith(".*"):
            effective_pattern = ".*" + effective_pattern
        if not effective_pattern.endswith("$") and not effective_pattern.endswith(".*"):
            effective_pattern = effective_pattern + ".*"

        regex = re.compile(effective_pattern, re.IGNORECASE)
    except re.error as e:
        raise click.ClickException(f"invalid regex pattern: {e}") from e

    # extract literal substring for efficient pre-filtering at the data layer
    literal_substring = _extract_literal_substring(id_pattern)

    store_strat = result.StoreStrategy(store_strategy)

    for provider_name in provider_names:
        source_workspace = workspace.Workspace(root=cfg.root, name=provider_name)

        # check if source workspace exists
        if not os.path.exists(source_workspace.results_path):
            logging.warning(f"source workspace not found for provider {provider_name!r}, skipping")
            continue

        if dry_run:
            # dry-run mode: just show matching IDs without writing
            matched_count = 0
            with result.Reader(source_workspace) as reader:
                for identifier in reader.ids(literal_filter=literal_substring):
                    if regex.search(identifier):
                        print(f"{provider_name}: {identifier}")
                        matched_count += 1

            logging.info(f"would select {matched_count} results from {provider_name!r}")  # noqa: S608
            continue

        # create destination workspace (results only, no input)
        dest_workspace = workspace.Workspace(root=output_path, name=provider_name)
        dest_workspace.create(create_input=False)

        # determine policy based on --replace flag
        policy = result.ResultStatePolicy.DELETE_BEFORE_WRITE if replace else result.ResultStatePolicy.KEEP

        matched_count = 0
        with (
            result.Reader(source_workspace) as reader,
            result.Writer(
                dest_workspace,
                result_state_policy=policy,
                store_strategy=store_strat,
            ) as writer,
        ):
            # prepare the store (handles DELETE_BEFORE_WRITE by clearing results)
            writer.store.prepare()

            # use literal substring for efficient pre-filtering, then apply regex
            for identifier in reader.ids(literal_filter=literal_substring):
                if regex.search(identifier):
                    envelope = reader.read(identifier)
                    if envelope is None:
                        logging.warning(f"failed to read result {identifier!r}, skipping")
                        continue
                    writer.store.store(identifier, envelope)
                    writer.wrote += 1
                    matched_count += 1

        logging.info(f"selected {matched_count} results from {provider_name!r}")

        # record workspace state
        dest_workspace.record_state(
            version=1,
            distribution_version=1,
            timestamp=SYNTHETIC_TIMESTAMP,
            urls=[],
            store=str(store_strat.value),
            stale=True,
        )
