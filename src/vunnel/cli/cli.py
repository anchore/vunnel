from __future__ import annotations

import dataclasses
import enum
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any

import click
import yaml

from vunnel import __name__ as package_name
from vunnel import providers
from vunnel.cli import config


@click.option("--verbose", "-v", default=False, help="show logs", count=True)
@click.option("--config", "-c", "config_path", default=".vunnel.yaml", help="override config path")
@click.group(help="Tool for pulling and parsing vulnerability data for use with grype-db.")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.core.Context, verbose: bool, config_path: str) -> None:
    import logging.config

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
    logging.info(f"running {provider_name} provider")
    config = cfg.providers.get(provider_name)
    # technically config has type Any | None, so double check to appease mypy
    if config and config.runtime and hasattr(config.runtime, "skip_download"):
        config.runtime.skip_download = skip_download

    provider = providers.create(provider_name, cfg.root, config=config)
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

        provider = providers.create(provider_name, cfg.root, config=cfg.providers.get(provider_name))
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
            provider = providers.create(name, cfg.root, config=cfg.providers.get(name))

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
@click.pass_obj
def list_providers(cfg: config.Application) -> None:
    for p in providers.names():
        print(p)
