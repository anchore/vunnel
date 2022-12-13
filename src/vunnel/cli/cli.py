import dataclasses
import logging

import click
import yaml

from vunnel import providers
from vunnel.cli import config


@click.option("--verbose", "-v", default=False, help="show logs", count=True)
@click.option("--config", "-c", "config_path", default=".vunnel.yaml", help="override config path")
@click.group(help="Tool for pulling and parsing vulnerability data for use with grype-db.")
@click.pass_context
def cli(ctx, verbose: bool, config_path: str):
    # pylint: disable=redefined-outer-name, import-outside-toplevel
    import logging.config

    # TODO: config parsing
    ctx.obj = config.load(path=config_path)

    log_level = ctx.obj.log.level.upper()
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"

    log_format = "%(log_color)s %(asctime)s %(name)s [%(levelname)s] %(message)s"
    if ctx.obj.log.slim:
        log_format = "%(log_color)s [%(levelname)s] %(message)s"

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
        }
    )


@cli.command(name="config", help="show the application config")
@click.pass_obj
def show_config(cfg: config.Application):
    logging.info("showing application config")

    # pylint: disable=too-many-ancestors
    class IndentDumper(yaml.Dumper):
        def increase_indent(self, flow=False, indentless=False):
            return super().increase_indent(flow, False)

    cfg_dict = dataclasses.asdict(cfg)
    print(yaml.dump(cfg_dict, Dumper=IndentDumper, default_flow_style=False))


@cli.command(name="run", help="run a vulnerability provider")
@click.option("--provider", "-p", "provider_name", help="provider to run", required=True)
@click.pass_obj
def run_provider(cfg: config.Application, provider_name: str):
    logging.info(f"running {provider_name} provider")

    provider = providers.create(provider_name, cfg.root, config=cfg.providers.get(provider_name))
    provider.populate()


@cli.command(name="list", help="list available vulnerability providers")
@click.pass_obj
def list_providers(cfg: config.Application):  # pylint: disable=unused-argument
    for p in providers.names():
        print(p)
