import click

from .cli import cli


def run():
    return cli()  # pylint: disable=no-value-for-parameter
