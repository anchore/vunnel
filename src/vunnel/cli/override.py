import click
from vunnel.cli import config

@click.group(name="override", help="create and manage overrides of upstream data")
@click.pass_obj
def group(_: config.Application):
    pass

@group.command(name="create", help="create an override")
@click.argument("provider_name")
@click.argument("vuln_id")
def create_override(provider_name: str, vuln_id: str) -> None:
    print(f"creating override for {provider_name} {vuln_id}")
    # TODO:
        # download (or find!) the data and save it to the override location
        # print the file to stdout
