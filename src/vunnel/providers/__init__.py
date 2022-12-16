from vunnel.providers import (
    alpine,
    amazon,
    centos,
    debian,
    github,
    nvd,
    oracle,
    rhel,
    sles,
    ubuntu,
    wolfi,
)

_providers = {
    alpine.Provider.name: alpine.Provider,
    amazon.Provider.name: amazon.Provider,
    centos.Provider.name: centos.Provider,
    debian.Provider.name: debian.Provider,
    github.Provider.name: github.Provider,
    nvd.Provider.name: nvd.Provider,
    oracle.Provider.name: oracle.Provider,
    rhel.Provider.name: rhel.Provider,
    sles.Provider.name: sles.Provider,
    ubuntu.Provider.name: ubuntu.Provider,
    wolfi.Provider.name: wolfi.Provider,
}


def create(name, workspace_path, *args, **kwargs):
    return _providers[name](workspace_path, *args, **kwargs)


def names():
    return sorted(_providers.keys())
