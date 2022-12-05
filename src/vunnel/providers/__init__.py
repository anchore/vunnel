from vunnel.providers import centos, nvdv2

_providers = {centos.Provider.name: centos.Provider, nvdv2.Provider.name: nvdv2.Provider}


def create(name, workspace_path, *args, **kwargs):
    return _providers[name](workspace_path, *args, **kwargs)


def names():
    return sorted(_providers.keys())
