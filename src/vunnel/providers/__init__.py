from vunnel.providers import centos, nvd

_providers = {centos.Provider.name: centos.Provider, nvd.Provider.name: nvd.Provider}


def create(name, workspace_path, *args, **kwargs):
    return _providers[name](workspace_path, *args, **kwargs)


def names():
    return sorted(_providers.keys())
