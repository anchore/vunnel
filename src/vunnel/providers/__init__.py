from vunnel.providers import centos

_providers = {centos.Provider.name: centos.Provider}


def create(name, workspace_path, *args, **kwargs):
    return _providers[name](workspace_path, *args, **kwargs)


def names():
    return sorted(_providers.keys())
