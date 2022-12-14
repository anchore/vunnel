from vunnel.providers import alpine, amazon, centos, debian, github, nvd

_providers = {
    alpine.Provider.name: alpine.Provider,
    amazon.Provider.name: amazon.Provider,
    centos.Provider.name: centos.Provider,
    debian.Provider.name: debian.Provider,
    nvd.Provider.name: nvd.Provider,
    github.Provider.name: github.Provider,
}


def create(name, workspace_path, *args, **kwargs):
    return _providers[name](workspace_path, *args, **kwargs)


def names():
    return sorted(_providers.keys())
