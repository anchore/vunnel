from vunnel import workspace

from . import first_observed
from .finder import Finder, Result

__all__ = ["Finder", "Result", "default_finder"]


def default_finder(ws: workspace.Workspace) -> Finder:
    # TODO: we can add others as we implement them

    # note: first_observed is a mix of the grype-db first observed dates dataset (a 5 year historical viewpoint) and
    # the vunnel observed fix dates dataset (a live, growing dataset of observed fix dates). We always check vunnel
    # first, then grype-db... if neither has a result, we add a new entry into vunnel and return that.
    return Finder(strategies=[], first_observed=first_observed.Store(ws))
