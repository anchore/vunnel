from vunnel import workspace

from . import first_observed
from .finder import Finder, Result

__all__ = ["Finder", "Result", "default_finder"]


def default_finder(ws: workspace.Workspace) -> Finder:
    # TODO: we can add others as we implement them

    return Finder(strategies=[], first_observed=first_observed.Store(ws))
