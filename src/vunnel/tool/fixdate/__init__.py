from vunnel import workspace

from . import first_observed
from .finder import Finder

__all__ = ["Finder", "default_finder"]


def default_finder(ws: workspace.Workspace, name: str) -> Finder:
    # TODO: we can add others as we implement them

    return first_observed.Store(ws, name)
