import abc
import enum
import logging
import os
import shutil
from dataclasses import dataclass

from . import workspace


class OnErrorPolicy(str, enum.Enum):
    FAIL = "fail"
    SKIP = "skip"
    RETRY = "retry"


class ExistingStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"


@dataclass
class RuntimeConfig:
    on_error: OnErrorPolicy = OnErrorPolicy.FAIL  # TODO: hook this up and enforce
    existing_input: ExistingStatePolicy = ExistingStatePolicy.DELETE
    existing_results: ExistingStatePolicy = ExistingStatePolicy.DELETE
    retry_attempts: int = 3

    def __post_init__(self):

        if not isinstance(self.on_error, OnErrorPolicy):
            self.on_error = OnErrorPolicy(self.on_error)
        if not isinstance(self.existing_input, ExistingStatePolicy):
            self.existing_input = ExistingStatePolicy(self.existing_input)
        if not isinstance(self.existing_results, ExistingStatePolicy):
            self.existing_results = ExistingStatePolicy(self.existing_results)


class Provider(abc.ABC):
    def __init__(self, root: str, runtime_cfg: RuntimeConfig = RuntimeConfig()):
        self.root = root
        self.logger = logging.getLogger(self.name)
        self.urls = []
        self.runtime_cfg = runtime_cfg

    @property
    @abc.abstractstaticmethod
    def name():
        pass

    @abc.abstractmethod
    def update(self):
        """Populates the input directory from external sources, processes the data, places results into the output directory."""

    def populate(self):
        self.logger.info(f"using {self.workspace} as workspace root")

        if self.runtime_cfg.existing_results == ExistingStatePolicy.DELETE:
            self._clear_results()

        if self.runtime_cfg.existing_input == ExistingStatePolicy.DELETE:
            self._clear_input()

        self._create_workspace()
        urls = self.update()
        self._catalog_workspace(urls=urls)

    def _create_workspace(self):
        if not os.path.exists(self.input):
            self.logger.debug(f"creating workspace for {self.name!r}")
            os.makedirs(self.input)
        else:
            self.logger.debug(f"using existing workspace for {self.name!r}")
        if not os.path.exists(self.results):
            os.makedirs(self.results)

    def _clear_results(self):
        if os.path.exists(self.results):
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.results)

    def _clear_input(self):
        if os.path.exists(self.input):
            self.logger.debug("clearing existing workspace")
            shutil.rmtree(self.input)

    def _catalog_workspace(self, urls: list[str]):
        state = workspace.WorkspaceState.from_fs(provider=self.name, urls=urls, input=self.input, results=self.results)

        metadata_path = state.write(self.workspace)

        self.logger.debug(msg=f"wrote workspace state to {metadata_path}")

    @property
    def workspace(self):
        return f"{self.root}/{self.name}"

    @property
    def input(self):
        return f"{self.workspace}/input"

    @property
    def results(self):
        return f"{self.workspace}/results"

    def __repr__(self):
        extra = []
        prefix = ""
        if getattr(self, "config"):
            extra.append(f"config={self.config}")  # pylint: disable=no-member
        if extra:
            prefix = ", "
        return f"Provider(name={self.name}, input={self.input}{prefix}{', '.join(extra)})"
