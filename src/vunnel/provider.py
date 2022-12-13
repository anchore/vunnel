import abc
import enum
import logging
import os
import shutil
import time
from dataclasses import dataclass, field

from . import result, workspace


class OnErrorPolicy(str, enum.Enum):
    FAIL = "fail"
    SKIP = "skip"
    RETRY = "retry"

    def __repr__(self):
        return self.value


class InputStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"

    def __repr__(self):
        return self.value


class ResultStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"
    DELETE_BEFORE_WRITE = "delete-before-write"  # treat like "KEEP" in error cases

    def __repr__(self):
        return self.value


@dataclass
class OnErrorConfig:
    policy: OnErrorPolicy = OnErrorPolicy.FAIL
    retry_count: int = 3
    retry_delay: int = 5
    input: InputStatePolicy = InputStatePolicy.KEEP
    results: ResultStatePolicy = ResultStatePolicy.KEEP

    def __post_init__(self):

        if not isinstance(self.policy, OnErrorPolicy):
            self.policy = OnErrorPolicy(self.policy)
        if not isinstance(self.input, InputStatePolicy):
            self.input = InputStatePolicy(self.input)
        if not isinstance(self.results, ResultStatePolicy):
            self.results = ResultStatePolicy(self.results)


@dataclass
class RuntimeConfig:
    on_error: OnErrorConfig = field(default_factory=OnErrorConfig)  # TODO: hook this up and enforce
    existing_input: InputStatePolicy = InputStatePolicy.DELETE
    existing_results: ResultStatePolicy = ResultStatePolicy.DELETE_BEFORE_WRITE

    def __post_init__(self):

        if not isinstance(self.existing_input, InputStatePolicy):
            self.existing_input = InputStatePolicy(self.existing_input)
        if not isinstance(self.existing_results, ResultStatePolicy):
            self.existing_results = ResultStatePolicy(self.existing_results)

    @property
    def skip_if_exists(self):
        return self.existing_input == InputStatePolicy.KEEP


class Provider(abc.ABC):
    def __init__(self, root: str, runtime_cfg: RuntimeConfig = RuntimeConfig()):
        self._root = root
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
        self.logger.debug(f"using {self.root} as workspace root")

        if self.runtime_cfg.existing_results == ResultStatePolicy.DELETE:
            self._clear_results()

        if self.runtime_cfg.existing_input == InputStatePolicy.DELETE:
            self._clear_input()

        self._create_workspace()
        try:
            urls = self.update()
        except Exception as e:  # pylint: disable=broad-except
            self._on_error(e)
        self._catalog_workspace(urls=urls)

    def _on_error(self, e: Exception):
        self.logger.error(f"error during update: {e}")

        # manage state
        self._on_error_handle_state()

        # manage event
        if self.runtime_cfg.on_error.policy == OnErrorPolicy.FAIL:
            raise e

        if self.runtime_cfg.on_error.policy == OnErrorPolicy.SKIP:
            return

        if self.runtime_cfg.on_error.policy == OnErrorPolicy.RETRY:
            attempt = 2
            last_exception = e
            while attempt <= self.runtime_cfg.on_error.retry_count:
                self.logger.info(f"retrying after error: {e}")
                time.sleep(self.runtime_cfg.on_error.retry_delay)
                try:
                    self.update()
                    last_exception = None
                    break
                except Exception as ex:  # pylint: disable=broad-except
                    self.logger.error(f"error during update (attempt {attempt}): {e}")
                    self._on_error_handle_state()
                    last_exception = ex
                    attempt += 1

            if last_exception:
                raise last_exception

    def _on_error_handle_state(self):
        if self.runtime_cfg.on_error.input == InputStatePolicy.DELETE:
            self._clear_input()
        if self.runtime_cfg.on_error.results == ResultStatePolicy.DELETE:
            self._clear_results()

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

        metadata_path = state.write(self.root)

        self.logger.debug(msg=f"wrote workspace state to {metadata_path}")

    @property
    def root(self):
        return f"{self._root}/{self.name}"

    @property
    def input(self):
        return f"{self.root}/input"

    @property
    def results(self):
        return f"{self.root}/results"

    def __repr__(self):
        extra = []
        prefix = ""
        if getattr(self, "config"):
            extra.append(f"config={self.config}")  # pylint: disable=no-member
        if extra:
            prefix = ", "
        return f"Provider(name={self.name}, input={self.input}{prefix}{', '.join(extra)})"

    def results_writer(self, **kwargs):
        return result.Writer(
            prefix=self.name,
            result_dir=self.results,
            logger=self.logger,
            clear_results_before_writing=self.runtime_cfg.existing_results == ResultStatePolicy.DELETE_BEFORE_WRITE,
            **kwargs,
        )
