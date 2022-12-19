import abc
import enum
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

from . import result, workspace


class OnErrorAction(str, enum.Enum):
    FAIL = "fail"
    SKIP = "skip"
    RETRY = "retry"

    def __repr__(self) -> str:
        return self.value


class InputStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"

    def __repr__(self) -> str:
        return self.value


class ResultStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"
    DELETE_BEFORE_WRITE = "delete-before-write"  # treat like "KEEP" in error cases

    def __repr__(self) -> str:
        return self.value


@dataclass
class OnErrorConfig:
    action: OnErrorAction = OnErrorAction.FAIL
    retry_count: int = 3
    retry_delay: int = 5
    input: InputStatePolicy = InputStatePolicy.KEEP
    results: ResultStatePolicy = ResultStatePolicy.KEEP

    def __post_init__(self) -> None:

        if not isinstance(self.action, OnErrorAction):
            self.action = OnErrorAction(self.action)
        if not isinstance(self.input, InputStatePolicy):
            self.input = InputStatePolicy(self.input)
        if not isinstance(self.results, ResultStatePolicy):
            self.results = ResultStatePolicy(self.results)


@dataclass
class RuntimeConfig:
    on_error: OnErrorConfig = field(default_factory=OnErrorConfig)
    existing_input: InputStatePolicy = InputStatePolicy.DELETE
    existing_results: ResultStatePolicy = ResultStatePolicy.DELETE_BEFORE_WRITE

    def __post_init__(self) -> None:

        if not isinstance(self.existing_input, InputStatePolicy):
            self.existing_input = InputStatePolicy(self.existing_input)
        if not isinstance(self.existing_results, ResultStatePolicy):
            self.existing_results = ResultStatePolicy(self.existing_results)

    @property
    def skip_if_exists(self) -> bool:
        return self.existing_input == InputStatePolicy.KEEP


class Provider(abc.ABC):
    def __init__(self, root: str, runtime_cfg: RuntimeConfig = RuntimeConfig()):
        self._root = root
        self.logger = logging.getLogger(self.name())
        self.urls: list[str] = []
        self.runtime_cfg = runtime_cfg

    @classmethod
    @abc.abstractmethod
    def name(cls) -> str:
        raise NotImplementedError("'name()' must be implemented")

    @abc.abstractmethod
    def update(self) -> list[str]:
        """Populates the input directory from external sources, processes the data, places results into the output directory."""

    def populate(self) -> None:
        self.logger.debug(f"using {self.root} as workspace root")

        if self.runtime_cfg.existing_results == ResultStatePolicy.DELETE:
            self.clear_results()

        if self.runtime_cfg.existing_input == InputStatePolicy.DELETE:
            self.clear_input()

        self._create_workspace()
        urls = None
        try:
            urls = self.update()
            self._catalog_workspace(urls=urls)
        except Exception as e:  # noqa
            urls = self._on_error(e)

    def _on_error(self, e: Exception) -> list[str]:
        self.logger.error(f"error during update: {e}")

        # manage state
        urls = self._on_error_handle_state()

        # manage event
        if self.runtime_cfg.on_error.action == OnErrorAction.FAIL:
            raise e

        if self.runtime_cfg.on_error.action == OnErrorAction.SKIP:
            return urls

        if self.runtime_cfg.on_error.action == OnErrorAction.RETRY:
            attempt = 1
            last_exception: Exception | None = e
            while attempt <= self.runtime_cfg.on_error.retry_count:
                self.logger.info(f"retrying after error: {e}")
                time.sleep(self.runtime_cfg.on_error.retry_delay)
                try:
                    urls = self.update()
                    self._catalog_workspace(urls=urls)
                    last_exception = None
                    break
                except Exception as ex:  # noqa
                    self.logger.error(f"error during update (attempt {attempt}): {e}")
                    self._on_error_handle_state()
                    last_exception = ex
                    attempt += 1

            if last_exception:
                raise last_exception

        return urls

    def _on_error_handle_state(self) -> list[str]:
        if self.runtime_cfg.on_error.input == InputStatePolicy.DELETE:
            self.clear_input()
        if self.runtime_cfg.on_error.results == ResultStatePolicy.DELETE:
            self.clear_results()

        try:
            current_state = workspace.WorkspaceState.read(root=self.root)
            return current_state.urls
        except FileNotFoundError:
            pass
        return []

    def _create_workspace(self) -> None:
        if not os.path.exists(self.input):
            self.logger.debug(f"creating workspace for {self.name()!r}")
            os.makedirs(self.input)
        else:
            self.logger.debug(f"using existing workspace for {self.name()!r}")
        if not os.path.exists(self.results):
            os.makedirs(self.results)

    def clear(self) -> None:
        self.clear_input()
        self.clear_results()

    def clear_results(self) -> None:
        if os.path.exists(self.results):
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.results)

        try:
            current_state = workspace.WorkspaceState.read(root=self.root)
            current_state.results = workspace.FileListing(files=[])
            current_state.write(self.root)
        except FileNotFoundError:
            pass

    def clear_input(self) -> None:
        if os.path.exists(self.input):
            self.logger.debug("clearing existing workspace")
            shutil.rmtree(self.input)

        try:
            current_state = workspace.WorkspaceState.read(root=self.root)
            current_state.input = workspace.FileListing(files=[])
            current_state.write(self.root)
        except FileNotFoundError:
            pass

    def _catalog_workspace(self, urls: list[str]) -> None:
        if not urls:
            try:
                current_state = workspace.WorkspaceState.read(root=self.root)
                urls = current_state.urls
            except FileNotFoundError:
                urls = []

        self.logger.info(msg="cataloging workspace state")

        state = workspace.WorkspaceState.from_fs(provider=self.name(), urls=urls, input=self.input, results=self.results)

        metadata_path = state.write(self.root)

        self.logger.debug(msg=f"wrote workspace state to {metadata_path}")

    def current_state(self) -> workspace.WorkspaceState | None:
        return workspace.WorkspaceState.read(self.root)

    @property
    def root(self) -> str:
        return f"{self._root}/{self.name()}"

    @property
    def input(self) -> str:
        return f"{self.root}/input"

    @property
    def results(self) -> str:
        return f"{self.root}/results"

    def __repr__(self) -> str:
        extra = []
        prefix = ""
        if getattr(self, "config"):
            extra.append(f"config={self.config}")  # type: ignore
        if extra:
            prefix = ", "
        return f"Provider(name={self.name()}, input={self.input}{prefix}{', '.join(extra)})"

    def results_writer(self, **kwargs: Any) -> result.Writer:
        return result.Writer(
            prefix=self.name(),
            result_dir=self.results,
            logger=self.logger,
            clear_results_before_writing=self.runtime_cfg.existing_results == ResultStatePolicy.DELETE_BEFORE_WRITE,
            **kwargs,
        )
