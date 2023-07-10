from __future__ import annotations

import abc
import datetime
import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from . import result, workspace
from .result import ResultStatePolicy


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


@dataclass
class OnErrorConfig:
    # the action to take when an error occurs
    action: OnErrorAction = OnErrorAction.FAIL
    # the number of times to retry an action that fails
    retry_count: int = 3
    # the number of seconds to wait between retries
    retry_delay: int = 5
    # what to do with the input directory when an error occurs
    input: InputStatePolicy = InputStatePolicy.KEEP  # noqa: A003
    # what to do with the result directory when an error occurs
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
    # what to do when an error occurs while the provider is running
    on_error: OnErrorConfig = field(default_factory=OnErrorConfig)
    # what to do with existing data in the input directory before running
    existing_input: InputStatePolicy = InputStatePolicy.KEEP
    # what to do with existing data in the result directory before running
    existing_results: ResultStatePolicy = ResultStatePolicy.KEEP
    # the format the results should be written in
    result_store: result.StoreStrategy = result.StoreStrategy.FLAT_FILE

    def __post_init__(self) -> None:
        if not isinstance(self.existing_input, InputStatePolicy):
            self.existing_input = InputStatePolicy(self.existing_input)
        if not isinstance(self.existing_results, ResultStatePolicy):
            self.existing_results = ResultStatePolicy(self.existing_results)
        if not isinstance(self.result_store, result.StoreStrategy):
            self.result_store = result.StoreStrategy(self.result_store)

    @property
    def skip_if_exists(self) -> bool:
        return self.existing_input == InputStatePolicy.KEEP


def disallow_existing_input_policy(cfg: RuntimeConfig) -> None:
    if cfg.existing_input != InputStatePolicy.KEEP:
        raise ValueError(
            f"existing_input policy is '{cfg.existing_input}' but only a value of 'keep' is allowed for this provider",
        )


class Provider(abc.ABC):
    # a breaking change to the semantics or values that the provider writes out should incur a version bump here.
    # this is used to determine if the provider can be run on an existing workspace or if it must be cleared first
    # (regardless of the existing_input and existing_result policy is).
    __version__: int = 1

    def __init__(self, root: str, runtime_cfg: RuntimeConfig = RuntimeConfig()):  # noqa: B008
        self.logger = logging.getLogger(self.name())
        self.workspace = workspace.Workspace(root, self.name(), logger=self.logger, create=False)
        self.urls: list[str] = []
        self.runtime_cfg = runtime_cfg

    @classmethod
    def version(cls) -> int:
        return cls.__version__

    @classmethod
    @abc.abstractmethod
    def name(cls) -> str:
        # note: wrapping [abstractmethod -> classmethod -> property] is no longer supported in
        # python 3.11 (deprecated due to undefined behavior) for this reason a simple classmethod
        # is used instead of a property
        raise NotImplementedError("'name()' must be implemented")

    @abc.abstractmethod
    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        """Populates the input directory from external sources, processes the data, places results into the output directory."""
        raise NotImplementedError("'update()' must be implemented")

    def read_state(self) -> workspace.State | None:
        try:
            return workspace.State.read(root=self.workspace.path)
        except FileNotFoundError:
            return None

    def _update(self) -> None:
        start = datetime.datetime.now(tz=datetime.timezone.utc)

        last_updated = None
        current_state = self.read_state()
        if current_state:
            last_updated = current_state.timestamp

        urls, count = self.update(last_updated=last_updated)
        if count > 0:
            self.workspace.record_state(
                version=self.version(),
                timestamp=start,
                urls=urls,
                store=self.runtime_cfg.result_store.value,
            )
        else:
            self.logger.debug("skipping recording of workspace state (no new results found)")

    def run(self) -> None:
        self.logger.debug(f"using {self.workspace.path!r} as workspace")

        current_state = self.read_state()
        if current_state and current_state.version != self.version():
            self.logger.warning(f"provider version has changed from {current_state.version} to {self.version()}")
            self.logger.warning("clearing workspace to ensure consistency of existing input and results")
            self.workspace.clear()
        else:
            if self.runtime_cfg.existing_results == ResultStatePolicy.DELETE:
                self.workspace.clear_results()

            if self.runtime_cfg.existing_input == InputStatePolicy.DELETE:
                self.workspace.clear_input()

        self.workspace.create()
        try:
            self._update()
        except Exception as e:
            self._on_error(e)

    def _on_error(self, e: Exception) -> None:
        self.logger.error(f"error during update: {e}")

        # manage state
        self._on_error_handle_state()

        # manage event
        if self.runtime_cfg.on_error.action == OnErrorAction.FAIL:
            raise e

        if self.runtime_cfg.on_error.action == OnErrorAction.SKIP:
            return

        if self.runtime_cfg.on_error.action == OnErrorAction.RETRY:
            attempt = 1
            last_exception: Exception | None = e
            while attempt <= self.runtime_cfg.on_error.retry_count:
                self.logger.info(f"retrying after error: {e}")
                time.sleep(self.runtime_cfg.on_error.retry_delay)
                try:
                    self._update()
                    last_exception = None
                    break
                except Exception as ex:
                    self.logger.error(f"error during update (attempt {attempt}): {e}")
                    self._on_error_handle_state()
                    last_exception = ex
                    attempt += 1

            if last_exception:
                raise last_exception

    def _on_error_handle_state(self) -> None:
        if self.runtime_cfg.on_error.input == InputStatePolicy.DELETE:
            self.workspace.clear_input()
        if self.runtime_cfg.on_error.results == ResultStatePolicy.DELETE:
            self.workspace.clear_results()

    def __repr__(self) -> str:
        extra = []
        prefix = ""
        if getattr(self, "config", None):
            extra.append(f"config={self.config}")  # type: ignore[attr-defined]
        if extra:
            prefix = ", "
        return f"Provider(name={self.name()}, input={self.workspace.input_path}{prefix}{', '.join(extra)})"

    def results_writer(self, **kwargs: Any) -> result.Writer:
        return result.Writer(
            workspace=self.workspace,
            result_state_policy=self.runtime_cfg.existing_results,
            logger=self.logger,
            store_strategy=self.runtime_cfg.result_store,
            **kwargs,
        )
