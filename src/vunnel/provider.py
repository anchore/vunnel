from __future__ import annotations

import abc
import datetime
import enum
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from vunnel.utils import archive, hasher, http

from . import distribution, result, workspace
from . import schema as schema_def
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
    input: InputStatePolicy = InputStatePolicy.KEEP
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
    # skip checks for newer archive if true (always download latest)
    skip_newer_archive_check: bool = False

    import_results_host: Optional[str] = None  # noqa: UP007 - breaks mashumaro
    import_results_path: Optional[str] = None  # noqa: UP007 - breaks mashumaro
    import_results_enabled: Optional[bool] = None  # noqa: UP007 - breaks mashumaro

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

    def import_url(self, provider_name: str) -> str:
        path = self.import_results_path
        if path is None:
            path = ""
        path = path.format(provider_name=provider_name)
        host = self.import_results_host
        if host is None:
            host = ""

        return f"{host.strip('/')}/{path.strip('/')}"


def disallow_existing_input_policy(cfg: RuntimeConfig) -> None:
    if cfg.existing_input != InputStatePolicy.KEEP:
        raise ValueError(
            f"existing_input policy is '{cfg.existing_input}' but only a value of 'keep' is allowed for this provider",
        )


class Provider(abc.ABC):
    # a breaking change to the semantics of how the provider processes results.
    #
    # NOTE: this value should only be changed in classes that inherit this class. Do not change the value in this class!
    __version__: int = 1

    # a breaking change to the schema of the results that the provider writes out should incur a version bump here.
    #
    # NOTE: this value should only be changed in classes that inherit this class. Do not change the value in this class!
    __distribution_version__: int = 1

    def __init__(self, root: str, runtime_cfg: RuntimeConfig = RuntimeConfig()):  # noqa: B008
        self.logger = logging.getLogger(self.name())
        self.workspace = workspace.Workspace(root, self.name(), logger=self.logger, create=False)
        self.urls: list[str] = []
        if runtime_cfg.import_results_enabled:
            if not runtime_cfg.import_results_host:
                raise RuntimeError("enabling import results requires host")
            if not runtime_cfg.import_results_path:
                raise RuntimeError("enabling import results requires path")

        self.runtime_cfg = runtime_cfg

    @classmethod
    def version(cls) -> int:
        return cls.__version__ + (cls.distribution_version() - 1)

    @classmethod
    def distribution_version(cls) -> int:
        """This version represents when a breaking change is made for interpreting purely the provider results. This
        tends to be an aggregation of all schema versions involved in the provider (i.e. the provider workspace state
        and results shape). This is slightly different from the `version` method which is specific to the provider,
        which encapsulates at least the distribution version + any other behavioral or data differences of the
        provider itself (which is valid during processing, but not strictly interpreting results)."""
        workspace_version = int(schema_def.ProviderStateSchema().major_version)
        return (workspace_version - 1) + cls.__distribution_version__

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
        start = datetime.datetime.now(tz=datetime.UTC)

        last_updated = None
        current_state = self.read_state()
        if current_state and not current_state.stale:
            last_updated = current_state.timestamp

        stale = False
        if self.runtime_cfg.import_results_enabled:
            urls, count, start = self._fetch_or_use_results_archive()
            stale = True
        else:
            urls, count = self.update(last_updated=last_updated)

        if count > 0 or stale:
            self.workspace.record_state(
                stale=stale,
                version=self.version(),
                distribution_version=self.distribution_version(),
                timestamp=start,
                urls=urls,
                store=self.runtime_cfg.result_store.value,
            )
        else:
            self.logger.debug("skipping recording of workspace state (no new results found)")

    def _fetch_or_use_results_archive(self) -> tuple[list[str], int, datetime.datetime]:
        listing_doc = self._fetch_listing_document()
        latest_entry = listing_doc.latest_entry(schema_version=self.distribution_version())
        if not latest_entry:
            raise RuntimeError("no listing entry found")
        timestamp = None
        if self.runtime_cfg.skip_newer_archive_check or self._has_newer_archive(latest_entry=latest_entry):
            self.logger.info("fetching latest listing")
            self._prep_workspace_from_listing_entry(entry=latest_entry)
        else:
            # Update the timestamp of the state to the latest entry's built time
            self.logger.info("using existing listing and updating timestamp")
            timestamp = datetime.datetime.fromisoformat(latest_entry.built)

        state = self.workspace.state()
        if not timestamp:
            timestamp = state.timestamp
        return state.urls, state.result_count(self.workspace.path), timestamp

    def _fetch_listing_document(self) -> distribution.ListingDocument:
        url = self.runtime_cfg.import_url(provider_name=self.name())
        resp = http.get(url, logger=self.logger)
        resp.raise_for_status()

        return distribution.ListingDocument.from_dict(resp.json())

    def _has_newer_archive(self, latest_entry: distribution.ListingEntry) -> bool:
        if not os.path.exists(self.workspace.metadata_path):
            return True

        state = self.workspace.state()
        if not state:
            return True

        if state.distribution_version != self.distribution_version():
            return True

        if not state.listing:
            return True

        # note: the checksum is the digest of the checksums file within the archive, which is in the form "algo:value"
        return f"{state.listing.algorithm}:{state.listing.digest}" != latest_entry.enclosed_checksum

    def _prep_workspace_from_listing_entry(self, entry: distribution.ListingEntry) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            unarchived_path = _fetch_listing_entry_archive(dest=temp_dir, entry=entry, logger=self.logger)

            temp_ws = workspace.Workspace(unarchived_path, self.name(), logger=self.logger, create=False)

            # validate that the workspace is in a good state
            temp_ws.validate_checksums()

            # then switch the existing workspace to the new one...
            # move the contents of the tmp dir to the workspace destination
            self.workspace.replace_results(temp_workspace=temp_ws)

    def run(self) -> None:
        self.logger.debug(f"using {self.workspace.path!r} as workspace")

        current_state = self.read_state()
        if self.runtime_cfg.import_results_enabled:
            if current_state and current_state.distribution_version != self.distribution_version():
                self.logger.warning(
                    f"provider distribution version has changed from {current_state.distribution_version} to {self.distribution_version()}",
                )
                self.logger.warning("clearing workspace to ensure consistency of existing results")
                self.workspace.clear()
        elif current_state and current_state.version != self.version():
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


def _fetch_listing_entry_archive(dest: str, entry: distribution.ListingEntry, logger: logging.Logger) -> str:
    archive_path = os.path.join(dest, os.path.basename(urlparse(entry.url, allow_fragments=False).path))

    # download the URL for the archive
    resp = http.get(entry.url, logger=logger, stream=True)
    resp.raise_for_status()
    logger.debug(f"downloading {entry.url} to {archive_path}")
    with open(archive_path, "wb") as fp:
        for chunk in resp.iter_content(chunk_size=None):
            fp.write(chunk)

    logger.debug(f"validating checksum for {archive_path}")
    hashMethod = hasher.Method.parse(entry.distribution_checksum)
    actual_labeled_digest = hashMethod.digest(archive_path)
    if actual_labeled_digest != entry.distribution_checksum:
        raise ValueError(f"archive checksum mismatch: {actual_labeled_digest} != {entry.distribution_checksum}")

    unarchive_path = os.path.join(dest, "unarchived")
    logger.debug(f"unarchiving {archive_path} to {unarchive_path}")
    archive.extract(archive_path, unarchive_path)

    return unarchive_path
