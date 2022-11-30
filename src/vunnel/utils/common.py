# pylint: skip-file

import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from operator import itemgetter
from typing import Any, Dict, List

from anchore_engine.configuration.localconfig import get_config
from anchore_engine.subsys import logger
from anchore_enterprise.services.feeds.drivers import tasks

workspace_dir = "/tmp/feeds_workspace"
drivers_dir = "drivers"


def init_workspace(local_workspace="/tmp/feeds_workspace"):

    global workspace_dir

    if local_workspace:
        workspace_dir = local_workspace

    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)


def configure_workspace(feed_sync_task_id=None):
    global workspace_dir

    # setup pre-loaded workspace if drivers directory does not exist
    if not os.path.exists(os.path.join(workspace_dir, drivers_dir)):
        config = get_config().get("services", {}).get("feeds", {})
        enable_preload = str(config.get("workspace_preload", {}).get("enabled", True)).lower() in ["true", "t"]

        if enable_preload:
            task_id = tasks.create_workspace_config_task(parent_task_id=feed_sync_task_id)
            try:
                preload_file = config.get("workspace_preload", {}).get("workspace_preload_file", "/workspace_preload/data.tar.gz")
                _extract(preload_file, workspace_dir)
                tasks.update_task(
                    task_id,
                    tasks.TaskStatus.COMPLETED.value,
                    {"message": "Configured {} using pre-loaded workspace file {}".format(workspace_dir, preload_file)},
                )
            except Exception as e:
                tasks.update_task(task_id, tasks.TaskStatus.FAILED.value, {"error": str(e)})
                raise e


def _extract(compressed, destination):
    logger.info("Extracting pre-loaded workspace file {} to {}".format(compressed, destination))
    subprocess.check_call(["tar", "-x", "-z", "-f", compressed, "-C", destination])


def remove_driver_workspace(driver):
    global workspace_dir

    driver_ws = os.path.join(workspace_dir, drivers_dir, driver)

    if os.path.exists(driver_ws):
        shutil.rmtree(driver_ws)


def init_driver_workspace(driver):
    global workspace_dir

    driver_ws = os.path.join(workspace_dir, drivers_dir, driver)
    if not os.path.exists(driver_ws):
        logger.info("Setting up driver workspace for {}".format(driver))
        config = get_config().get("services", {}).get("feeds", {})
        enable_preload = str(config.get("workspace_preload", {}).get("enabled", True)).lower() in ["true", "t"]

        if enable_preload:
            try:
                preload_file = config.get("workspace_preload", {}).get("workspace_preload_file", "/workspace_preload/data.tar.gz")
                preload_driver = "{}/{}".format(drivers_dir, driver)
                logger.debug("Extracting {} from {} to {}".format(preload_driver, preload_file, workspace_dir))
                subprocess.check_call(
                    [
                        "tar",
                        "-C",
                        workspace_dir,
                        "-x",
                        "-z",
                        "-f",
                        preload_file,
                        preload_driver,
                    ]
                )
            except:
                logger.debug_exception(
                    "Ignoring error setting up driver workspace for {}. Initializing empty workspace".format(driver)
                )
                os.makedirs(driver_ws)
        else:
            os.makedirs(driver_ws)

    return driver_ws


severity_order = {
    "Unknown": 0,
    "Negligible": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}

vulnerability_element = {
    "Vulnerability": {
        "Severity": None,
        "NamespaceName": None,
        "FixedIn": [],
        "Link": None,
        "Description": "",
        "Metadata": {},
        "Name": None,
        "CVSS": [],
    }
}


def order_payload(payload, feed_type):
    if payload and feed_type:
        if (
            feed_type == "vulnerabilities"
            and "Vulnerability" in payload
            and "FixedIn" in payload["Vulnerability"]
            and payload["Vulnerability"]["FixedIn"]
        ):
            payload["Vulnerability"]["FixedIn"].sort(key=(itemgetter("Name", "Version")))
        elif feed_type == "packages":
            for content in payload.values():
                for key, value in content.items():
                    if isinstance(value, list):
                        value.sort()
        else:
            pass

    return payload


@dataclass
class FixedIn:
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.

    """

    Name: str
    NamespaceName: str
    VersionFormat: str
    Version: str


@dataclass
class CVSSBaseMetrics:
    base_score: float
    exploitability_score: float
    impact_score: float
    base_severity: str


@dataclass
class CVSS:
    version: str
    vector_string: str
    base_metrics: CVSSBaseMetrics
    status: str


@dataclass
class Vulnerability:
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """

    Name: str
    NamespaceName: str
    Description: str
    Severity: str
    Link: str
    CVSS: List[CVSS]
    FixedIn: List[FixedIn]
    Metadata: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self):
        return {"Vulnerability": asdict(self)}
