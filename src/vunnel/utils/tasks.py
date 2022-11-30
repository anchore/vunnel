# pylint: skip-file

from datetime import datetime as dt
from enum import Enum

from anchore_engine.db import session_scope
from anchore_engine.subsys import logger
from anchore_enterprise.db.entities.feeds import Task


class TaskStatus(Enum):
    RUNNING = "running"
    FAILED = "failed"
    COMPLETED = "completed"


def _cleanup_pending_tasks_quiet(session):
    """
    Helper function for bulk updating all the tasks in `running` state to `failed`.
    Logs errors if the cleanup fails and moves on. Does not raise any exceptions

    :param session:
    :return:
    """
    if not session:
        return

    try:
        session.query(Task).filter(Task.status == TaskStatus.RUNNING.value).update(
            {
                Task.status: TaskStatus.FAILED.value,
                Task.result: {"error": "task aborted due to service restart"},
            },
            synchronize_session=False,
        )
    except Exception:
        logger.debug_exception("Ignoring error cleaning up incomplete tasks")


def create_feed_sync_task(cleanup=True):
    task_id = None
    try:
        with session_scope() as session:
            if cleanup:
                _cleanup_pending_tasks_quiet(session)

            task = Task(
                task_type="FeedSyncTask",
                status=TaskStatus.RUNNING.value,
                start_time=dt.utcnow(),
                started_by="system",
            )
            session.add(task)
            session.flush()
            task_id = task.task_id
    except Exception:
        logger.exception("Failed to initialize feed sync task")

    return task_id


def create_driver_execution_task(feed_id, driver_id, parent_task_id):
    task_id = None
    try:
        with session_scope() as session:
            task = Task(
                task_type="DriverExecutionTask",
                feed_id=feed_id,
                driver_id=driver_id,
                status=TaskStatus.RUNNING.value,
                start_time=dt.utcnow(),
                started_by="system",
                parent_task_id=parent_task_id,
            )
            session.add(task)
            session.flush()
            task_id = task.task_id
    except Exception:
        logger.exception("Failed to initialize driver execution task for {}/{}".format(feed_id, driver_id))

    return task_id


def create_workspace_config_task(parent_task_id=None):
    task_id = None
    try:
        with session_scope() as session:
            task = Task(
                task_type="WorkspaceConfigTask",
                status=TaskStatus.RUNNING.value,
                start_time=dt.utcnow(),
                started_by="system",
                parent_task_id=parent_task_id,
            )
            session.add(task)
            session.flush()
            task_id = task.task_id
    except Exception:
        logger.exception("Failed to initialize workspace configuration task")

    return task_id


def update_task(task_id, status, result, quiet=True):
    error = None
    try:
        with session_scope() as session:
            task = session.query(Task).filter(Task.task_id == task_id).one()
            task.status = status
            task.result = result
            task.end_time = dt.utcnow()
            session.flush()
    except Exception as e:
        error = e
        logger.warn("Failed to update task {} due to {}".format(task_id, str(e)))

    if not quiet and error:
        raise error
