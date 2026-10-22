"""Hosted scheduled dispatch, deadline sweep and recovery of queued API jobs."""
from peaso.worker import Worker
from peaso.storage.runtime import WorkflowDispatcher
from peaso.storage.sqlite import SQLiteStore


def handler(event, context):
    worker = Worker("collector")
    worker.store.expire()
    if hasattr(worker.store, "reconcile_admissions"):
        worker.store.reconcile_admissions()
    created = worker.schedule_tick()
    dispatcher = WorkflowDispatcher(store=worker.store)
    dispatched = 0
    if hasattr(worker.store, "queued_jobs"):
        for job in worker.store.queued_jobs():
            if dispatcher.dispatch(job["tenant"], worker.store.public_job(job)):
                dispatched += 1
    return {"scheduled": len(created), "queued_dispatches": dispatched}
