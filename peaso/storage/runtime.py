"""Choose local or optional hosted adapters through explicit configuration."""
import os
from .sqlite import SQLiteStore
from .artifacts import FileArtifacts, S3Artifacts


def stores(settings):
    mode = os.getenv("PEASO_STORAGE", "sqlite")
    if mode == "sqlite":
        return SQLiteStore(settings.state_dir), FileArtifacts(settings.state_dir / "artifacts")
    if mode == "dynamodb":
        from .dynamodb import DynamoStore
        return DynamoStore(os.environ["PEASO_DYNAMODB_TABLE"]), S3Artifacts(os.environ["PEASO_ARTIFACT_BUCKET"], kms_key=os.getenv("PEASO_ARTIFACT_KMS_KEY"))
    raise ValueError("Unsupported storage adapter")


class WorkflowDispatcher:
    def __init__(self, arn=None, client=None):
        self.arn = arn or os.getenv("PEASO_WORKFLOW_ARN")
        self.client = client

    def dispatch(self, tenant, job):
        if not self.arn:
            return False
        if job.get('ai_enabled', True):
            # Gate the workflow before it can provision an analyzer, container,
            # pod or build that will run AI. Queued retries recheck current state.
            from peaso.server.config import Settings
            from peaso.ai.auth import require_local_codex
            settings = Settings()
            store, _ = stores(settings)
            try:
                require_local_codex(settings, store, job.get('ai_user_id', tenant))
            except Exception:
                return False
        if self.client is None:
            import boto3
            self.client = boto3.client("stepfunctions")
        import json
        import time
        now = int(time.time())
        try:
            self.client.start_execution(stateMachineArn=self.arn, name="scan-" + job["id"], input=json.dumps({"tenant_id": tenant, "scan_id": job["id"], "now_epoch": now, "lock_expires_at": now + 2100}))
            return True
        except self.client.exceptions.ExecutionAlreadyExists:
            return True
        except Exception:
            # A durable queued record is retried by the scheduler; no request secrets logged.
            return False
