"""Storage backend abstractions for checkpoint artifacts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
import shutil
from typing import Union


class StorageBackend(ABC):
    """Abstract storage backend for checkpoint artifacts."""

    @abstractmethod
    def save(self, local_path: Path, artifact_key: str) -> str:
        """Persist local_path under artifact_key and return the storage URI."""

    @abstractmethod
    def load(self, artifact_key: str, local_path: Path) -> None:
        """Fetch artifact_key and write it to local_path."""

    @abstractmethod
    def exists(self, artifact_key: str) -> bool:
        """Return True if the artifact exists in storage."""


class LocalBackend(StorageBackend):
    """Local filesystem storage backend."""

    def __init__(self, base_dir: Union[str, Path]):
        """Initialise the local storage root."""
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save(self, local_path: Path, artifact_key: str) -> str:
        """Copy a local artifact into the backend, protecting against path traversal."""
        source = Path(local_path)
        # Resolve destination and ensure it is within base_dir
        destination = (self.base_dir / artifact_key).resolve()
        self.base_dir.resolve()
        if not destination.is_relative_to(self.base_dir.resolve()):
            raise ValueError(f"Invalid artifact_key leads outside storage base directory: {artifact_key}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination:
            shutil.copy2(source, destination)
        return str(destination)

    def load(self, artifact_key: str, local_path: Path) -> None:
        """Copy an artifact from the backend into the local path."""
        source = self.base_dir / artifact_key
        destination = Path(local_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve():
            shutil.copy2(source, destination)

    def exists(self, artifact_key: str) -> bool:
        """Return True when the local artifact exists."""
        return (self.base_dir / artifact_key).exists()


class S3Backend(StorageBackend):
    """S3 storage backend. Requires boto3 and valid AWS credentials."""

    def __init__(self, bucket: str, prefix: str = ""):
        """Initialise the S3 bucket and key prefix."""
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""

    def save(self, local_path: Path, artifact_key: str) -> str:
        """Upload a local artifact to S3 and return its URI."""
        import boto3

        s3 = boto3.client("s3")
        object_key = f"{self.prefix}{artifact_key}"
        s3.upload_file(str(local_path), self.bucket, object_key)
        return f"s3://{self.bucket}/{object_key}"

    def load(self, artifact_key: str, local_path: Path) -> None:
        """Download an S3 artifact into a local path."""
        import boto3

        s3 = boto3.client("s3")
        object_key = f"{self.prefix}{artifact_key}"
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        s3.download_file(self.bucket, object_key, str(local_path))

    def exists(self, artifact_key: str) -> bool:
        """Return True when the S3 artifact exists."""
        import boto3
        from botocore.exceptions import ClientError

        s3 = boto3.client("s3")
        object_key = f"{self.prefix}{artifact_key}"
        try:
            s3.head_object(Bucket=self.bucket, Key=object_key)
            return True
        except ClientError:
            return False
