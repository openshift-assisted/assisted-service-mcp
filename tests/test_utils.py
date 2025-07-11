"""
Test utilities for creating test objects.
"""

from typing import Optional
from assisted_service_client import models


def create_test_cluster(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    cluster_id: str = "test-cluster-id",
    name: str = "test-cluster",
    openshift_version: str = "4.18.2",
    status: str = "ready",
    status_info: str = "Cluster is ready for installation",
    created_at: str = "2023-01-01T00:00:00Z",
    updated_at: str = "2023-01-01T00:00:00Z",
) -> models.Cluster:
    """Create a test cluster object with default values."""
    return models.Cluster(
        kind="Cluster",
        id=cluster_id,
        href=f"/api/assisted-install/v2/clusters/{cluster_id}",
        name=name,
        openshift_version=openshift_version,
        status=status,
        status_info=status_info,
        image_info=models.ImageInfo(),
        created_at=created_at,
        updated_at=updated_at,
    )


def create_test_installing_cluster(
    cluster_id: str = "test-cluster-id",
) -> models.Cluster:
    """Create a test cluster object with installing status."""
    return create_test_cluster(
        cluster_id=cluster_id,
        status="installing",
        status_info="Cluster installation is in progress",
    )


def create_test_host(
    host_id: str = "test-host-id",
    status: str = "known",
    status_info: str = "Host is ready for installation",
    role: Optional[str] = None,
) -> models.Host:
    """Create a test host object with default values."""
    return models.Host(
        kind="Host",
        id=host_id,
        href=f"/api/assisted-install/v2/hosts/{host_id}",
        status=status,
        status_info=status_info,
        role=role,
    )


def create_test_infra_env(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    infra_env_id: str = "test-infraenv-id",
    name: str = "test-infraenv",
    infra_env_type: str = "full-iso",
    cluster_id: Optional[str] = None,
    created_at: str = "2023-01-01T00:00:00Z",
    updated_at: str = "2023-01-01T00:00:00Z",
) -> models.InfraEnv:
    """Create a test infrastructure environment object with default values."""
    return models.InfraEnv(
        kind="InfraEnv",
        id=infra_env_id,
        href=f"/api/assisted-install/v2/infra-envs/{infra_env_id}",
        name=name,
        type=infra_env_type,
        cluster_id=cluster_id,
        created_at=created_at,
        updated_at=updated_at,
    )


def create_test_presigned_url(
    url: str = "https://example.com/presigned-url",
    expires_at: Optional[str] = "2023-12-31T23:59:59Z",
) -> models.PresignedUrl:
    """Create a test presigned URL object with default values."""
    return models.PresignedUrl(
        url=url,
        expires_at=expires_at,
    )
