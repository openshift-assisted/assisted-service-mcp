#!/usr/bin/env python3
"""
Main entry point for the OpenShift Assisted Installer Log Analyzer.
"""
import logging
import json
from typing import List, Optional

from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    ClusterAnalyzer,
    LogAnalyzer,
)
from assisted_service_mcp.src.utils.log_analyzer.signatures import (
    ALL_SIGNATURES,
    SignatureResult,
    Signature,
)


async def analyze_cluster(
    cluster_id: str,
    api_client: InventoryClient,
    specific_signatures: Optional[List[str]] = None,
) -> List[SignatureResult]:
    """
    Analyze a cluster's logs.

    Args:
        cluster_id: UUID of the cluster to analyze
        api_client: Client to fetch log files with
        specific_signatures: List of specific signature names to run (None for all)

    Returns:
        List of SignatureResult objects
    """
    logger = logging.getLogger(__name__)

    # Initialize API client
    logger.info("Analyzing cluster: %s", cluster_id)

    try:
        # first call the api to get the cluster and check if logs are available
        cluster = await api_client.get_cluster(cluster_id)

        if cluster.logs_info != "completed":
            logger.info(
                "Logs are not available for cluster: %s\nDefaulting to signatures that don't require logs",
                cluster_id,
            )

            analyzer = ClusterAnalyzer()

            # Call events API to get the events and set the events in the analyzer
            events = await api_client.get_events(cluster_id)
            analyzer.set_cluster_events(json.loads(events))

            # Set the cluster metadata in the analyzer
            analyzer.set_cluster_metadata(cluster.to_dict())

            # Select signatures that don't require logs
            signatures_to_run = [
                sig for sig in ALL_SIGNATURES if sig.logs_required is False
            ]

        else:
            # Download logs
            logs_archive = await api_client.get_cluster_logs(cluster_id)

            # Initialize log analyzer
            analyzer = LogAnalyzer(logs_archive)

            # Add all signatures to the list to run
            signatures_to_run = ALL_SIGNATURES

        # If specific signatures are provided, filter the signatures to run
        if specific_signatures:
            signatures_to_run = filter_signatures(
                signatures_to_run, specific_signatures
            )

        # Run signatures
        results = []
        for signature_class in signatures_to_run:
            logger.debug("Running signature: %s", signature_class.__name__)
            try:
                signature = signature_class()
                result = signature.analyze(analyzer)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(
                    "Error running signature %s: %s", signature_class.__name__, e
                )

        return results

    except Exception as e:
        logger.error("Error analyzing cluster %s: %s", cluster_id, e)
        raise


def filter_signatures(
    signatures: List[type[Signature]], specific_signatures: List[str]
) -> List[type[Signature]]:
    """Filter signatures to run based on specific signatures."""
    logger = logging.getLogger(__name__)
    signature_classes = {sig.__name__: sig for sig in signatures}
    filtered_signatures = []
    for sig_name in specific_signatures:
        if sig_name in signature_classes:
            filtered_signatures.append(signature_classes[sig_name])
        else:
            logger.warning("Unknown signature: %s", sig_name)
    return filtered_signatures


def print_results(results: List[SignatureResult]) -> None:
    """Print analysis results to stdout."""
    if not results:
        print("No issues found in the cluster logs.")
        return

    print("OpenShift Assisted Installer Log Analysis")
    print("=" * 50)
    print()

    for result in results:
        print(result)
