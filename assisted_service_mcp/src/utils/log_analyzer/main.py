#!/usr/bin/env python3
"""
Main entry point for the OpenShift Assisted Installer Log Analyzer.
"""
import logging
from typing import List, Optional

from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient

from .log_analyzer import LogAnalyzer
from .signatures import ALL_SIGNATURES, SignatureResult


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
        # Download logs
        logs_archive = await api_client.get_cluster_logs(cluster_id)

        # Initialize log analyzer
        log_analyzer = LogAnalyzer(logs_archive)

        # Determine which signatures to run
        signatures_to_run = ALL_SIGNATURES
        if specific_signatures:
            signature_classes = {sig.__name__: sig for sig in ALL_SIGNATURES}
            signatures_to_run = []
            for sig_name in specific_signatures:
                if sig_name in signature_classes:
                    signatures_to_run.append(signature_classes[sig_name])
                else:
                    logger.warning("Unknown signature: %s", sig_name)

        # Run signatures
        results = []
        for signature_class in signatures_to_run:
            logger.debug("Running signature: %s", signature_class.__name__)
            try:
                signature = signature_class()
                result = signature.analyze(log_analyzer)
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
