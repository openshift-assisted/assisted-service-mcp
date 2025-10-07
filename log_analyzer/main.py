#!/usr/bin/env python3
"""
Main entry point for the OpenShift Assisted Installer Log Analyzer.
"""
import argparse
import logging
import sys
import os
from typing import List, Optional

from .api_client import AssistedInstallerAPIClient
from .log_analyzer import LogAnalyzer
from .signatures import ALL_SIGNATURES, SignatureResult


def setup_logging(verbose: bool = False) -> None:
    """Set up colored logging."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)-10s %(message)s"))

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(handler)


def analyze_cluster(
    cluster_id: str,
    auth_token: Optional[str] = None,
    specific_signatures: Optional[List[str]] = None,
) -> List[SignatureResult]:
    """
    Analyze a cluster's logs.

    Args:
        cluster_id: UUID of the cluster to analyze
        auth_token: Authentication token for API access
        specific_signatures: List of specific signature names to run (None for all)

    Returns:
        List of SignatureResult objects
    """
    logger = logging.getLogger(__name__)

    # Initialize API client
    logger.info("Analyzing cluster: %s", cluster_id)
    api_client = AssistedInstallerAPIClient(auth_token=auth_token)

    try:
        # Download logs
        logs_archive = api_client.download_logs(cluster_id)

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


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze OpenShift Assisted Installer cluster logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("cluster_id", nargs="?", help="UUID of the cluster to analyze")

    parser.add_argument(
        "--auth-token",
        default=os.environ.get("OPENSHIFT_AUTH_TOKEN"),
        help="Authentication token for API access (or set OPENSHIFT_AUTH_TOKEN env var)",
    )

    parser.add_argument(
        "--api-url",
        default="https://api.openshift.com",
        help="Base URL for the OpenShift API (default: %(default)s)",
    )

    parser.add_argument(
        "--signatures",
        nargs="+",
        help="Specific signatures to run (default: all signatures)",
    )

    parser.add_argument(
        "--list-signatures",
        action="store_true",
        help="List available signatures and exit",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.list_signatures:
        print("Available signatures:")
        for signature in ALL_SIGNATURES:
            print(f"  - {signature.__name__}")
        return 0

    if not args.cluster_id:
        parser.error("cluster_id is required unless using --list-signatures")

    try:
        # Analyze the cluster
        results = analyze_cluster(
            cluster_id=args.cluster_id,
            auth_token=args.auth_token,
            specific_signatures=args.signatures,
        )

        # Print results
        print_results(results)

        return 0

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        logging.getLogger(__name__).error("Analysis failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
