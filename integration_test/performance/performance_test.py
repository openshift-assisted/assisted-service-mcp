#!/usr/bin/env python3
"""
Performance test script for the Assisted Service MCP Server.

This script simulates multiple concurrent users making requests to test
server performance, throughput, and behavior under load.
"""

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional, TypedDict

import aiohttp


class TestScenario(TypedDict):
    """Test scenario configuration."""

    name: str
    weight: float
    method: str
    params: Dict[str, Any]


class ToolStats(TypedDict):
    """Tool performance statistics."""

    total: int
    success: int
    avg_time: List[float]


@dataclass
class TestResult:
    """Result of a single test request."""

    success: bool
    response_time: float
    status_code: Optional[int]
    error_message: Optional[str]
    tool_name: str
    user_id: int


@dataclass
class ResponseTimeStats:
    """Response time statistics."""

    average: float
    min: float
    max: float
    p95: float
    p99: float


@dataclass
class TestSummary:
    """Summary statistics for the performance test."""

    total_requests: int
    successful_requests: int
    failed_requests: int
    response_times: ResponseTimeStats
    requests_per_second: float
    total_duration: float
    error_rate: float


class MCPPerformanceTester:
    """Performance tester for MCP server."""

    def __init__(self, base_url: str, auth_token: str, auth_type: str = "bearer"):
        """Initialize the performance tester with server configuration."""
        self.base_url = base_url
        self.auth_token = auth_token
        self.auth_type = auth_type.lower()
        self.results: List[TestResult] = []

        # Test scenarios with different tools and parameters
        self.test_scenarios: List[TestScenario] = [
            {
                "name": "list_clusters",
                "weight": 0.5,  # 50% of requests
                "method": "tools/call",
                "params": {"name": "list_clusters", "arguments": {}},
            },
            {
                "name": "list_versions",
                "weight": 0.3,  # 30% of requests
                "method": "tools/call",
                "params": {"name": "list_versions", "arguments": {}},
            },
            {
                "name": "list_operator_bundles",
                "weight": 0.2,  # 20% of requests
                "method": "tools/call",
                "params": {"name": "list_operator_bundles", "arguments": {}},
            },
        ]

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on auth type."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
        }

        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "offline-token":
            headers["OCM-Offline-Token"] = self.auth_token
        else:
            raise ValueError(f"Unknown auth type: {self.auth_type}")

        return headers

    def select_scenario(self, request_id: int) -> TestScenario:
        """Select a test scenario based on weights."""
        # Simple round-robin selection weighted by scenario weights
        cumulative_weight = 0.0
        selector = (request_id * 0.618033988749) % 1  # Golden ratio for distribution

        for scenario in self.test_scenarios:
            cumulative_weight += scenario["weight"]
            if selector <= cumulative_weight:
                return scenario

        # Fallback to first scenario
        return self.test_scenarios[0]

    async def make_request(
        self, session: aiohttp.ClientSession, user_id: int, request_id: int
    ) -> TestResult:
        """Make a single request to the MCP server."""
        scenario = self.select_scenario(request_id)

        payload = {
            "jsonrpc": "2.0",
            "id": f"user-{user_id}-req-{request_id}",
            "method": scenario["method"],
            "params": scenario["params"],
        }

        start_time = time.time()

        try:
            async with session.post(
                self.base_url,
                json=payload,
                headers=self.get_auth_headers(),
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                await response.text()  # Read response body
                response_time = time.time() - start_time

                return TestResult(
                    success=response.status == 200,
                    response_time=response_time,
                    status_code=response.status,
                    error_message=(
                        None if response.status == 200 else f"HTTP {response.status}"
                    ),
                    tool_name=scenario["name"],
                    user_id=user_id,
                )

        except asyncio.TimeoutError:
            return TestResult(
                success=False,
                response_time=time.time() - start_time,
                status_code=None,
                error_message="Request timeout",
                tool_name=scenario["name"],
                user_id=user_id,
            )
        except Exception as e:
            return TestResult(
                success=False,
                response_time=time.time() - start_time,
                status_code=None,
                error_message=str(e),
                tool_name=scenario["name"],
                user_id=user_id,
            )

    async def simulate_user(
        self,
        session: aiohttp.ClientSession,
        user_id: int,
        requests_per_user: int,
        delay_between_requests: float,
    ) -> List[TestResult]:
        """Simulate a single user making multiple requests."""
        user_results = []

        for request_id in range(requests_per_user):
            result = await self.make_request(session, user_id, request_id)
            user_results.append(result)

            # Add delay between requests from the same user
            if delay_between_requests > 0 and request_id < requests_per_user - 1:
                await asyncio.sleep(delay_between_requests)

        return user_results

    async def run_test(
        self,
        concurrent_users: int,
        requests_per_user: int,
        delay_between_requests: float = 0.1,
    ) -> TestSummary:
        """Run the performance test with specified parameters."""
        print("Starting performance test:")
        print(f"  - Concurrent users: {concurrent_users}")
        print(f"  - Requests per user: {requests_per_user}")
        print(f"  - Total requests: {concurrent_users * requests_per_user}")
        print(f"  - Delay between requests: {delay_between_requests}s")
        print(f"  - Server: {self.base_url}")
        print(f"  - Auth type: {self.auth_type}")
        print()

        start_time = time.time()

        # Create aiohttp session with connection limits
        connector = aiohttp.TCPConnector(
            limit=concurrent_users * 2,  # Connection pool size
            limit_per_host=concurrent_users * 2,
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks for all users
            tasks = [
                self.simulate_user(
                    session, user_id, requests_per_user, delay_between_requests
                )
                for user_id in range(concurrent_users)
            ]

            # Run all user simulations concurrently
            user_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Flatten results
            self.results = []
            for user_result in user_results:
                if isinstance(user_result, Exception):
                    print(f"User simulation failed: {user_result}")
                else:
                    # Type assertion: user_result is List[TestResult] after exception check
                    assert isinstance(user_result, list)
                    self.results.extend(user_result)

        end_time = time.time()
        total_duration = end_time - start_time

        return self.calculate_summary(total_duration)

    def calculate_summary(self, total_duration: float) -> TestSummary:
        """Calculate performance test summary statistics."""
        if not self.results:
            raise ValueError("No results to analyze")

        successful_results = [r for r in self.results if r.success]
        failed_results = [r for r in self.results if not r.success]

        response_times = [r.response_time for r in self.results]

        return TestSummary(
            total_requests=len(self.results),
            successful_requests=len(successful_results),
            failed_requests=len(failed_results),
            response_times=ResponseTimeStats(
                average=statistics.mean(response_times),
                min=min(response_times),
                max=max(response_times),
                p95=(
                    statistics.quantiles(response_times, n=20)[18]
                    if len(response_times) > 1
                    else response_times[0]
                ),
                p99=(
                    statistics.quantiles(response_times, n=100)[98]
                    if len(response_times) > 1
                    else response_times[0]
                ),
            ),
            requests_per_second=len(self.results) / total_duration,
            total_duration=total_duration,
            error_rate=len(failed_results) / len(self.results) * 100,
        )

    def print_detailed_results(self, summary: TestSummary) -> None:
        """Print detailed test results."""
        print("=" * 60)
        print("PERFORMANCE TEST RESULTS")
        print("=" * 60)
        print(f"Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        print("SUMMARY STATISTICS:")
        print(f"  Total Duration:        {summary.total_duration:.2f} seconds")
        print(f"  Total Requests:        {summary.total_requests}")
        print(f"  Successful Requests:   {summary.successful_requests}")
        print(f"  Failed Requests:       {summary.failed_requests}")
        print(f"  Success Rate:          {(100 - summary.error_rate):.2f}%")
        print(f"  Error Rate:            {summary.error_rate:.2f}%")
        print(f"  Requests/Second:       {summary.requests_per_second:.2f}")
        print()

        print("RESPONSE TIME STATISTICS:")
        print(f"  Average:               {summary.response_times.average:.3f}s")
        print(f"  Minimum:               {summary.response_times.min:.3f}s")
        print(f"  Maximum:               {summary.response_times.max:.3f}s")
        print(f"  95th Percentile:       {summary.response_times.p95:.3f}s")
        print(f"  99th Percentile:       {summary.response_times.p99:.3f}s")
        print()

        # Tool breakdown
        tool_stats: Dict[str, ToolStats] = {}
        for result in self.results:
            if result.tool_name not in tool_stats:
                tool_stats[result.tool_name] = {
                    "total": 0,
                    "success": 0,
                    "avg_time": [],
                }
            tool_stats[result.tool_name]["total"] += 1
            if result.success:
                tool_stats[result.tool_name]["success"] += 1
            tool_stats[result.tool_name]["avg_time"].append(result.response_time)

        print("TOOL PERFORMANCE BREAKDOWN:")
        for tool, stats in tool_stats.items():
            success_rate = (stats["success"] / stats["total"]) * 100
            avg_time = statistics.mean(stats["avg_time"])
            print(
                f"  {tool:<25} {stats['total']:>6} requests, {success_rate:>6.1f}% success, {avg_time:>8.3f}s avg"
            )

        # Error analysis
        if summary.failed_requests > 0:
            print()
            print("ERROR ANALYSIS:")
            error_counts: Dict[str, int] = {}
            for result in self.results:
                if not result.success and result.error_message:
                    error_counts[result.error_message] = (
                        error_counts.get(result.error_message, 0) + 1
                    )

            for error, count in sorted(
                error_counts.items(), key=lambda x: x[1], reverse=True
            ):
                print(f"  {error:<40} {count:>6} occurrences")


async def main() -> None:
    """Run the performance test."""
    parser = argparse.ArgumentParser(description="MCP Server Performance Test")
    parser.add_argument(
        "--url",
        default="http://localhost:8000/mcp",
        help="MCP server URL (default: http://localhost:8000/mcp)",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Authentication token (bearer token or offline token)",
    )
    parser.add_argument(
        "--auth-type",
        choices=["bearer", "offline-token"],
        default="bearer",
        help="Authentication type (default: bearer)",
    )
    parser.add_argument(
        "--users", type=int, default=10, help="Number of concurrent users (default: 10)"
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=5,
        help="Number of requests per user (default: 5)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between requests from same user in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save test results to a JSON file (default: False)",
    )

    args = parser.parse_args()

    tester = MCPPerformanceTester(args.url, args.token, args.auth_type)

    try:
        summary = await tester.run_test(args.users, args.requests, args.delay)
        tester.print_detailed_results(summary)

        # Save results to JSON for further analysis (only if requested)
        if args.save_results:
            results_file = f"performance_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "summary": {
                            "total_requests": summary.total_requests,
                            "successful_requests": summary.successful_requests,
                            "failed_requests": summary.failed_requests,
                            "average_response_time": summary.response_times.average,
                            "min_response_time": summary.response_times.min,
                            "max_response_time": summary.response_times.max,
                            "p95_response_time": summary.response_times.p95,
                            "p99_response_time": summary.response_times.p99,
                            "requests_per_second": summary.requests_per_second,
                            "total_duration": summary.total_duration,
                            "error_rate": summary.error_rate,
                        },
                        "raw_results": [
                            {
                                "success": r.success,
                                "response_time": r.response_time,
                                "status_code": r.status_code,
                                "error_message": r.error_message,
                                "tool_name": r.tool_name,
                                "user_id": r.user_id,
                            }
                            for r in tester.results
                        ],
                    },
                    f,
                    indent=2,
                )

            print(f"\nDetailed results saved to: {results_file}")
        else:
            print("\nTo save results to a file, use the --save-results flag")

    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
