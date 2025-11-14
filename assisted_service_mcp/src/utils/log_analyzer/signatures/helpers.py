"""
Helper functions for signature analysis.
"""

import re
from typing import Any, Generator, Callable, Dict


def operator_statuses_from_controller_logs(
    controller_log: str, include_empty: bool = False
):
    operator_regex = re.compile(r"Operator ([a-z\-]+), statuses: \[(.*)\].*")
    conditions_regex = re.compile(r"\{(.+?)\}")
    condition_regex = re.compile(
        r"([A-Za-z]+) (False|True) ([0-9a-zA-Z\-]+ [0-9a-zA-Z\:]+ [0-9a-zA-Z\-\+]+ [A-Z]+) (.*)"
    )
    operator_statuses = {}

    for operator_name, operator_status in operator_regex.findall(controller_log):
        if include_empty:
            operator_statuses[operator_name] = {}
        operator_conditions = operator_statuses.setdefault(operator_name, {})
        for operator_conditions_raw in conditions_regex.findall(operator_status):
            for (
                condition_name,
                condition_result,
                condition_timestamp,
                condition_reason,
            ) in condition_regex.findall(operator_conditions_raw):
                operator_conditions[condition_name] = {
                    "result": condition_result == "True",
                    "timestamp": condition_timestamp,
                    "reason": condition_reason,
                }

    return operator_statuses


def condition_has_result(
    operator_conditions, expected_condition_name: str, expected_condition_result: bool
) -> bool:
    return any(
        condition_values["result"] == expected_condition_result
        for condition_name, condition_values in operator_conditions.items()
        if condition_name == expected_condition_name
    )


def filter_operators(
    operator_statuses,
    required_conditions,
    aggregation_function: Callable[[Generator[Any, None, None]], bool],
):
    return {
        operator_name: operator_conditions
        for operator_name, operator_conditions in operator_statuses.items()
        if aggregation_function(
            condition_has_result(
                operator_conditions, required_condition_name, expected_condition_result
            )
            for required_condition_name, expected_condition_result in required_conditions
        )
    }
