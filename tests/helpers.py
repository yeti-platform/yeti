import time
import unittest
from typing import Any, Optional

from core.database_arango import ArangoYetiConnector
from core.schemas import observable


class YetiTestCase(unittest.TestCase):
    def check_observables(self, expected_values: list[dict[str, Any]]):
        """Checks observables against a list of expected values.

        Args:
            expected_values: A list of dictionaries, each containing expected values
                for 'value', 'type', and 'tags' attributes.
        """
        time.sleep(1)
        observables = observable.Observable.filter({"value": ""})
        observable_obj, _ = observables
        observable_obj = sorted(observable_obj, key=lambda x: x.value)
        expected_values = sorted(expected_values, key=lambda x: x["value"])

        self.assertEqual(len(observable_obj), len(expected_values))

        for obs, expected_value in zip(observable_obj, expected_values):
            self.assertEqual(obs.value, expected_value["value"])
            self.assertEqual(obs.type, expected_value["type"])
            self.assertEqual(set(obs.tags.keys()), expected_value["tags"])

    def check_neighbors(
        self,
        indicator: Optional[ArangoYetiConnector],
        expected_neighbor_values: list[str],
    ):
        """Checks an indicator's neighbors against a list of expected values.

        Args:
            indicator: The indicator.Query object to use for neighbor comparison.
            expected_neighbor_values: A list of expected neighbor values.
        """
        if indicator is None:
            self.assertIsNone(indicator, "Indicator not found in database")
            return

        indicator_neighbors = [
            o.value
            for o in indicator.neighbors()[0].values()
            if isinstance(o, observable.Observable)
        ]

        for expected_value in expected_neighbor_values:
            self.assertIn(expected_value, indicator_neighbors)
