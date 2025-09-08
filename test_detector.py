#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the Stormshield SNS Firewall Rule Analyzer.
"""

import unittest
import io
import logging
from unittest.mock import patch

# Temporarily add the current directory to the path to import the script
import sys
sys.path.insert(0, '.')

from detect_stormshield_anomalies import (
    ObjectResolver,
    load_rules,
    run_analysis,
    _parse_ip_token,
    _parse_port_token
)

# Suppress logging during tests
logging.disable(logging.CRITICAL)

# Define the new header format for reusability in tests
NEW_HEADER = "#type_slot,#rule_name,#state,#action,#from_src,#to_dest,#service,#proto,#comment\n"

class TestParsingAndNormalization(unittest.TestCase):
    """Tests for parsing, normalization, and object resolution with the new format."""

    def test_object_resolver(self):
        objects_csv = "name;type;value\nhost_a;host;1.1.1.1/32"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(str(resolver.resolve_ip_group("host_a")[0]), "1.1.1.1/32")

    def test_circular_dependency(self):
        objects_csv = "name;type;value\ngrp_a;group;grp_b\ngrp_b;group;grp_a"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            with self.assertRaises(ValueError):
                resolver.resolve_ip_group("grp_a")

    def test_load_rules_new_format(self):
        rules_csv = (
            NEW_HEADER +
            "rule,Rule1,on,allow,1.1.1.1,2.2.2.2,80,tcp,Test rule 1\n" +
            "separator,,,,,,,,\n" + # Should be skipped
            "rule,Rule2,off,deny,any,any,any,any,Test rule 2\n"
        )
        with patch('builtins.open', return_value=io.StringIO(rules_csv)):
            resolver = ObjectResolver(None)
            active, disabled, total = load_rules("rules.csv", resolver, "both")

            self.assertEqual(total, 3)
            self.assertEqual(len(active), 1)
            self.assertEqual(len(disabled), 1)

            self.assertEqual(active[0].rule_id, "Rule1")
            self.assertEqual(active[0].position, 1) # First actual rule
            self.assertEqual(disabled[0].rule_id, "Rule2")
            self.assertTrue(active[0].enabled)
            self.assertFalse(disabled[0].enabled)


class TestAnalysisEngineNewFormat(unittest.TestCase):
    """High-level tests for the main analysis engine with the new CSV format."""

    def run_test_on_rules(self, rules_data, objects_data="name;type;value\n"):
        """Helper to run analysis on given CSV data."""
        with patch('builtins.open') as mock_open:
            def side_effect(path, *args, **kwargs):
                if path == "rules.csv":
                    return io.StringIO(rules_data)
                if path == "objects.csv":
                    return io.StringIO(objects_data)
                return unittest.mock.mock_open(read_data="").return_value
            mock_open.side_effect = side_effect

            resolver = ObjectResolver("objects.csv" if objects_data else None)
            active_rules, _, _ = load_rules("rules.csv", resolver, "both")
            results = run_analysis(active_rules)
            return results

    def test_shadowed_same_action(self):
        rules = (
            NEW_HEADER +
            "rule,R1,on,allow,any,any,any,any,\n" +
            "rule,R2,on,allow,10.0.0.1,any,any,any,"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")
        self.assertEqual(results.shadowed_same_action[0]['shadowed_by'], "R1")

    def test_shadowed_conflict(self):
        rules = (
            NEW_HEADER +
            "rule,R1,on,deny,10.0.0.0/8,any,any,any,\n" +
            "rule,R2,on,allow,10.0.0.0/16,any,any,any,"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_conflict), 1)
        self.assertEqual(results.shadowed_conflict[0]['rule'], "R2")

    def test_duplicate(self):
        rules = (
            NEW_HEADER +
            "rule,R1,on,allow,1.1.1.1,2.2.2.2,80,tcp,\n" +
            "rule,R2,on,allow,1.1.1.1,2.2.2.2,80,tcp,"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.duplicates), 1)
        self.assertEqual(results.duplicates[0]['rule'], "R2")

    def test_conflict(self):
        rules = (
            NEW_HEADER +
            "rule,R1,on,allow,10.0.0.0/24,any,80,tcp,\n" +
            "rule,R2,on,deny,10.0.0.0/16,any,80,tcp,"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.conflicts), 1)
        self.assertEqual(results.conflicts[0]['rule_a'], "R2")
        self.assertEqual(results.conflicts[0]['rule_b'], "R1")

    def test_no_anomaly_between_slots(self):
        # This test needs to be adapted as slot is now inferred
        rules = (
            "#type_slot,#rule_name,#state,#action,#from_src,#to_dest,#service,#proto,#comment,#nat_to_target\n" +
            "rule,R1,on,allow,any,any,any,any,,,\n" +  # This is a filter rule
            "rule,R2,on,snat,10.0.0.1,any,any,any,,some_nat_host" # This is a NAT rule
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_same_action), 0)
        self.assertEqual(len(results.shadowed_conflict), 0)
        self.assertEqual(len(results.conflicts), 0)
        self.assertEqual(len(results.duplicates), 0)

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
