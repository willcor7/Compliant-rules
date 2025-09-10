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
)

# Suppress logging during tests
logging.disable(logging.CRITICAL)

# --- Test Data ---
RULES_HEADER = "#type_slot,rule_name,state,action,from_src,to_dest,service,proto,comment,nat_to_target\n"
OBJECTS_HEADER = "#type,name,begin,end,beginv6,endv6,beginmac,endmac,comment\n"

class TestParsing(unittest.TestCase):
    """Tests for parsing the new 9-column object format."""

    def test_object_host(self):
        objects_csv = OBJECTS_HEADER + "host,my_host,1.2.3.4,,,,,\n"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy.csv")
            self.assertEqual(str(resolver.resolve_ip_group("my_host")[0]), "1.2.3.4/32")

    def test_object_network(self):
        objects_csv = OBJECTS_HEADER + "network,my_net,10.0.0.0,255.255.255.0,,,,\n"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy.csv")
            self.assertEqual(str(resolver.resolve_ip_group("my_net")[0]), "10.0.0.0/24")

    def test_object_ip_range(self):
        objects_csv = OBJECTS_HEADER + "range,ip_range,10.0.0.1,10.0.0.10,,,,\n"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy.csv")
            # This should resolve to a list of networks covering the range
            self.assertGreater(len(resolver.resolve_ip_group("ip_range")), 0)

    def test_object_mac_range(self):
        objects_csv = OBJECTS_HEADER + "range,mac_range,,,,,01:0c:cd:01:00:00,01:0c:cd:01:01:ff,\n"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy.csv")
            self.assertIn('mac_range', resolver.raw_objects)
            self.assertTrue(resolver.raw_objects['mac_range']['value'].startswith('mac_range:'))

    def test_object_group(self):
        objects_csv = (
            OBJECTS_HEADER +
            "host,host_a,1.1.1.1,,,,,\n" +
            "group,my_group,host_a,,,,,\n"
        )
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy.csv")
            self.assertEqual(len(resolver.resolve_ip_group("my_group")), 1)

class TestAnalysisEngine(unittest.TestCase):
    """High-level tests for the main analysis engine."""

    def run_test(self, rules_data, objects_data=None):
        """Helper for running tests. rules_data can be a string or a list of strings."""
        with patch('builtins.open') as mock_open:
            if isinstance(rules_data, list):
                # Multi-file scenario
                file_map = {f"rules{i}.csv": content for i, content in enumerate(rules_data)}
                if objects_data:
                    file_map["objects.csv"] = objects_data

                def side_effect(path, *args, **kwargs):
                    if path in file_map:
                        return io.StringIO(file_map[path])
                    return unittest.mock.mock_open(read_data="").return_value

                mock_open.side_effect = side_effect
                rule_paths = list(file_map.keys())
                if "objects.csv" in rule_paths: rule_paths.remove("objects.csv")

            else: # Single file scenario
                def side_effect(path, *args, **kwargs):
                    if path == "rules.csv": return io.StringIO(rules_data)
                    if path == "objects.csv" and objects_data: return io.StringIO(objects_data)
                    return unittest.mock.mock_open(read_data="").return_value
                mock_open.side_effect = side_effect
                rule_paths = ["rules.csv"]

            resolver = ObjectResolver("objects.csv" if objects_data else None)
            active, _, _ = load_rules(rule_paths, resolver, "both")
            results = run_analysis(active)
            return results

    def test_interleaved_shadow_rule(self):
        """Tests that a rule in file 2 is shadowed by a rule in file 1."""
        rules1 = RULES_HEADER + "rule,R1,on,allow,any,any,any,any,,\n"
        rules2 = RULES_HEADER + "rule,R2,on,allow,10.0.0.0/8,any,any,any,,\n"
        results = self.run_test([rules1, rules2])
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")

    def test_mac_rule_is_skipped(self):
        rules = RULES_HEADER + "rule,mac_rule,on,allow,mac_obj,any,any,any,,\n"
        objects = OBJECTS_HEADER + "range,mac_obj,,,,,00:11:22:33:44:55,00:11:22:33:44:66,\n"
        results = self.run_test(rules, objects)
        self.assertIn("mac_rule", results.unsupported_mac_rules)

    def test_shadowed_rule_ip_only(self):
        rules = (
            RULES_HEADER +
            "rule,R1,on,allow,any,any,any,any,,\n" +
            "rule,R2,on,allow,host_a,any,any,any,,\n"
        )
        objects = OBJECTS_HEADER + "host,host_a,1.1.1.1,,,,,\n"
        results = self.run_test(rules, objects)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")
        self.assertEqual(len(results.unsupported_mac_rules), 0)

    def test_shadowed_by_any(self):
        rules = (
            RULES_HEADER +
            "rule,R1,on,allow,any,1.1.1.1/32,80,tcp,,\n" +
            "rule,R2,on,allow,10.0.0.0/24,1.1.1.1/32,80,tcp,,\n"
        )
        results = self.run_test(rules, None)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
