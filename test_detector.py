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

# --- Rules Test Data ---
OLD_RULES_HEADER = "rule_id;position;slot;enabled;action;src;dst;svc;proto;comment\n"
NEW_RULES_HEADER = "#type_slot,rule_name,state,action,from_src,to_dest,service,proto,comment,nat_to_target\n"

# --- Objects Test Data ---
OLD_OBJECTS_CSV = "name;type;value\nhost_a;host;1.1.1.1/32"
NEW_OBJECTS_HOST_CSV = '#type,name,ip,ipv6,resolve,mac,comment\nhost,my_host,1.2.3.4,,dynamic,,\n'
NEW_OBJECTS_NET_CSV = '#type,name,ip,ipv6,resolve,mac,comment\nnetwork,my_net,10.0.0.0,255.255.255.0,24,,\n'


class TestParsing(unittest.TestCase):
    """Tests for parsing different file formats."""

    def test_load_rules_old_format(self):
        rules_csv = OLD_RULES_HEADER + "R1;1;filter;true;allow;any;any;any;any;\n"
        with patch('builtins.open', return_value=io.StringIO(rules_csv)):
            resolver = ObjectResolver(None)
            active, _, _ = load_rules("rules.csv", resolver, "both")
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0].rule_id, "R1")

    def test_load_rules_new_format(self):
        rules_csv = NEW_RULES_HEADER + "rule,R1,on,allow,any,any,any,any,,\n"
        with patch('builtins.open', return_value=io.StringIO(rules_csv)):
            resolver = ObjectResolver(None)
            active, _, _ = load_rules("rules.csv", resolver, "both")
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0].rule_id, "R1")

    def test_object_resolver_old_format(self):
        with patch('builtins.open', return_value=io.StringIO(OLD_OBJECTS_CSV)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(str(resolver.resolve_ip_group("host_a")[0]), "1.1.1.1/32")

    def test_object_resolver_new_format_host(self):
        with patch('builtins.open', return_value=io.StringIO(NEW_OBJECTS_HOST_CSV)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(str(resolver.resolve_ip_group("my_host")[0]), "1.2.3.4/32")

    def test_object_resolver_new_format_network(self):
        with patch('builtins.open', return_value=io.StringIO(NEW_OBJECTS_NET_CSV)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(str(resolver.resolve_ip_group("my_net")[0]), "10.0.0.0/24")

class TestAnalysisEngine(unittest.TestCase):
    """High-level tests for the main analysis engine to ensure it works with different formats."""

    def run_test_on_rules(self, rules_data, objects_data=None):
        with patch('builtins.open') as mock_open:
            def side_effect(path, *args, **kwargs):
                if path == "rules.csv":
                    return io.StringIO(rules_data)
                if path == "objects.csv" and objects_data:
                    return io.StringIO(objects_data)
                return unittest.mock.mock_open(read_data="").return_value
            mock_open.side_effect = side_effect

            resolver = ObjectResolver("objects.csv" if objects_data else None)
            active_rules, _, _ = load_rules("rules.csv", resolver, "both")
            results = run_analysis(active_rules)
            return results

    def test_shadowed_rule_with_new_formats(self):
        rules = NEW_RULES_HEADER + "rule,R1,on,allow,any,any,any,any,,\n" + "rule,R2,on,allow,my_host,any,any,any,,\n"
        objects = NEW_OBJECTS_HOST_CSV
        results = self.run_test_on_rules(rules, objects)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")

    def test_shadowed_rule_with_old_formats(self):
        rules = OLD_RULES_HEADER + "R1;1;filter;true;allow;any;any;any;any;\nR2;2;filter;true;allow;host_a;any;any;any;"
        objects = OLD_OBJECTS_CSV
        results = self.run_test_on_rules(rules, objects)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
