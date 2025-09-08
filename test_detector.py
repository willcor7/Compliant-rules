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
    main,
    _parse_ip_token,
    _parse_port_token
)

# Suppress logging during tests
logging.disable(logging.CRITICAL)

class TestParsingHelpers(unittest.TestCase):
    """Tests for low-level parsing functions."""

    def test_parse_ip_token(self):
        self.assertEqual(str(_parse_ip_token("192.168.1.1")[0]), "192.168.1.1/32")
        self.assertEqual(str(_parse_ip_token("10.0.0.0/24")[0]), "10.0.0.0/24")
        self.assertEqual(len(_parse_ip_token("10.0.0.1-10.0.0.2")), 2) # 10.0.0.1/32, 10.0.0.2/32
        self.assertEqual(str(_parse_ip_token("any")[0]), "0.0.0.0/0")
        self.assertEqual(_parse_ip_token("invalid-ip"), [])

    def test_parse_port_token(self):
        self.assertEqual(_parse_port_token("80")[0].start, 80)
        self.assertEqual(_parse_port_token("80")[0].end, 80)
        self.assertEqual(_parse_port_token("1000-2000")[0].start, 1000)
        self.assertEqual(_parse_port_token("1000-2000")[0].end, 2000)
        self.assertEqual(_parse_port_token("any")[0].start, 0)
        self.assertEqual(_parse_port_token("any")[0].end, 65535)
        self.assertEqual(_parse_port_token("invalid-port"), [])

class TestObjectResolver(unittest.TestCase):
    """Tests for the ObjectResolver class."""

    def test_simple_resolution(self):
        objects_csv = "name;type;value\nhost_a;host;1.1.1.1/32"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(str(resolver.resolve_ip_group("host_a")[0]), "1.1.1.1/32")

    def test_group_resolution(self):
        objects_csv = "name;type;value\nhost_a;host;1.1.1.1/32\nhost_b;host;2.2.2.2/32\ngrp_ab;group;host_a,host_b"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            resolved = resolver.resolve_ip_group("grp_ab")
            self.assertEqual(len(resolved), 2)
            self.assertIn(str(resolved[0]), "1.1.1.1/32")

    def test_unknown_object(self):
        objects_csv = "name;type;value\n"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            self.assertEqual(resolver.resolve_ip_group("unknown_host"), [])
            self.assertIn("unknown_host", resolver.unknown_objects)

    def test_circular_dependency(self):
        objects_csv = "name;type;value\ngrp_a;group;grp_b\ngrp_b;group;grp_a"
        with patch('builtins.open', return_value=io.StringIO(objects_csv)):
            resolver = ObjectResolver("dummy_path.csv")
            with self.assertRaises(ValueError) as cm:
                resolver.resolve_ip_group("grp_a")
            self.assertIn("Circular dependency", str(cm.exception))

class TestAnalysisEngine(unittest.TestCase):
    """High-level tests for the main analysis engine."""

    def run_test_on_rules(self, rules_data, objects_data="name;type;value\n"):
        """Helper to run analysis on given CSV data."""
        with patch('builtins.open') as mock_open:
            # Route open calls to the correct in-memory file
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
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;allow;any;any;any;any\n"
            "R2;2;filter;true;allow;10.0.0.1;any;any;any"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], "R2")
        self.assertEqual(results.shadowed_same_action[0]['shadowed_by'], "R1")

    def test_shadowed_conflict(self):
        rules = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;deny;10.0.0.0/8;any;any;any\n"
            "R2;2;filter;true;allow;10.0.0.0/16;any;any;any"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_conflict), 1)
        self.assertEqual(results.shadowed_conflict[0]['rule'], "R2")

    def test_duplicate(self):
        rules = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;allow;1.1.1.1;2.2.2.2;80;tcp\n"
            "R2;2;filter;true;allow;1.1.1.1;2.2.2.2;80;tcp"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.duplicates), 1)
        self.assertEqual(results.duplicates[0]['rule'], "R2")

    def test_conflict(self):
        rules = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;allow;10.0.0.0/24;any;80;tcp\n"
            "R2;2;filter;true;deny;10.0.0.0/16;any;80;tcp"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.conflicts), 1)
        self.assertEqual(results.conflicts[0]['rule_a'], "R2")
        self.assertEqual(results.conflicts[0]['rule_b'], "R1")

    def test_partial_overlap(self):
        rules = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;allow;10.0.0.0/24;any;80;tcp\n"
            "R2;2;filter;true;allow;10.0.0.0/16;any;80;tcp"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.partial_overlaps), 1)
        self.assertEqual(results.partial_overlaps[0]['rule_a'], "R2")

    def test_no_anomaly_between_slots(self):
        rules = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto\n"
            "R1;1;filter;true;allow;any;any;any;any\n"
            "R2;2;nat;true;snat;10.0.0.1;any;any;any"
        )
        results = self.run_test_on_rules(rules)
        self.assertEqual(len(results.shadowed_same_action), 0)
        self.assertEqual(len(results.shadowed_conflict), 0)

    def test_example_from_prompt(self):
        rules_csv = (
            "rule_id;position;slot;enabled;action;src;dst;svc;proto;in_if;out_if;schedule;users;comment\n"
            "R1;1;filter;true;allow;10.0.0.0/24;192.168.1.0/24;80,443;tcp;;;;\n"
            "R2;2;filter;true;allow;10.0.0.10-10.0.0.20;192.168.1.100/32;80;tcp;;;;\n"
            "R3;3;filter;true;deny;10.0.0.0/8;192.168.0.0/16;1-65535;tcp;;;;\n"
            "R4;4;filter;false;allow;any;any;any;any;;;;\n"
            "R5;5;nat;true;snat;10.0.0.0/24;any;any;any;;;;"
        )
        objects_csv = (
            "name;type;value\n"
            "srv_web;host;192.168.1.100/32\n"
            "prod_nets;group;10.0.0.0/24,10.0.1.0/24\n"
            "http;service;tcp:80\n"
            "web;service_group;http,tcp:443"
        )
        results = self.run_test_on_rules(rules_csv, objects_csv)

        # R2 is shadowed by R1 (same action)
        self.assertEqual(len(results.shadowed_same_action), 1)
        self.assertEqual(results.shadowed_same_action[0]['rule'], 'R2')
        self.assertEqual(results.shadowed_same_action[0]['shadowed_by'], 'R1')

        # The prompt's spec says A is shadowed by B if pos(B) < pos(A).
        # The prompt's example JSON contradicts this. I will test against the spec.
        # According to the spec, a higher rule (lower pos) shadows a lower rule (higher pos).

        # R1 is NOT shadowed by anything.
        # R3 intersects with R1, and has a different action -> conflict.
        # R3 intersects with R2, and has a different action -> conflict.
        self.assertEqual(len(results.shadowed_conflict), 0)
        self.assertEqual(len(results.conflicts), 2)
        self.assertEqual(results.conflicts[0]['rule_a'], 'R3')
        self.assertEqual(results.conflicts[0]['rule_b'], 'R1')
        self.assertEqual(results.conflicts[1]['rule_a'], 'R3')
        self.assertEqual(results.conflicts[1]['rule_b'], 'R2')

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
