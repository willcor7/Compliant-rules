#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stormshield SNS Firewall Rule Analyzer.

This script analyzes Stormshield SNS firewall rules from CSV exports to detect
inconsistencies such as shadowed rules, duplicates, and conflicts.
"""

import argparse
import csv
import ipaddress
import json
import logging
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Set, Dict, Any, Union, Tuple, Optional

# --- Configuration ---
LOG = logging.getLogger(__name__)
IPV6_ENABLED = False # Controlled by CLI arg

# --- Type Aliases ---
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# --- Enums ---
class MatchRelation(Enum):
    EQUAL = "EQUAL"
    SUBSET = "SUBSET" # A is a subset of B
    SUPERSET = "SUPERSET" # A is a superset of B
    INTERSECT = "INTERSECT"
    NONE = "NONE"

# --- Core Data Structures ---

@dataclass(frozen=True, order=True)
class PortRange:
    """Represents a range of ports."""
    start: int
    end: int
    def __post_init__(self):
        if not (0 <= self.start <= 65535 and 0 <= self.end <= 65535): raise ValueError(f"Port out of range: {self.start}-{self.end}")
        if self.start > self.end: raise ValueError(f"Invalid port range: start > end")
    def __str__(self): return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"

@dataclass(frozen=True, order=True)
class Service:
    """Represents a service (protocol and port ranges)."""
    protocol: str
    ports: Tuple[PortRange, ...]

@dataclass
class Rule:
    """Represents a single, normalized firewall rule."""
    rule_id: str; position: int; slot: str; enabled: bool; action: str; comment: str
    src_ips: List[IPNetwork]; dst_ips: List[IPNetwork]; services: List[Service]
    raw_src: str; raw_dst: str; raw_svc: str; raw_proto: str
    def __repr__(self): return f"Rule(id={self.rule_id}, pos={self.position}, slot='{self.slot}', action='{self.action}')"

@dataclass
class AnalysisResult:
    """Holds the results of the firewall rule analysis."""
    shadowed_same_action: list = field(default_factory=list)
    shadowed_conflict: list = field(default_factory=list)
    duplicates: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    partial_overlaps: list = field(default_factory=list)
    disabled_rules: list = field(default_factory=list)
    unknown_objects: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

# --- Object Resolution ---
class ObjectResolver:
    def __init__(self, objects_path: Optional[str]):
        self.raw_objects: Dict[str, Dict[str, str]] = self._load_raw_objects(objects_path)
        self.resolved_cache: Dict[str, Any] = {}
        self.unknown_objects: Set[str] = set()
    def _load_raw_objects(self, objects_path: Optional[str]) -> Dict[str, Dict[str, str]]:
        if not objects_path: return {}
        objects = {}
        try:
            with open(objects_path, 'r', encoding='utf-8-sig') as f:
                sample = f.read(2048)
                if not sample:
                    LOG.warning(f"Object file {objects_path} is empty.")
                    return {}
                f.seek(0)

                is_new_format = sample.lstrip().startswith('#')

                if is_new_format:
                    LOG.info("Detected new object format.")
                    reader = csv.reader(f, delimiter=',')
                    try:
                        header_row = next(reader)
                        fieldnames = [h.strip().lstrip('#') for h in header_row]
                    except StopIteration:
                        return {}

                    rows = [dict(zip(fieldnames, row_list)) for row_list in reader if row_list and row_list[0].strip()]
                else:
                    LOG.info("Detected old object format.")
                    sniffer = csv.Sniffer()
                    dialect = sniffer.sniff(sample, delimiters=';,')
                    f.seek(0)
                    reader = csv.DictReader(f, dialect=dialect)
                    rows = list(reader)

                for row in rows:
                    try:
                        if is_new_format:
                            name = row.get('name')
                            obj_type = row.get('type')
                            if not name or not obj_type: continue
                            if obj_type not in ('host', 'network', 'range', 'group', 'service', 'service_group'): continue

                            value = ''
                            if obj_type == 'host':
                                value = row.get('ip', '')
                            elif obj_type == 'network':
                                ip = row.get('ip')
                                netmask = row.get('ipv6')
                                if ip and netmask: value = f"{ip}/{netmask}"
                                elif ip: value = ip
                            else:
                                value = row.get('ip', '')
                                if not value: LOG.warning(f"Could not determine value for object '{name}' of type '{obj_type}'.")

                            objects[name] = {'type': obj_type, 'value': value}
                        else:
                            objects[row['name']] = {'type': row['type'], 'value': row['value']}
                    except (KeyError, TypeError) as e:
                        LOG.warning(f"Skipping object row due to error: {e}. Row: {row}")

        except (IOError, csv.Error) as e:
            LOG.error(f"Failed to read or parse objects file {objects_path}: {e}")
            raise
        return objects
    def resolve_ip_group(self, name: str, path: Optional[Set[str]] = None) -> List[IPNetwork]:
        path = path or set();
        if name in path: raise ValueError(f"Circular dependency in IP groups: {' -> '.join(path)} -> {name}")
        path.add(name)
        if name in self.resolved_cache: return self.resolved_cache[name]
        if name not in self.raw_objects: self.unknown_objects.add(name); return []
        obj = self.raw_objects[name]; obj_type, obj_value = obj['type'], obj['value']
        result: List[IPNetwork] = []
        if obj_type in ('host', 'network', 'range'): result = _parse_ip_token(obj_value)
        elif obj_type == 'group':
            for member in obj_value.split(','):
                if member.strip(): result.extend(self.resolve_ip_group(member.strip(), path.copy()))
        else: LOG.warning(f"Object '{name}' has non-IP type '{obj_type}' in IP context.")
        self.resolved_cache[name] = result; return result
    def resolve_service_group(self, name: str, path: Optional[Set[str]] = None) -> List[Tuple[str, str]]:
        path = path or set()
        if name in path: raise ValueError(f"Circular dependency in service groups: {' -> '.join(path)} -> {name}")
        path.add(name)
        if name in self.resolved_cache: return self.resolved_cache[name]
        if name not in self.raw_objects: self.unknown_objects.add(name); return []
        obj = self.raw_objects[name]; obj_type, obj_value = obj['type'], obj['value']
        result: List[Tuple[str, str]] = []
        if obj_type == 'service': result.append(_parse_service_token_value(obj_value))
        elif obj_type == 'service_group':
            for member in obj_value.split(','):
                member = member.strip()
                if not member: continue
                if ':' in member: result.append(_parse_service_token_value(member))
                else: result.extend(self.resolve_service_group(member, path.copy()))
        else: LOG.warning(f"Object '{name}' has non-service type '{obj_type}' in service context.")
        self.resolved_cache[name] = result; return result

# --- Parsing & Normalization Helpers ---
def _parse_ip_token(token: str) -> List[IPNetwork]:
    token = token.strip().lower()
    if not token or token == 'any': return [ipaddress.ip_network('0.0.0.0/0' if not IPV6_ENABLED else '::/0')]
    try:
        if '-' in token:
            start_ip, end_ip = map(ipaddress.ip_address, token.split('-', 1))
            if start_ip.version != end_ip.version: raise ValueError("IP range must be same version.")
            if not IPV6_ENABLED and start_ip.version == 6: return []
            return list(ipaddress.summarize_address_range(start_ip, end_ip))
        else:
            net = ipaddress.ip_network(token, strict=False)
            if not IPV6_ENABLED and net.version == 6: return []
            return [net]
    except ValueError as e: LOG.warning(f"Could not parse IP token '{token}': {e}"); return []
def _parse_port_token(token: str) -> List[PortRange]:
    token = token.strip().lower()
    if not token or token == 'any': return [PortRange(0, 65535)]
    try:
        if '-' in token: start, end = map(int, token.split('-', 1)); return [PortRange(start, end)]
        else: port = int(token); return [PortRange(port, port)]
    except (ValueError, TypeError) as e: LOG.warning(f"Could not parse port token '{token}': {e}"); return []
def _parse_service_token_value(value: str) -> Tuple[str, str]:
    try: proto, port = value.split(':', 1); return proto.strip().lower(), port.strip()
    except ValueError: LOG.warning(f"Invalid service value '{value}'."); return "any", "any"
def _normalize_services(proto_str: str, svc_str: str, resolver: ObjectResolver) -> List[Service]:
    protocols = {p for p in proto_str.lower().split(',') if p} or ['any']
    if 'any' in protocols: protocols = {'tcp', 'udp', 'icmp'}
    svc_tokens = [s.strip() for s in svc_str.split(',') if s.strip()]
    ports_by_proto: Dict[str, List[PortRange]] = {p: [] for p in protocols}
    for token in svc_tokens:
        if ':' in token:
            proto, port_def = _parse_service_token_value(token)
            if proto in ports_by_proto: ports_by_proto[proto].extend(_parse_port_token(port_def))
        elif resolver.raw_objects.get(token, {}).get('type') in ('service', 'service_group'):
            for proto, port_def in resolver.resolve_service_group(token):
                if proto in ports_by_proto: ports_by_proto[proto].extend(_parse_port_token(port_def))
        else:
            for proto in ports_by_proto: ports_by_proto[proto].extend(_parse_port_token(token))
    if not svc_tokens or 'any' in {t.lower() for t in svc_tokens}:
        for proto in ports_by_proto: ports_by_proto[proto].extend(_parse_port_token('any'))
    if 'icmp' in ports_by_proto and not ports_by_proto['icmp']: ports_by_proto['icmp'].extend(_parse_port_token('any'))
    return [Service(p, tuple(sorted(list(set(ports))))) for p, ports in ports_by_proto.items() if ports]
def _normalize_ip_field(ip_str: str, resolver: ObjectResolver) -> List[IPNetwork]:
    networks = []
    for token in [t.strip() for t in ip_str.split(',') if t.strip()]:
        if token in resolver.raw_objects: networks.extend(resolver.resolve_ip_group(token))
        else: networks.extend(_parse_ip_token(token))
    return sorted(list(set(networks)), key=lambda n: n.network_address)
def load_rules(rules_path: str, resolver: ObjectResolver, slot_filter: str) -> Tuple[List[Rule], List[Rule], int]:
    """Loads and normalizes rules from the user-provided CSV format, supporting both old and new formats."""
    all_rules = []
    total_count = 0
    try:
        with open(rules_path, 'r', encoding='utf-8-sig') as f:
            sample = f.read(2048)
            if not sample:
                LOG.warning(f"Rules file {rules_path} is empty.")
                return [], [], 0
            f.seek(0)

            # Determine format by inspecting headers
            sample_lower = sample.lower()
            is_new_format = 'type_slot' in sample_lower or 'rule_name' in sample_lower

            if is_new_format:
                LOG.info("Detected new rule format.")
                reader = csv.DictReader(f, delimiter=',')
                reader.fieldnames = [name.strip().lstrip('#') for name in reader.fieldnames or []]
                rows = list(reader)
                total_count = len(rows)
                rule_pos = 0
                for i, row in enumerate(rows):
                    if row.get('type_slot') != 'rule':
                        continue
                    rule_pos += 1
                    slot = 'nat' if row.get('nat_to_target') else 'filter'
                    if slot_filter != 'both' and slot != slot_filter: continue

                    is_enabled = row.get('state', 'true').lower() in {'on', 'active', 'enabled', 'true'}
                    rule = Rule(
                        rule_id=row.get('rule_name') or f"row_{i+2}", position=rule_pos, slot=slot,
                        enabled=is_enabled, action=row.get('action', 'pass'), comment=row.get('comment', ''),
                        raw_src=row.get('from_src', 'any'), raw_dst=row.get('to_dest', 'any'),
                        raw_svc=row.get('service', 'any'), raw_proto=row.get('proto', 'any'),
                        src_ips=[], dst_ips=[], services=[]
                    )
                    all_rules.append(rule)
            else:
                LOG.info("Detected old rule format.")
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=';,')
                    f.seek(0) # Rewind after sniff
                    reader = csv.DictReader(f, dialect=dialect)
                except csv.Error:
                    f.seek(0) # Rewind
                    reader = csv.DictReader(f, delimiter=';')

                reader.fieldnames = [name.strip().lstrip('#') for name in reader.fieldnames or []]
                rows = list(reader)
                total_count = len(rows)
                for i, row in enumerate(rows):
                    if not any(row.values()):
                        total_count -= 1
                        continue
                    slot = row.get('slot', 'filter')
                    if slot_filter != 'both' and slot != slot_filter: continue

                    is_enabled = str(row.get('enabled', 'true')).lower() in {'on', 'active', 'enabled', 'true'}
                    rule = Rule(
                        rule_id=row.get('rule_id') or f"row_{i+2}", position=int(row.get('position', i + 1)),
                        slot=slot, enabled=is_enabled, action=row.get('action', 'pass'),
                        comment=row.get('comment', ''), raw_src=row.get('src', 'any'),
                        raw_dst=row.get('dst', 'any'), raw_svc=row.get('svc', 'any'),
                        raw_proto=row.get('proto', 'any'), src_ips=[], dst_ips=[], services=[]
                    )
                    all_rules.append(rule)

    except (IOError, csv.Error) as e:
        LOG.error(f"Failed to process rules file {rules_path}: {e}")
        raise
    except KeyError as e:
        LOG.error(f"A required column is missing in {rules_path}. Detected headers from sample: {sample.splitlines()[0]}")
        raise

    active = sorted([r for r in all_rules if r.enabled], key=lambda r: r.position)
    disabled = [r for r in all_rules if not r.enabled]

    for rule in active:
        rule.src_ips = _normalize_ip_field(rule.raw_src, resolver)
        rule.dst_ips = _normalize_ip_field(rule.raw_dst, resolver)
        rule.services = _normalize_services(rule.raw_proto, rule.raw_svc, resolver)

    return active, disabled, total_count

# --- Detection Engine ---
def _is_subset_ip(a: List[IPNetwork], b: List[IPNetwork]) -> bool: return all(any(n_a.subnet_of(n_b) for n_b in b) for n_a in a)
def _ip_intersects(a: List[IPNetwork], b: List[IPNetwork]) -> bool: return any(n_a.overlaps(n_b) for n_a in a for n_b in b)
def _is_subset_ports(a: Tuple[PortRange, ...], b: Tuple[PortRange, ...]) -> bool: return all(any(pr_a.start >= pr_b.start and pr_a.end <= pr_b.end for pr_b in b) for pr_a in a)
def _ports_intersect(a: Tuple[PortRange, ...], b: Tuple[PortRange, ...]) -> bool: return any(max(pr_a.start, pr_b.start) <= min(pr_a.end, pr_b.end) for pr_a in a for pr_b in b)
def _compare_services(a: List[Service], b: List[Service]) -> MatchRelation:
    map_a, map_b = {s.protocol: s.ports for s in a}, {s.protocol: s.ports for s in b}
    all_protos, is_subset, is_superset, intersects = set(map_a.keys()) | set(map_b.keys()), True, True, False
    for proto in all_protos:
        ports_a, ports_b = map_a.get(proto), map_b.get(proto)
        if ports_a and ports_b:
            if not _is_subset_ports(ports_a, ports_b): is_subset = False
            if not _is_subset_ports(ports_b, ports_a): is_superset = False
            if _ports_intersect(ports_a, ports_b): intersects = True
        elif ports_a: is_superset = False
        elif ports_b: is_subset = False
    if is_subset and is_superset: return MatchRelation.EQUAL
    if is_subset: return MatchRelation.SUBSET
    if is_superset: return MatchRelation.SUPERSET
    if intersects: return MatchRelation.INTERSECT
    return MatchRelation.NONE
def compare_rules(a: Rule, b: Rule) -> Dict[str, MatchRelation]:
    return {"src": MatchRelation.EQUAL if a.src_ips == b.src_ips else MatchRelation.SUBSET if _is_subset_ip(a.src_ips, b.src_ips) else MatchRelation.SUPERSET if _is_subset_ip(b.src_ips, a.src_ips) else MatchRelation.INTERSECT if _ip_intersects(a.src_ips, b.src_ips) else MatchRelation.NONE,
            "dst": MatchRelation.EQUAL if a.dst_ips == b.dst_ips else MatchRelation.SUBSET if _is_subset_ip(a.dst_ips, b.dst_ips) else MatchRelation.SUPERSET if _is_subset_ip(b.dst_ips, a.dst_ips) else MatchRelation.INTERSECT if _ip_intersects(a.dst_ips, b.dst_ips) else MatchRelation.NONE,
            "svc": _compare_services(a.services, b.services)}
def run_analysis(rules: List[Rule]) -> AnalysisResult:
    results = AnalysisResult()
    rules_by_slot: Dict[str, List[Rule]] = {}
    for rule in rules:
        rules_by_slot.setdefault(rule.slot, []).append(rule)

    for slot, slot_rules in rules_by_slot.items():
        LOG.info(f"Analyzing {len(slot_rules)} rules in slot '{slot}'...")
        for i in range(len(slot_rules)):
            for j in range(i):
                rule_a, rule_b = slot_rules[i], slot_rules[j]
                relations = compare_rules(rule_a, rule_b)
                is_subset = all(r in (MatchRelation.SUBSET, MatchRelation.EQUAL) for r in relations.values())
                is_equal = all(r == MatchRelation.EQUAL for r in relations.values())
                intersects = all(r != MatchRelation.NONE for r in relations.values())
                if is_equal:
                    if rule_a.action == rule_b.action: results.duplicates.append({"rule": rule_a.rule_id, "duplicate_of": rule_b.rule_id, "slot": slot})
                elif is_subset:
                    detail = {"rule": rule_a.rule_id, "shadowed_by": rule_b.rule_id, "slot": slot, "overlap_detail": {k: v.value for k, v in relations.items()}}
                    if rule_a.action == rule_b.action: results.shadowed_same_action.append(detail)
                    else: results.shadowed_conflict.append(detail)
                elif intersects:
                    detail = {"rule_a": rule_a.rule_id, "rule_b": rule_b.rule_id, "slot": slot, "overlap_detail": {k: v.value for k, v in relations.items()}}
                    if rule_a.action != rule_b.action: results.conflicts.append(detail)
                    else: results.partial_overlaps.append(detail)
    return results

# --- Output Generation ---
def generate_json_report(results: AnalysisResult, out_path: str):
    """Generates the JSON output file."""
    LOG.info(f"Generating JSON report at {out_path}...")
    class CustomEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, (ipaddress.IPv4Network, ipaddress.IPv6Network, MatchRelation)): return str(o)
            return super().default(o)
    try:
        with open(out_path, 'w', encoding='utf-8') as f: json.dump(asdict(results), f, indent=2, cls=CustomEncoder)
    except IOError as e: LOG.error(f"Failed to write JSON report: {e}"); return 1
    return 0

def generate_md_report(results: AnalysisResult, md_path: str):
    """Generates the Markdown output file."""
    LOG.info(f"Generating Markdown report at {md_path}...")
    try:
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# Firewall Analysis Report\n\n")
            # Summary
            f.write("## 1. Summary\n\n")
            stats = results.stats
            f.write(f"- **Total Rules Analyzed:** {stats.get('rules_total', 'N/A')}\n")
            f.write(f"- **Enabled Rules Analyzed:** {stats.get('rules_enabled', 'N/A')}\n")
            f.write(f"- **Analysis Duration:** {stats.get('duration_ms', 'N/A')} ms\n\n")

            summary_data = {
                "Shadowed (Conflict Action)": len(results.shadowed_conflict),
                "Shadowed (Same Action)": len(results.shadowed_same_action),
                "Duplicates": len(results.duplicates),
                "Conflicts": len(results.conflicts),
                "Partial Overlaps": len(results.partial_overlaps),
                "Disabled Rules": len(results.disabled_rules),
                "Unknown Objects": len(results.unknown_objects),
            }
            f.write("| Category | Count |\n")
            f.write("|---|---:|\n")
            for name, count in summary_data.items():
                if count > 0: f.write(f"| {name} | {count} |\n")
            f.write("\n")

            # Helper to write tables
            def write_table(title, headers, data, limit=50):
                if not data: return
                f.write(f"## {title}\n\n")
                f.write(f"Displaying top {min(len(data), limit)} findings.\n\n")
                f.write(f"| {' | '.join(headers)} |\n")
                f.write(f"|{'---|' * len(headers)}\n")
                for i, row in enumerate(data):
                    if i >= limit: break
                    f.write(f"| {' | '.join(str(row.get(h.lower().replace(' ', '_'), '')) for h in headers)} |\n")
                f.write("\n")

            write_table("2. Shadowed Rules (Conflict Action)", ["Rule", "Shadowed By", "Slot"], results.shadowed_conflict)
            write_table("3. Duplicates", ["Rule", "Duplicate Of", "Slot"], results.duplicates)
            write_table("4. Conflicts", ["Rule A", "Rule B", "Slot"], results.conflicts)
            write_table("5. Shadowed Rules (Same Action)", ["Rule", "Shadowed By", "Slot"], results.shadowed_same_action)
            write_table("6. Partial Overlaps", ["Rule A", "Rule B", "Slot"], results.partial_overlaps)

            if results.disabled_rules:
                f.write("## 7. Disabled Rules\n\n")
                f.write("```\n" + "\n".join(results.disabled_rules) + "\n```\n\n")
            if results.unknown_objects:
                f.write("## 8. Unknown Objects\n\n")
                f.write("```\n" + "\n".join(results.unknown_objects) + "\n```\n\n")

    except IOError as e: LOG.error(f"Failed to write Markdown report: {e}"); return 1
    return 0

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Stormshield SNS Firewall Rule Analyzer.")
    parser.add_argument('--rules', required=True, help="Path to the rules CSV file.")
    parser.add_argument('--objects', help="Path to the objects CSV file (optional).")
    parser.add_argument('--out', required=True, help="Path for the output JSON report.")
    parser.add_argument('--md', help="Path for the output Markdown report (optional).")
    parser.add_argument('--slot', choices=['filter', 'nat', 'both'], default='both', help="Which rule slot to analyze.")
    parser.add_argument('--ipv6', choices=['on', 'off'], default='off', help="Enable IPv6 processing.")
    parser.add_argument('--unknown', choices=['fail', 'warn'], default='warn', help="Action on unknown objects.")
    parser.add_argument('--perf.hints', choices=['on', 'off'], default='off', help="Enable performance hints (not implemented).")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    start_time = time.time()

    global IPV6_ENABLED
    IPV6_ENABLED = (args.ipv6 == 'on')

    try:
        resolver = ObjectResolver(args.objects)
        active_rules, disabled_rules, total_rules = load_rules(args.rules, resolver, args.slot)

        if args.unknown == 'fail' and resolver.unknown_objects:
            LOG.error(f"Found {len(resolver.unknown_objects)} unknown objects, and --unknown=fail. Aborting.")
            LOG.error(f"Unknown objects: {', '.join(sorted(list(resolver.unknown_objects)))}")
            return 3

        results = run_analysis(active_rules)
        results.disabled_rules = sorted([r.rule_id for r in disabled_rules])
        results.unknown_objects = sorted(list(resolver.unknown_objects))

        duration_ms = (time.time() - start_time) * 1000
        results.stats = {"rules_total": total_rules, "rules_enabled": len(active_rules), "duration_ms": round(duration_ms)}

        if generate_json_report(results, args.out) != 0: return 1
        if args.md:
            if generate_md_report(results, args.md) != 0: return 1

    except Exception as e:
        LOG.error(f"An unexpected error occurred: {e}", exc_info=True)
        return 4

    LOG.info(f"Analysis complete in {results.stats['duration_ms']} ms.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
