"""Conservative proof for one NEW, external, local-unicast TCP/3000 flow.

No firewall commands here. Unsupported constructs fail closed; summaries are NOT
used as authorization. Both the iptables and native nft views must prove the path.
"""
import copy
import json
import re
import shlex


class Unsafe(Exception):
    def __init__(self, code="PATH_NOT_PROVEN"): self.code = code


def saved_tables(raw):
    tables = {}; current = None
    for line in raw.splitlines():
        if not line or line.startswith("#"): continue
        if line.startswith("*"):
            current = {"chains": {}, "rules": []}
            if line[1:] in tables: raise Unsafe()
            tables[line[1:]] = current
        elif line == "COMMIT": current = None
        elif current is None: raise Unsafe()
        elif line.startswith(":"):
            match = re.fullmatch(r":(\S+) (\S+) \[\d+:\d+\]", line)
            if not match: raise Unsafe()
            current["chains"][match[1]] = match[2]
        elif line.startswith("-A "): current["rules"].append(shlex.split(line))
        else: raise Unsafe()
    if current is not None: raise Unsafe()
    return tables


def empty_tables(raw):
    for table in saved_tables(raw).values():
        if table["rules"] or any(p != "ACCEPT" for p in table["chains"].values()): raise Unsafe("OTHER_FILTERING_BACKEND")


def and_condition(conditions):
    return False if False in conditions else None if None in conditions else True


def ip_rule(args, port=3000):
    """Translate only known predicates. None is unknown, never guessed true."""
    if args[:1] != ["-A"] or len(args) < 4: raise Unsafe()
    # HTTPS/SSH proof models ordinary TCP without IPv6 routing headers.
    # The exact stock RH0 DROP stays BEFORE the user chain and is preserved;
    # do not treat arbitrary routing-header matches as a harmless exception.
    if port in (22, 80, 443) and args[1] in ("ufw6-before-input", "ufw6-before-output", "ufw6-before-forward") and args[2:] == ["-m", "rt", "--rt-type", "0", "-j", "DROP"]:
        return False, "DROP"
    conditions = []; verdict = None; i = 2
    while i < len(args):
        flag = args[i]; i += 1
        if i >= len(args): raise Unsafe()
        value = args[i]; i += 1
        if flag in ("-j", "-g"):
            if flag == "-g" or verdict is not None: raise Unsafe()
            verdict = value
        elif flag == "-p": conditions.append(True if value in ("tcp", "6", "all", "0") else False if value in ("udp", "icmp", "icmpv6", "ipv6-icmp", "sctp", "gre", "esp", "ah", "igmp", "udplite") or value.isdigit() else None)
        elif flag == "--dport": conditions.append(int(value) == port if value.isdigit() else None)
        elif flag in ("--ctstate", "--state"): conditions.append("NEW" in value.split(","))
        elif flag == "-i": conditions.append(False if value == "lo" else None)
        elif flag == "--dst-type": conditions.append(value == "LOCAL" if value in ("LOCAL", "BROADCAST", "MULTICAST") else None)
        elif flag in ("-s", "-d"): conditions.append(True if value in ("0.0.0.0/0", "::/0") else None)
        elif flag == "-m":
            if value not in ("tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "conntrack", "state", "addrtype", "limit", "comment") and not (port in (22, 80, 443) and value == "hl"): raise Unsafe()
        elif flag in ("--comment", "--log-prefix", "--log-level", "--reject-with"): pass
        else: conditions.append(None)
    if verdict is None: raise Unsafe()
    return and_condition(conditions), verdict


def nft_rule(expr, port=3000, chain=None):
    if port in (22, 80, 443) and chain in ("ufw6-before-input", "ufw6-before-output", "ufw6-before-forward"):
        guard = [{"match": {"op": "==", "left": {"exthdr": {"name": "rt", "field": "type"}}, "right": 0}}, {"drop": None}]
        if [item for item in expr if set(item) != {"counter"}] == guard: return False, "DROP"
    conditions = []; verdict = "LOG"; terminal = False
    for item in expr:
        if not isinstance(item, dict) or len(item) != 1: raise Unsafe()
        if terminal: raise Unsafe()
        key, value = next(iter(item.items()))
        if key in ("counter", "log"): continue
        if key in ("accept", "drop", "reject", "return"):
            if key != "reject" and value is not None: raise Unsafe()
            verdict = key.upper(); terminal = True; continue
        if key == "jump":
            if not isinstance(value, dict) or set(value) != {"target"}: raise Unsafe()
            verdict = value["target"]; terminal = True; continue
        if key == "limit": conditions.append(None); continue
        if key != "match": raise Unsafe()
        if not isinstance(value, dict) or set(value) != {"left", "right", "op"}: raise Unsafe()
        left, right, op = value.get("left"), value.get("right"), value.get("op")
        actual = None
        if left == {"meta": {"key": "l4proto"}}: actual = "tcp"
        elif left == {"ct": {"key": "state"}}: actual = "new"
        elif left == {"payload": {"protocol": "tcp", "field": "dport"}}: actual = port
        elif left == {"meta": {"key": "iifname"}} and right == "lo": actual = "external"
        elif isinstance(left, dict) and set(left) == {"fib"} and left["fib"] == {"result": "type", "flags": ["daddr"]}: actual = "local"
        elif isinstance(left, dict) and set(left) == {"payload"} and left["payload"].get("protocol") in ("udp", "icmp", "icmpv6"):
            # A preceding protocol predicate must rule out this rule; do not
            # interpret bytes of a TCP packet as another protocol's payload.
            actual = None
        condition = None
        if actual is not None:
            if actual == "tcp" and right == 6: right = "tcp"
            allowed = ("tcp", "udp", "icmp", "ipv6-icmp", "sctp", "gre", "esp", "ah", "igmp", "udplite") if actual == "tcp" else ("new", "established", "related", "invalid", "untracked") if actual == "new" else ("local", "multicast", "broadcast", "unicast", "blackhole", "unreachable", "prohibit") if actual == "local" else ("lo",) if actual == "external" else None
            values = right["set"] if isinstance(right, dict) and set(right) == {"set"} and isinstance(right["set"], list) else [right]
            known = all(type(v) is int and 0 <= v <= 65535 for v in values) if type(actual) is int else all(type(v) is str and v in allowed for v in values)
            if not known: conditions.append(None); continue
            if op in ("==", "in"):
                condition = actual in right["set"] if isinstance(right, dict) and set(right) == {"set"} and isinstance(right["set"], list) else actual == right if not isinstance(right, dict) else None
            elif op == "!=": condition = actual != right if not isinstance(right, dict) else None
        conditions.append(condition)
    return and_condition(conditions), verdict


def outcomes(chains, root, user, append=False):
    """Explore every unknown predicate branch; loops/too much work are refused."""
    budget = [4000]
    def walk(chain, index, stack):
        budget[0] -= 1
        if budget[0] < 0 or len(stack) > 32 or chain not in chains: raise Unsafe()
        rules = chains[chain]
        if index == len(rules): return {"ACCEPT"} if append and chain == user else {"RETURN"}
        condition, verdict = rules[index]
        following = lambda: walk(chain, index + 1, stack)
        if condition is False: return following()
        if verdict in ("ACCEPT", "DROP", "REJECT", "RETURN"): matched = {verdict}
        elif verdict in ("LOG", "NFLOG"): matched = following()
        else:
            if verdict in stack: raise Unsafe()
            matched = walk(verdict, 0, (*stack, chain))
            if "RETURN" in matched: matched = (matched - {"RETURN"}) | following()
        return matched | following() if condition is None else matched
    return {"DROP" if value == "RETURN" else value for value in walk(root, 0, ())}


def prove(chains, user, allow_existing=False):
    # A pre-existing applicable rule is never changed or duplicated, even when
    # a later filter makes it ineffective. A restricted rule requires review.
    if user not in chains: raise Unsafe()
    if allow_existing and outcomes(chains, "INPUT", user) == {"ACCEPT"}: return False
    for condition, _ in chains[user]:
        if condition is not False: raise Unsafe("EXISTING_OR_CONFLICTING_3000_RULE")
    if outcomes(chains, "INPUT", user) != {"DROP"}: raise Unsafe()
    if outcomes(chains, "INPUT", user, append=True) != {"ACCEPT"}: raise Unsafe()
    return True


def ip_profile(raw, family, port=3000, allow_existing=False):
    tables = saved_tables(raw)
    for name, table in tables.items():
        if name != "filter" and (table["rules"] or any(p != "ACCEPT" for p in table["chains"].values())): raise Unsafe("ADDITIONAL_FILTERING")
    table = tables.get("filter", {})
    policies = table.get("chains", {})
    prefix = "ufw" if family == 4 else "ufw6"
    user = prefix + "-user-input"
    if policies.get("INPUT") != "DROP" or policies.get("OUTPUT") != "ACCEPT": raise Unsafe("POLICY_NOT_SUPPORTED")
    if any(name not in ("INPUT", "OUTPUT", "FORWARD") and not name.startswith(prefix + "-") for name in policies): raise Unsafe("FOREIGN_CHAINS")
    for suffix in ("input", "output", "forward", "limit", "limit-accept"):
        if prefix + "-user-" + suffix not in policies: raise Unsafe("UFW_RELOAD_WOULD_BE_REQUIRED")
    chains = {name: [] for name in policies}
    for args in table["rules"]:
        if args[1] not in chains: raise Unsafe()
        if args[1].startswith(prefix + "-user-") and args[-2:] == ["-j", "RETURN"]: raise Unsafe("UFW_RELOAD_WOULD_BE_REQUIRED")
        chains[args[1]].append(ip_rule(args, port))
    needed = prove(chains, user, allow_existing)
    return (tables, needed) if allow_existing else tables


def nft_profile(raw, backend, port=3000, allow_existing=False):
    entries = json.loads(raw)["nftables"]
    if not isinstance(entries, list): raise Unsafe()
    if backend == "legacy":
        if any(set(item) != {"metainfo"} for item in entries): raise Unsafe("OTHER_FILTERING_BACKEND")
        return (entries, None) if allow_existing else entries
    chains = {4: {}, 6: {}}
    for item in entries:
        if set(item) == {"metainfo"}: continue
        if len(item) != 1: raise Unsafe()
        kind, value = next(iter(item.items()))
        if kind not in ("table", "chain", "rule") or value.get("family") not in ("ip", "ip6") or value.get("name" if kind == "table" else "table") != "filter": raise Unsafe("ADDITIONAL_NFT_FILTERING")
        family = 4 if value["family"] == "ip" else 6
        prefix = "ufw" if family == 4 else "ufw6"
        if kind == "table" and set(value) - {"family", "name", "handle"}: raise Unsafe("ADDITIONAL_NFT_FILTERING")
        if kind == "chain":
            if set(value) - {"family", "table", "name", "handle", "type", "hook", "prio", "policy"}: raise Unsafe("ADDITIONAL_NFT_FILTERING")
            name = value["name"]
            if name in chains[family]: raise Unsafe()
            if "hook" in value:
                if name not in ("INPUT", "OUTPUT", "FORWARD") or value.get("type") != "filter" or value["hook"] != name.lower() or value.get("prio") != 0: raise Unsafe("ADDITIONAL_NFT_FILTERING")
                if name == "INPUT" and value.get("policy") != "drop": raise Unsafe()
                if name == "OUTPUT" and value.get("policy") != "accept": raise Unsafe()
            elif not name.startswith(prefix + "-"): raise Unsafe("FOREIGN_CHAINS")
            chains[family][name] = []
    for item in entries:
        if "rule" not in item: continue
        rule = item["rule"]; family = 4 if rule["family"] == "ip" else 6
        if rule["chain"] not in chains[family]: raise Unsafe()
        chains[family][rule["chain"]].append(nft_rule(rule["expr"], port, rule["chain"]))
    needed = {family: prove(rules, ("ufw" if family == 4 else "ufw6") + "-user-input", allow_existing) for family, rules in chains.items()}
    return (entries, needed) if allow_existing else entries


def clean_nft(value):
    # Handles and packet/byte counters may change without a config change.
    if isinstance(value, list): return [clean_nft(v) for v in value]
    if isinstance(value, dict): return {k: (None if k == "counter" else clean_nft(v)) for k, v in value.items() if k not in ("handle", "packets", "bytes", "metainfo")}
    return value


def expected_delta(before, after, backend, port=3000, families=(4, 6)):
    if any(before[key] != after[key] for key in ("version4", "version6")): return False
    for family in (4, 6):
        name = "ip" + str(family)
        old, new = saved_tables(before[name]), saved_tables(after[name])
        expected = copy.deepcopy(old)
        user = ("ufw" if family == 4 else "ufw6") + "-user-input"
        if family in families:
            expected["filter"]["rules"].append(["-A", user, "-p", "tcp", "-m", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        # iptables-save groups rules by chain, so compare each chain's order.
        def grouped(tables):
            return {table: {"chains": data["chains"], "rules": {chain: [r for r in data["rules"] if r[1] == chain] for chain in data["chains"]}} for table, data in tables.items()}
        if grouped(expected) != grouped(new): return False
    old = [clean_nft(v) for v in json.loads(before["nft"])["nftables"] if "metainfo" not in v]
    new = [clean_nft(v) for v in json.loads(after["nft"])["nftables"] if "metainfo" not in v]
    if backend == "nft":
        for family, user in (("ip", "ufw-user-input"), ("ip6", "ufw6-user-input")):
            if (4 if family == "ip" else 6) not in families: continue
            candidates = [i for i, item in enumerate(new) if "rule" in item and item["rule"].get("family") == family and item["rule"].get("table") == "filter" and item["rule"].get("chain") == user]
            if not candidates: return False
            item = new[candidates[-1]]; rule = item["rule"]
            if nft_rule(rule["expr"], port) != (True, "ACCEPT"): return False
            allowed = [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}, {"counter": None}, {"accept": None}]
            if any(expr not in allowed for expr in rule["expr"]) or allowed[1] not in rule["expr"] or allowed[3] not in rule["expr"]: return False
            del new[candidates[-1]]
    legacy_same = all(saved_tables(before[key]) == saved_tables(after[key]) for key in ("legacy4", "legacy6")) if backend == "nft" else all(saved_tables(after["legacy" + str(v)]) == saved_tables(after["ip" + str(v)]) for v in (4, 6))
    return old == new and legacy_same and before["protected"] == after["protected"]
