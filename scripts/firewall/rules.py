"""Conservative proof for one NEW, external, local-unicast TCP/3000 flow.

No firewall commands here. Unsupported constructs fail closed; summaries are NOT
used as authorization. Both the iptables and native nft views must prove the path.
"""
import copy
import hashlib
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


# In iptables-nft compatibility mode nft JSON intentionally omits xt payloads.
# Both canonical views must match a reviewed stock profile, not merely the word
# "xt". User allow rules are excluded here and verified separately rule-by-rule.
def stock_user_file(raw, family):
    begin,end='### RULES ###\n','### END RULES ###\n'
    if raw.count(begin)!=1 or raw.count(end)!=1:raise Unsafe('STANDARD_UFW_PERSISTED_TEMPLATE_UNCONFIRMED')
    prefix,rest=raw.split(begin);body,suffix=rest.split(end)
    user=('ufw' if family==4 else 'ufw6')+'-user-'
    for line in body.splitlines():
        if not line.strip() or line.startswith('### tuple ###'):continue
        if not line.startswith(('-A '+user+'input ','-A '+user+'output ')):raise Unsafe('STANDARD_UFW_PERSISTED_TEMPLATE_UNCONFIRMED')
    # Never execute persisted -I instructions. Their complete logging/footer
    # template must equal the audited serializer, and all live base chains
    # must equal the corresponding independent kernel reference.
    template=hashlib.sha256((prefix+begin+end+suffix).encode()).hexdigest()
    headers='*filter\n:'+user+'input - [0:0]\n:'+user+'output - [0:0]\n'
    return template,saved_tables(headers+body+'\nCOMMIT\n')


def stock_shape(data):
    def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
    def user(chain):return chain in ('ufw-user-input','ufw-user-output','ufw6-user-input','ufw6-user-output')
    result={}
    for family in (4,6):
        tables=saved_tables(data['ip'+str(family)])
        grouped={name:{'chains':t['chains'],'rules':{chain:[r for r in t['rules'] if r[1]==chain] for chain in t['chains'] if not user(chain)}} for name,t in tables.items()}
        result['ip'+str(family)]=digest(grouped)
    topology=[];chains={}
    for item in json.loads(data['nft'])['nftables']:
        if set(item)=={'metainfo'}:continue
        if set(item) in ({'table'},{'chain'}):topology.append(clean_nft(item));continue
        if set(item)!={'rule'}:raise Unsafe('ADDITIONAL_NFT_FILTERING')
        r=item['rule']
        if not user(r['chain']):chains.setdefault((r['family'],r['table'],r['chain']),[]).append(clean_nft(r))
    result['nft']=digest({'topology':sorted(topology,key=lambda x:json.dumps(x,sort_keys=True)),
                          'rules':{'/'.join(k):v for k,v in chains.items()}})
    result['files']=digest({name:data['protected'][name] for name in ('/etc/ufw/before.rules','/etc/ufw/before6.rules','/etc/ufw/after.rules','/etc/ufw/after6.rules')})
    for family in (4,6):result['user'+str(family)]=stock_user_file(data['user'+str(family)],family)[0]
    return result


# Reviewed Ubuntu 24.04 UFW 0.36.2-6 stock kernel profiles. Filled from the
# isolated official-package CI reference, never from the target VPS itself.
# Kernel reference: CI 42994817792, independent x64/ARM64 outputs agree.
# Persisted templates: the same checksum-verified official serializer, low/off.
STANDARD_UFW_PROFILES = (
    {'files': '7cb9129a0b138217bf8f320a70b0643a5477d2cc5dbf2021c8adbae63312f2bc', 'ip4': '5277d00b029c6aaf684bc8fef8b769df64b7f9102bb17ecae88bbc10f457f69c', 'ip6': 'fee641b9764e16633862e0f2d0931234e30b69827024c772d1414e5cc87917cd', 'nft': '1390889094e4e83a3c29cb526466f88f3de1a229e66f1ec6be394db3348133da', 'user4': '9cc3b32090f301aa2a2467f714623ee645fb91bea872181639a3bf8b5a24b50d', 'user6': 'f6a851c2ae7edf22fa3c8cdb46b6c74771d5ac8da2ff9afa11f561002b611d79'},
    {'files': '7cb9129a0b138217bf8f320a70b0643a5477d2cc5dbf2021c8adbae63312f2bc', 'ip4': '35e35e3027222cdfaf089b6944cfe51d4dfd7b577783ba975c6d99021ddbf64d', 'ip6': 'cadc28e581f343d2f3443d4af3998eb08d81d356311b18c8f3a879619b7a8698', 'nft': '3c89bd114202a84222101301fd25c061877d45d32751ff0f513d2525d13c8143', 'user4': '25493247488f4b575019dd857968c874b61394c86aa4e075f18da9b59639b6d2', 'user6': '5ce4c65944298841692ce3166e9a166fa59379392422a8ce0979858b8a776eda'},
)


def stock_nft_profile(data, profiles=STANDARD_UFW_PROFILES):
    """Prove opaque xt compatibility data without guessing hidden parameters.

    Stock non-user chains must match BOTH decoded iptables and nft topology/
    expressions, plus original before/after files. Only simple per-port user
    allows are variable and each is correlated, in order, across both views.
    This narrow fallback does not interpret arbitrary xt extensions.
    """
    if stock_shape(data) not in profiles: raise Unsafe('STANDARD_UFW_PROFILE_UNCONFIRMED')
    entries = json.loads(data['nft'])['nftables']
    observed = {}
    users = ('ufw-user-input','ufw-user-output','ufw6-user-input','ufw6-user-output')
    for item in entries:
        if 'rule' not in item: continue
        r=item['rule']
        if r['chain'] not in users: continue
        if set(r)-{'family','table','chain','expr','handle','comment'}: raise Unsafe('STANDARD_UFW_USER_RULE_UNCONFIRMED')
        observed.setdefault((r['family'],r['table'],r['chain']),[]).append(r)
    expected_keys=set()
    for family,nf,prefix in ((4,'ip','ufw'),(6,'ip6','ufw6')):
        table=saved_tables(data['ip'+str(family)])['filter']
        for suffix in ('input','output'):
            chain=prefix+'-user-'+suffix;key=(nf,'filter',chain);expected_keys.add(key)
            ip_rules=[r for r in table['rules'] if r[1]==chain]; nft_rules=observed.get(key,[])
            if len(ip_rules)!=len(nft_rules):raise Unsafe('STANDARD_UFW_USER_RULE_UNCONFIRMED')
            for args,native in zip(ip_rules,nft_rules):
                # iptables-save may place comment/protocol modules in another
                # order than the UFW file. Parse only this conjunction of known
                # primitive options; never ignore unknown flags or duplicates.
                fields={};modules=[];i=2
                while i<len(args):
                    if i+1>=len(args):raise Unsafe('STANDARD_UFW_USER_IP_RULE_UNCONFIRMED')
                    key,value=args[i:i+2];i+=2
                    if key=='-m':modules.append(value)
                    elif key in ('-p','--dport','-j','--comment') and key not in fields:fields[key]=value
                    else:raise Unsafe('STANDARD_UFW_USER_IP_RULE_UNCONFIRMED')
                if set(fields)-{'-p','--dport','-j','--comment'} or not {'-p','--dport','-j'}<=set(fields) or fields['-p'] not in ('tcp','udp') or fields['-j']!='ACCEPT' or not fields['--dport'].isdigit() or not 1<=int(fields['--dport'])<=65535:
                    raise Unsafe('STANDARD_UFW_USER_IP_RULE_UNCONFIRMED')
                proto,port=fields['-p'],int(fields['--dport']);comment='--comment' in fields
                allowed_modules=[proto]+(['comment'] if comment else [])
                if len(modules)!=len(set(modules)) or any(m not in allowed_modules for m in modules) or ('comment' in modules)!=comment:
                    raise Unsafe('STANDARD_UFW_USER_IP_RULE_UNCONFIRMED')
                # Linux xt_comment.comment_mt() always returns true. Labels
                # prove no identity/ownership and cannot change this simple
                # ACCEPT selector. Keep their exact bytes in both post-deltas.
                if comment and len(fields['--comment'].encode())>256:raise Unsafe('STANDARD_UFW_USER_COMMENT_UNCONFIRMED')
                if native.get('comment') is not None and (type(native['comment']) is not str or len(native['comment'].encode())>256):raise Unsafe('STANDARD_UFW_USER_COMMENT_UNCONFIRMED')
                expr=[clean_nft(v) for v in native['expr'] if set(v)!={'counter'}]
                match={'match':{'op':'==','left':{'payload':{'protocol':proto,'field':'dport'}},'right':port}}
                annotation={'xt':{'type':'match','name':'comment'}}
                if sum(item==annotation for item in expr)!=int(comment):raise Unsafe('STANDARD_UFW_USER_NFT_RULE_UNCONFIRMED')
                expr=[item for item in expr if item!=annotation]
                tail=[{'accept':None}]
                candidates=[[match,*tail]]
                candidates.append([{'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':proto}},match,*tail])
                if family==4:
                    candidates.append([{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'protocol'}},'right':6 if proto=='tcp' else 17}},match,*tail])
                if json.dumps(expr,sort_keys=True) not in {json.dumps(c,sort_keys=True) for c in candidates}:raise Unsafe('STANDARD_UFW_USER_NFT_RULE_UNCONFIRMED')
    if set(observed)-expected_keys:raise Unsafe('STANDARD_UFW_USER_RULE_UNCONFIRMED')
    return entries
