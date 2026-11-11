"""Read-only explanation, never an admission proof or firewall editor.

Kernel nft metadata does not record the process that created a rule. Names are
untrusted hints only. All identities, addresses, comments, marks and targets
stay in private memory. TCP analysis deliberately over-approximates reachable
effects; unknown predicates/expressions never establish safety.
"""
import json
import re

NFT_PORTS = (22, 80, 443)
NFT_FAMILIES = ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev')
NFT_HOOKS = ('ingress', 'prerouting', 'input', 'forward', 'output', 'postrouting', 'egress')
NFT_EFFECTS = ('ACCEPT_OBSERVED', 'DROP_POSSIBLE', 'REJECT_POSSIBLE', 'NAT_POSSIBLE',
               'TPROXY_POSSIBLE', 'MARK_OR_TRACKING_POSSIBLE', 'UNKNOWN_REVIEW_REQUIRED')
NFT_STATES = ('OBSERVED', 'READ_FAILED', 'DATA_INVALID', 'LIMIT_EXCEEDED', 'SNAPSHOT_CHANGED')
NFT_FEATURES = ('NAT', 'TPROXY', 'MARK_OR_TRACKING', 'OPAQUE_XT', 'INDIRECT_MAP', 'UNKNOWN')


class NftAuditError(Exception):
    pass


def nft_document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError()
            result[key] = value
        return result
    def reject(_): raise ValueError()
    if type(raw) is not str or len(raw) > 2 * 1024**2: raise ValueError()
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    if type(value) is not dict or set(value) != {'nftables'} or type(value['nftables']) is not list: raise ValueError()
    if len(value['nftables']) > 20000: raise NftAuditError()
    for item in value['nftables']:
        if type(item) is not dict or len(item) != 1 or type(next(iter(item.values()))) is not dict: raise ValueError()
    return value['nftables']


def nft_stable(value):
    # Packet counters are volatile, but chain/rule identities and ordering are not.
    if type(value) is dict:
        return {k: nft_stable(v) for k, v in value.items() if k not in ('metainfo', 'counter')}
    if type(value) is list: return [nft_stable(v) for v in value]
    return value


def nft_tcp_condition(match, port, reply):
    if type(match) is not dict or set(match) != {'left', 'op', 'right'}: return None
    left, op, right = (match[k] for k in ('left', 'op', 'right'))
    if left == {'meta': {'key': 'l4proto'}}:
        actual = 'tcp'
        if right == 6: right = 'tcp'
        def literal(v): return type(v) is str and v in ('tcp', 'udp', 'icmp', 'ipv6-icmp', 'sctp', 'esp', 'ah', 'gre')
    elif left == {'payload': {'protocol': 'tcp', 'field': 'sport' if reply else 'dport'}}:
        actual = port
        def literal(v): return type(v) is int and 0 <= v <= 65535
    else: return None
    if type(right) is dict and set(right) == {'range'}:
        r = right['range']
        if type(actual) is not int or type(r) is not list or len(r) != 2 or not all(literal(v) for v in r) or r[0] > r[1]: return None
        matches = r[0] <= actual <= r[1]
    elif type(right) is dict and set(right) == {'set'}:
        r = right['set']
        if type(r) is not list or len(r) > 1024 or not all(literal(v) for v in r): return None
        matches = actual in r
    elif literal(right): matches = actual == right
    else: return None
    if op in ('==', 'in'): return matches
    if op in ('!=', 'not in'): return not matches
    return None


def nft_hook_effects(key, chains, rules, port):
    """Possible ingress destination / local reply source port effects.

    Do not infer a global ACCEPT: other hooks, routing, provider filters and
    connection tracking may still block. Rules after a terminal verdict are
    conservatively retained. Side effects BEFORE a false match are retained.
    """
    root = chains[key]; hook = root.get('hook')
    reply = hook in ('output', 'postrouting', 'egress')
    effects = set(); budget = [4000]
    if root.get('policy') == 'drop': effects.add('DROP_POSSIBLE')
    elif root.get('policy') != 'accept': effects.add('UNKNOWN_REVIEW_REQUIRED')
    if key[0] not in ('ip', 'ip6', 'inet') or hook == 'forward': effects.add('UNKNOWN_REVIEW_REQUIRED')
    def walk(current, stack):
        if current in stack or current not in chains or len(stack) >= 12:
            effects.add('UNKNOWN_REVIEW_REQUIRED'); return
        for expressions in rules.get(current, []):
            for expr in expressions:
                budget[0] -= 1
                if budget[0] < 0: raise NftAuditError()
                if type(expr) is not dict or len(expr) != 1:
                    effects.add('UNKNOWN_REVIEW_REQUIRED'); continue
                name, body = next(iter(expr.items()))
                if name == 'match':
                    condition = nft_tcp_condition(body, port, reply)
                    if condition is False: break
                    if condition is None: effects.add('UNKNOWN_REVIEW_REQUIRED')
                elif name in ('counter', 'log'): pass
                elif name == 'accept': effects.add('ACCEPT_OBSERVED')
                elif name == 'drop': effects.add('DROP_POSSIBLE')
                elif name == 'reject': effects.add('REJECT_POSSIBLE')
                elif name in ('dnat', 'snat', 'redirect', 'masquerade'): effects.add('NAT_POSSIBLE')
                elif name == 'tproxy': effects.add('TPROXY_POSSIBLE')
                elif name in ('mangle', 'notrack', 'ct'): effects.add('MARK_OR_TRACKING_POSSIBLE')
                elif name in ('jump', 'goto'):
                    if type(body) is dict and set(body) == {'target'} and type(body['target']) is str:
                        walk((*current[:2], body['target']), (*stack, current))
                    else: effects.add('UNKNOWN_REVIEW_REQUIRED')
                elif name != 'return': effects.add('UNKNOWN_REVIEW_REQUIRED')
    walk(key, ())
    return sorted(effects)


def nft_hook_features(key, rules):
    # Structural purpose is independent of TCP applicability (e.g. UDP proxy).
    features=set(); todo=[key]; seen=set(); budget=4000
    while todo:
        current=todo.pop()
        if current in seen: continue
        seen.add(current)
        for expressions in rules.get(current,[]):
            for expr in expressions:
                budget-=1
                if budget<0: raise NftAuditError()
                if type(expr) is not dict or len(expr)!=1:features.add('UNKNOWN');continue
                name,body=next(iter(expr.items()))
                feature={'dnat':'NAT','snat':'NAT','redirect':'NAT','masquerade':'NAT','tproxy':'TPROXY',
                    'mangle':'MARK_OR_TRACKING','notrack':'MARK_OR_TRACKING','ct':'MARK_OR_TRACKING',
                    'xt':'OPAQUE_XT','vmap':'INDIRECT_MAP','lookup':'INDIRECT_MAP'}.get(name)
                if feature:features.add(feature)
                if name in ('jump','goto') and type(body) is dict and type(body.get('target')) is str:
                    todo.append((*current[:2],body['target']))
    return sorted(features)


def nft_hooks_summary(nft_raw, ip4, ip6, units=''):
    entries = nft_document(nft_raw); chains = {}; rules = {}
    for item in entries:
        if 'chain' in item:
            chain = item['chain']; key = tuple(chain.get(k) for k in ('family', 'table', 'name'))
            if not all(type(v) is str for v in key) or key in chains: raise ValueError()
            chains[key] = chain
        elif 'rule' in item:
            rule = item['rule']; key = tuple(rule.get(k) for k in ('family', 'table', 'chain'))
            if not all(type(v) is str for v in key) or type(rule.get('expr')) is not list: raise ValueError()
            rules.setdefault(key, []).append(rule['expr'])
    if set(rules) - set(chains): raise ValueError()
    base = [key for key, chain in chains.items() if 'hook' in chain]
    if len(base) > 32: raise NftAuditError()
    visible = set()
    for family, text in (('ip', ip4), ('ip6', ip6)):
        table = None
        for line in text.splitlines():
            if line.startswith('*'): table = line[1:]
            elif line.startswith(':') and table: visible.add((family, table, line.split()[0][1:]))
            elif line == 'COMMIT': table = None
    result = []
    for index, key in enumerate(base):
        chain = chains[key]
        ports = {str(p): nft_hook_effects(key, chains, rules, p) for p in NFT_PORTS}
        effects = {e for group in ports.values() for e in group}
        features = nft_hook_features(key, rules)
        labels = key[1] + ' ' + key[2]
        hint = ('VPN_NAME_HINT_ONLY' if re.search(r'(?:^|[^a-z0-9])(?:xray|x-ui|3x-ui|tproxy)(?:$|[^a-z0-9])', labels, re.I)
                else 'UFW_NAME_HINT_ONLY' if key[2].startswith(('ufw-', 'ufw6-')) else 'UNATTRIBUTED')
        purpose = ('TRANSPARENT_PROXY_PATTERN' if 'TPROXY' in features else
                   'NAT_PATTERN' if 'NAT' in features else
                   'PACKET_MARKING_PATTERN' if 'MARK_OR_TRACKING' in features else
                   'OPAQUE_PATTERN' if 'UNKNOWN_REVIEW_REQUIRED' in effects else 'FILTER_PATTERN')
        result.append({'id': f'H{index+1:02}', 'family': key[0] if key[0] in NFT_FAMILIES else 'unknown',
            'hook': chain['hook'] if chain['hook'] in NFT_HOOKS else 'unknown',
            'type': chain.get('type') if chain.get('type') in ('filter', 'nat', 'route') else 'unknown',
            'priority': chain.get('prio') if type(chain.get('prio')) is int and -(2**31) <= chain['prio'] < 2**31 else None,
            'policy': chain.get('policy') if chain.get('policy') in ('accept', 'drop') else 'unknown',
            'iptables_view': 'CHAIN_NAME_PRESENT' if key in visible else 'NFT_ONLY',
            'origin_hint': hint, 'purpose': purpose, 'features': features, 'tcp': ports})
    vpn = any(re.match(r'^(?:xray|x-ui|3x-ui)\.service\s+loaded\s+active\s', line) for line in units.splitlines())
    return {'state': 'OBSERVED', 'creator': 'NOT_PROVEN', 'vpn_unit_active': vpn, 'hooks': result}


def audit_nft_hooks(run, units=''):
    failed = {'state': 'READ_FAILED', 'creator': 'NOT_PROVEN', 'vpn_unit_active': False, 'hooks': []}
    try:
        names = ('nft', 'iptables', 'ip6tables')
        first = {name: run(name) for name in names}
        if any(state != 'ok' for state, _ in first.values()): return failed
        result = nft_hooks_summary(*(first[name][1] for name in names), units)
        after = {name: run(name) for name in names}
        if any(state != 'ok' for state, _ in after.values()): return failed
        # Counters/time comments are the only ignored changes in these snapshots.
        def ip_stable(raw): return [re.sub(r'\[\d+:\d+\]', '[0:0]', line) for line in raw.splitlines() if not line.startswith('#')]
        if (nft_stable(nft_document(first['nft'][1])) != nft_stable(nft_document(after['nft'][1])) or
                any(ip_stable(first[name][1]) != ip_stable(after[name][1]) for name in names[1:])):
            return {**failed, 'state': 'SNAPSHOT_CHANGED'}
        return result
    except NftAuditError: return {**failed, 'state': 'LIMIT_EXCEEDED'}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, IndexError):
        return {**failed, 'state': 'DATA_INVALID'}


def valid_nft_audit(value):
    # Exact output vocabulary: runner rejects unexpected strings/identities.
    if type(value) is not dict or set(value) != {'state', 'creator', 'vpn_unit_active', 'hooks'}: return False
    if value['state'] not in NFT_STATES or value['creator'] != 'NOT_PROVEN' or type(value['vpn_unit_active']) is not bool: return False
    hooks = value['hooks']
    if type(hooks) is not list or len(hooks) > 32 or value['state'] != 'OBSERVED' and hooks: return False
    for i, h in enumerate(hooks):
        if type(h) is not dict or set(h) != {'id','family','hook','type','priority','policy','iptables_view','origin_hint','purpose','features','tcp'}: return False
        if (h['id'] != f'H{i+1:02}' or h['family'] not in (*NFT_FAMILIES, 'unknown') or h['hook'] not in (*NFT_HOOKS, 'unknown') or
            h['type'] not in ('filter','nat','route','unknown') or h['policy'] not in ('accept','drop','unknown') or
            h['iptables_view'] not in ('CHAIN_NAME_PRESENT','NFT_ONLY') or
            h['origin_hint'] not in ('VPN_NAME_HINT_ONLY','UFW_NAME_HINT_ONLY','UNATTRIBUTED') or
            h['purpose'] not in ('TRANSPARENT_PROXY_PATTERN','NAT_PATTERN','PACKET_MARKING_PATTERN','OPAQUE_PATTERN','FILTER_PATTERN')): return False
        if h['priority'] is not None and (type(h['priority']) is not int or not -(2**31) <= h['priority'] < 2**31): return False
        features=h['features']
        if type(features) is not list or len(features)>len(NFT_FEATURES) or any(type(f) is not str or f not in NFT_FEATURES for f in features): return False
        if features!=sorted(set(features)): return False
        if type(h['tcp']) is not dict or set(h['tcp']) != {'22','80','443'}: return False
        for group in h['tcp'].values():
            if type(group) is not list or len(group) > len(NFT_EFFECTS) or any(type(e) is not str or e not in NFT_EFFECTS for e in group): return False
            if group != sorted(set(group)): return False
    return True
