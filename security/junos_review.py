#!/usr/bin/env python3
"""Review a Junos configuration written as `set` statements (the output of `show configuration | display set`).

Every finding has a rule id, a severity, the line it comes from, what is wrong and the fix. 16 rules, each in its own function
(check_JR001 ... check_JR016) so the tests can switch one off and see a test go red.

Written from the statement names and examples in Juniper's public documentation (security/vendor-docs/ holds the pages that
were read). It has been run on the sample configurations in security/junos/. It has never been run against a Junos device or a
vJunos image, so a statement form that the documentation does not show may be read wrongly or skipped (it is then reported as
an unparsed line, never silently).

    python security/junos_review.py security/junos/edge-fault-*.set
    python security/junos_review.py router.set --format json --fail-on high
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
MAX_BYTES = 5_000_000
MAX_LINE = 4000

PORT_NAMES = {"ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "http": 80, "ntp": 123, "snmp": 161,
              "snmptrap": 162, "bgp": 179, "https": 443, "syslog": 514, "netconf": 830, "netconf-ssh": 830}
PROTO_NAMES = {"icmp": 1, "tcp": 6, "udp": 17, "ospf": 89, "vrrp": 112, "gre": 47, "esp": 50, "ah": 51}
MGMT_PORTS = {22: "ssh", 23: "telnet", 830: "netconf", 161: "snmp"}
ADDR_FIELDS = {"source-address": "src", "source-prefix-list": "src", "destination-address": "dst",
               "destination-prefix-list": "dst", "address": "any", "prefix-list": "any"}
TERMINAL = {"accept", "discard", "reject"}
TRACKING = {"count", "log", "syslog"}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    fix: str
    text: str = ""

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "line": self.line, "message": self.message, "fix": self.fix,
                "statement": self.text}


@dataclass
class Stmt:
    line: int
    tokens: list[str]
    raw: str


@dataclass
class Term:
    name: str
    fields: dict = field(default_factory=dict)      # from-field -> list of values (strings)
    actions: dict = field(default_factory=dict)     # then-action -> list of values
    line: int = 0                                   # first line of the term
    last_line: int = 0


@dataclass
class Filter:
    name: str
    family: str
    terms: list = field(default_factory=list)
    line: int = 0


class Config:
    def __init__(self, stmts: list[Stmt], unparsed: list[tuple[int, str]], notes: list[str] | None = None):
        self.stmts = stmts
        self.unparsed = unparsed
        self.notes = notes or []

    def find(self, *prefix: str) -> list[Stmt]:
        """Statements whose leading tokens match prefix ('*' matches any one token)."""
        out = []
        for s in self.stmts:
            if len(s.tokens) >= len(prefix) and all(p == "*" or p == t for p, t in zip(prefix, s.tokens)):
                out.append(s)
        return out

    def has(self, *prefix: str) -> bool:
        return bool(self.find(*prefix))


# --- parsing -----------------------------------------------------------------------------------------------------------

def tokenize(line: str) -> list[str]:
    """Split on spaces, keeping a double quoted string as one token (quotes removed). An unbalanced quote keeps the rest of the
    line as one token instead of raising."""
    tokens, buf, in_q, i = [], [], False, 0
    while i < len(line):
        ch = line[i]
        if in_q:
            if ch == "\\" and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 1
            elif ch == '"':
                in_q = False
            else:
                buf.append(ch)
        elif ch == '"':
            in_q = True
            buf.append("")  # an empty quoted string is still a token
        elif ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


IGNORED = re.compile(r"^(#|##|\[edit|\{master|\{backup|\{primary|\{secondary|\w+@[\w.-]+[>#%]|/\*|\*/|\*\s|Last |\s*$)")


def parse_config(text: str) -> Config:
    """Parse set, delete, deactivate and insert lines. Anything else is kept in `unparsed`, never dropped without a trace."""
    stmts: list[Stmt] = []
    unparsed: list[tuple[int, str]] = []
    notes: list[str] = []
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        notes.append(f"input larger than {MAX_BYTES} bytes, not parsed")
        return Config([], [], notes)
    text = text.replace("\x00", "")
    brace_lines = 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if len(line) > MAX_LINE:
            unparsed.append((n, line[:60] + "..."))
            continue
        if not line or IGNORED.match(line):
            continue
        if line in ("{", "}") or line.endswith("{") or line.endswith(";"):
            brace_lines += 1
        toks = tokenize(line)
        if not toks:
            continue
        verb = toks[0]
        if verb == "set" and len(toks) > 1:
            stmts.append(Stmt(n, toks[1:], line))
        elif verb in ("delete", "deactivate") and len(toks) > 1:
            path = toks[1:]
            stmts = [s for s in stmts if s.tokens[: len(path)] != path]
        elif verb == "insert" and len(toks) > 1:
            stmts = apply_insert(stmts, toks[1:], n)
        elif verb in ("activate", "protect", "unprotect", "annotate", "rename", "replace"):
            continue
        else:
            unparsed.append((n, line[:80]))
    if brace_lines and not stmts:
        notes.append("the input looks like hierarchical (brace) format; convert it with `show configuration | display set`")
    return Config(stmts, unparsed, notes)


def apply_insert(stmts: list[Stmt], toks: list[str], n: int) -> list[Stmt]:
    """`insert firewall family inet filter F term A before term B` moves the statements of term A in front of (or after) term B."""
    try:
        i = next(k for k, t in enumerate(toks) if t in ("before", "after"))
        where, ref_path, mov_path = toks[i], toks[i + 1:], toks[:i]
    except StopIteration:
        return stmts
    if len(ref_path) < 2:
        return stmts
    parent = mov_path[:-2]
    ref_path = parent + ref_path
    mov = [s for s in stmts if s.tokens[: len(mov_path)] == mov_path]
    rest = [s for s in stmts if s.tokens[: len(mov_path)] != mov_path]
    idx = [k for k, s in enumerate(rest) if s.tokens[: len(ref_path)] == ref_path]
    if not mov or not idx:
        return stmts
    at = idx[0] if where == "before" else idx[-1] + 1
    return rest[:at] + mov + rest[at:]


# --- model helpers -----------------------------------------------------------------------------------------------------

def parse_port(tok: str):
    tok = tok.strip("[]")
    if tok in PORT_NAMES:
        return PORT_NAMES[tok], PORT_NAMES[tok]
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
    if m:
        lo = int(m.group(1))
        return lo, int(m.group(2) or lo)
    return None


def parse_net(tok: str):
    try:
        return ipaddress.ip_network(tok.strip("[]"), strict=False)
    except ValueError:
        return None


def prefix_lists(cfg: Config) -> dict[str, list]:
    out: dict[str, list] = {}
    for s in cfg.find("policy-options", "prefix-list"):
        if len(s.tokens) >= 4:
            net = parse_net(s.tokens[3])
            if net is not None:
                out.setdefault(s.tokens[2], []).append(net)
    return out


def filters(cfg: Config) -> list[Filter]:
    """Firewall filters in the order their terms appear. Handles `firewall family inet filter F ...` and `firewall filter F ...`."""
    out: dict[tuple, Filter] = {}
    for s in cfg.find("firewall"):
        t = s.tokens[1:]
        family = "inet"
        if t[:1] == ["family"] and len(t) >= 3:
            family, t = t[1], t[2:]
        if len(t) < 2 or t[0] != "filter":
            continue
        name, rest = t[1], t[2:]
        flt = out.setdefault((family, name), Filter(name, family, [], s.line))
        if not rest:
            continue
        if rest[0] == "term" and len(rest) >= 2:
            term_name, body = rest[1], rest[2:]
        else:
            term_name, body = "(unnamed)", rest
        term = next((x for x in flt.terms if x.name == term_name), None)
        if term is None:
            term = Term(term_name, line=s.line)
            flt.terms.append(term)
        term.last_line = s.line
        if body[:1] == ["from"] and len(body) >= 3:
            term.fields.setdefault(body[1], []).extend(body[2:])
        elif body[:1] == ["from"] and len(body) == 2:
            term.fields.setdefault(body[1], [])
        elif body[:1] == ["then"] and len(body) >= 2:
            term.actions.setdefault(body[1], []).extend(body[2:])
    return list(out.values())


def applied_filters(cfg: Config) -> dict[tuple[str, str], list[str]]:
    """(interface, direction) -> filter names, from `interfaces X unit N family F filter input|output|input-list ... NAME`."""
    out: dict[tuple[str, str], list[str]] = {}
    for s in cfg.find("interfaces"):
        t = s.tokens
        if "filter" in t:
            i = t.index("filter")
            if len(t) > i + 2 and t[i + 1] in ("input", "output", "input-list", "output-list"):
                direction = t[i + 1].split("-")[0]
                out.setdefault((t[1], direction), []).extend(x.strip("[]") for x in t[i + 2:])
    return out


def lo0_input_filters(cfg: Config) -> list[str]:
    names = []
    for (iface, direction), fl in applied_filters(cfg).items():
        if iface.startswith("lo0") and direction == "input":
            names.extend(fl)
    return names


def term_addresses(term: Term, plists: dict[str, list]):
    """-> {'src': nets or None, 'dst': nets or None, 'any': nets or None}. None = no restriction on that side. A value with
    `except`, or an unknown prefix list, makes the whole term 'complex' (returned as the string 'complex')."""
    res: dict = {"src": None, "dst": None, "any": None}
    for key, side in ADDR_FIELDS.items():
        if key not in term.fields:
            continue
        vals = term.fields[key]
        if "except" in vals:
            return "complex"
        nets = []
        for v in vals:
            v = v.strip("[]")
            if key.endswith("prefix-list"):
                if v not in plists:
                    return "complex"
                nets.extend(plists[v])
            else:
                net = parse_net(v)
                if net is None:
                    return "complex"
                nets.append(net)
        res[side] = (res[side] or []) + nets
    return res


def is_unrestricted(nets) -> bool:
    return nets is None or any(n.prefixlen == 0 for n in nets)


def ports_of(term: Term, key: str):
    out = []
    for v in term.fields.get(key, []):
        p = parse_port(v)
        if p is None:
            return None
        out.append(p)
    return out


def opens_any_source(term: Term, plists) -> bool:
    addr = term_addresses(term, plists)
    return addr != "complex" and is_unrestricted(addr["src"]) and is_unrestricted(addr["any"])


def last_terminal(term: Term) -> str | None:
    for a in ("discard", "reject", "accept"):
        if a in term.actions:
            return a
    return None


# --- the rules ---------------------------------------------------------------------------------------------------------

def finding(cfg: Config, rule: str, sev: str, line: int, msg: str, fix: str) -> Finding:
    text = next((s.raw for s in cfg.stmts if s.line == line), "")
    return Finding(rule, sev, line, msg, fix, text)


def check_JR001(cfg: Config) -> list[Finding]:
    """A firewall filter whose last term is not an unconditional discard or reject."""
    out = []
    for f in filters(cfg):
        if not f.terms:
            continue
        last = f.terms[-1]
        if not (last_terminal(last) in ("discard", "reject") and not last.fields):
            out.append(finding(cfg, "JR001", "medium", last.last_line,
                               f"filter {f.name} ({f.family}) has no final discard term; its last term is '{last.name}'. Junos "
                               "drops what no term matches, but silently: nothing is counted or logged.",
                               f"add a last term with no from clause: set firewall family {f.family} filter {f.name} term "
                               "discard-rest then count discard-rest then log then discard"))
    return out


def check_JR002(cfg: Config) -> list[Finding]:
    """A term that accepts any source to any destination."""
    out = []
    lo0 = set(lo0_input_filters(cfg))
    plists = prefix_lists(cfg)
    for f in filters(cfg):
        for t in f.terms:
            if "accept" not in t.actions:
                continue
            addr = term_addresses(t, plists)
            if addr == "complex":
                continue
            open_all = all(is_unrestricted(addr[k]) for k in ("src", "dst", "any"))
            narrowed = any(k in t.fields for k in ("protocol", "destination-port", "source-port", "port", "icmp-type",
                                                    "tcp-flags", "next-header"))
            if open_all and not narrowed:
                out.append(finding(cfg, "JR002", "critical" if f.name in lo0 else "high", t.line,
                                   f"term {t.name} in filter {f.name} accepts any source to any destination.",
                                   "match only the traffic the term is for: add from source-address or source-prefix-list, "
                                   "protocol and destination-port, or remove the term"))
    return out


def check_JR003(cfg: Config) -> list[Finding]:
    """Management services (ssh, telnet, netconf, snmp) reachable from 0.0.0.0/0."""
    out = []
    lo0 = set(lo0_input_filters(cfg))
    plists = prefix_lists(cfg)
    for f in filters(cfg):
        for t in f.terms:
            if "accept" not in t.actions or not opens_any_source(t, plists):
                continue
            dports = ports_of(t, "destination-port")
            if dports is None:
                continue
            hit = sorted({name for p, name in MGMT_PORTS.items() for lo, hi in dports if lo <= p <= hi})
            if hit:
                out.append(finding(cfg, "JR003", "critical" if f.name in lo0 else "high", t.line,
                                   f"term {t.name} in filter {f.name} accepts {', '.join(hit)} from any source address "
                                   "(0.0.0.0/0).",
                                   "limit the term with from source-prefix-list <management-hosts>, or remove it"))
    services = [s for s in cfg.find("system", "services") if s.tokens[2:3] and s.tokens[2] in ("ssh", "telnet", "netconf")]
    if services and not lo0:
        first = services[0]
        out.append(finding(cfg, "JR003", "high", first.line,
                           "management services are enabled and no firewall filter is applied to lo0 input, so ssh, telnet or "
                           "netconf answers on every interface from any address.",
                           "apply a filter that accepts management ports only from trusted prefixes and discards the rest: "
                           "set interfaces lo0 unit 0 family inet filter input protect-RE"))
    return out


def check_JR004(cfg: Config) -> list[Finding]:
    """Telnet, clear text J-Web (http) or ftp enabled."""
    out = []
    for s in cfg.find("system", "services"):
        t = s.tokens[2:]
        if t[:1] == ["telnet"]:
            out.append(finding(cfg, "JR004", "high", s.line, "telnet is enabled: passwords and sessions cross the network in clear text.",
                               "delete system services telnet and use ssh"))
        elif t[:2] == ["web-management", "http"]:
            out.append(finding(cfg, "JR004", "high", s.line, "J-Web is reachable over http (no encryption).",
                               "delete system services web-management http and use https with a certificate"))
        elif t[:1] == ["ftp"]:
            out.append(finding(cfg, "JR004", "medium", s.line, "the ftp service is enabled: clear text file transfer to the device.",
                               "delete system services ftp and use scp or sftp over ssh"))
    return out


def check_JR005(cfg: Config) -> list[Finding]:
    """Root login with a password only (no ssh key), or ssh root-login allow."""
    out = []
    root = cfg.find("system", "root-authentication")
    has_key = any(s.tokens[2:3] and s.tokens[2].startswith("ssh-") for s in root)
    pw = [s for s in root if s.tokens[2:3] and s.tokens[2] in ("encrypted-password", "plain-text-password")]
    if pw and not has_key:
        out.append(finding(cfg, "JR005", "high", pw[0].line,
                           "root authenticates with a password and no ssh public key is configured for root.",
                           "set system root-authentication ssh-ed25519 \"<public key>\" and keep the password for the console only"))
    for s in cfg.find("system", "services", "ssh", "root-login"):
        if s.tokens[4:5] == ["allow"]:
            out.append(finding(cfg, "JR005", "high", s.line, "ssh root-login is allowed.",
                               "set system services ssh root-login deny and log in as a named user"))
    return out


def check_JR006(cfg: Config) -> list[Finding]:
    """The SNMP community names everyone guesses."""
    out = []
    seen = set()
    for s in cfg.find("snmp", "community"):
        name = s.tokens[2] if len(s.tokens) > 2 else ""
        if name.lower() in ("public", "private") and name not in seen:
            seen.add(name)
            out.append(finding(cfg, "JR006", "high", s.line, f"SNMP community '{name}' is a default name.",
                               "use a long random community or SNMPv3, and restrict it with clients <prefix> restrict"))
    return out


def term_covers(a: Term, b: Term, plists) -> bool | None:
    """True when every packet that matches b also matches a (so a, placed earlier, takes all of b's traffic)."""
    aa, bb = term_addresses(a, plists), term_addresses(b, plists)
    if aa == "complex" or bb == "complex":
        return None
    for side in ("src", "dst", "any"):
        if aa[side] is None:
            continue
        if bb[side] is None:
            return False
        if not all(any(bn.version == an.version and bn.subnet_of(an) for an in aa[side]) for bn in bb[side]):
            return False
    for key in a.fields:
        if key in ADDR_FIELDS:
            continue
        if key not in b.fields:
            return False
        if key in ("destination-port", "source-port", "port"):
            ar, br = ports_of(a, key), ports_of(b, key)
            if ar is None or br is None:
                return False
            if not all(any(alo <= blo and bhi <= ahi for alo, ahi in ar) for blo, bhi in br):
                return False
        elif not set(b.fields[key]) <= set(a.fields[key]):
            return False
    return True


def check_JR007(cfg: Config) -> list[Finding]:
    """A term that can never match because an earlier term already takes all of its traffic (filters and routing policies)."""
    out = []
    plists = prefix_lists(cfg)
    for f in filters(cfg):
        for j, b in enumerate(f.terms):
            for a in f.terms[:j]:
                if last_terminal(a) is None or "next-term" in a.actions:
                    continue
                if term_covers(a, b, plists):
                    ta, tb = last_terminal(a), last_terminal(b)
                    sev = "high" if tb and ta != tb else "low"
                    why = (f"term {a.name} already {ta}s all of its traffic, so the {tb or 'action'} here never happens"
                           if tb and ta != tb else f"term {a.name} already takes all of its traffic")
                    out.append(finding(cfg, "JR007", sev, b.line, f"term {b.name} in filter {f.name} is shadowed: {why}.",
                                       f"move {b.name} before {a.name} (insert firewall family {f.family} filter {f.name} term "
                                       f"{b.name} before term {a.name}) or delete it"))
                    break
    out.extend(_policy_shadow(cfg))
    return out


def _policy_terms(cfg: Config) -> dict[str, list[Term]]:
    pols: dict[str, list[Term]] = {}
    for s in cfg.find("policy-options", "policy-statement"):
        t = s.tokens[2:]
        if len(t) < 2:
            continue
        name, rest = t[0], t[1:]
        terms = pols.setdefault(name, [])
        if rest[0] == "term" and len(rest) >= 2:
            tn, body = rest[1], rest[2:]
        else:
            tn, body = "(unnamed)", rest
        term = next((x for x in terms if x.name == tn), None)
        if term is None:
            term = Term(tn, line=s.line)
            terms.append(term)
        term.last_line = s.line
        if body[:1] == ["from"] and len(body) >= 2:
            term.fields.setdefault(body[1], []).extend(body[2:])
        elif body[:1] == ["then"] and len(body) >= 2:
            term.actions.setdefault(body[1], []).extend(body[2:])
    return pols


def _rf_list(term: Term):
    """route-filter entries as (network, kind, lo, hi); values come as: prefix exact|orlonger|longer|upto /N|prefix-length-range /a-/b."""
    vals = term.fields.get("route-filter", [])
    if not vals:
        return []
    net = parse_net(vals[0])
    if net is None:
        return None
    kind = vals[1] if len(vals) > 1 else "exact"
    lo, hi = net.prefixlen, net.prefixlen
    if kind == "orlonger":
        hi = net.max_prefixlen
    elif kind == "longer":
        lo, hi = net.prefixlen + 1, net.max_prefixlen
    elif kind == "upto" and len(vals) > 2:
        hi = int(vals[2].lstrip("/") or hi)
    elif kind == "prefix-length-range" and len(vals) > 2:
        m = re.fullmatch(r"/(\d+)-/(\d+)", vals[2])
        if not m:
            return None
        lo, hi = int(m.group(1)), int(m.group(2))
    return [(net, lo, hi)]


def _policy_covers(a: Term, b: Term) -> bool:
    if not a.fields:
        return True
    for key in a.fields:
        if key == "route-filter":
            ra, rb = _rf_list(a), _rf_list(b)
            if not ra or not rb or "route-filter" not in b.fields:
                return False
            (an, alo, ahi), (bn, blo, bhi) = ra[0], rb[0]
            if not (bn.version == an.version and bn.subnet_of(an) and alo <= blo and bhi <= ahi):
                return False
        elif key not in b.fields or not set(b.fields[key]) <= set(a.fields[key]):
            return False
    return True


def _policy_shadow(cfg: Config) -> list[Finding]:
    out = []
    for name, terms in _policy_terms(cfg).items():
        for j, b in enumerate(terms):
            for a in terms[:j]:
                if not (set(a.actions) & {"accept", "reject"}) or "next" in a.actions:
                    continue
                if _policy_covers(a, b):
                    out.append(finding(cfg, "JR007", "medium", b.line,
                                       f"term {b.name} in policy-statement {name} is shadowed: term {a.name} already "
                                       "takes all of its routes.",
                                       f"move {b.name} before {a.name} or delete it"))
                    break
    return out


def _bgp(cfg: Config):
    """-> (global statements, {group: statements}, [(group or None, neighbor, statements)], {group: type})"""
    g_stmts, groups, neigh = [], {}, {}
    for s in cfg.find("protocols", "bgp"):
        t = s.tokens[2:]
        if t[:1] == ["group"] and len(t) >= 2:
            gname, rest = t[1], t[2:]
            if rest[:1] == ["neighbor"] and len(rest) >= 2:
                neigh.setdefault((gname, rest[1]), []).append((s, rest[2:]))
            else:
                groups.setdefault(gname, []).append((s, rest))
        elif t[:1] == ["neighbor"] and len(t) >= 2:
            neigh.setdefault((None, t[1]), []).append((s, t[2:]))
        else:
            g_stmts.append((s, t))
    return g_stmts, groups, neigh


def _bgp_has(levels: list, pred) -> bool:
    return any(pred(rest) for stmts in levels for _s, rest in stmts)


def _bgp_check(cfg: Config, rule: str, sev: str, pred, what: str, fix: str, external_only: bool) -> list[Finding]:
    g_stmts, groups, neigh = _bgp(cfg)
    out = []
    for (gname, addr), nstmts in neigh.items():
        gl = groups.get(gname, []) if gname else []
        if external_only and gname and _bgp_has([gl], lambda r: r[:2] == ["type", "internal"]):
            continue
        if _bgp_has([g_stmts, gl, nstmts], pred):
            continue
        where = f"group {gname} neighbor {addr}" if gname else f"neighbor {addr}"
        out.append(finding(cfg, rule, sev, nstmts[0][0].line, f"BGP {where} has {what}.", fix.format(g=gname or "<group>", n=addr)))
    return out


def check_JR008(cfg: Config) -> list[Finding]:
    """A BGP neighbour with no authentication."""
    return _bgp_check(cfg, "JR008", "high",
                      lambda r: r[:1] in (["authentication-key"], ["authentication-algorithm"], ["authentication-key-chain"]),
                      "no authentication key (nothing stops a spoofed TCP session reset or a forged peer)",
                      "set protocols bgp group {g} neighbor {n} authentication-key \"<secret>\"", False)


def check_JR009(cfg: Config) -> list[Finding]:
    """An external BGP neighbour with no prefix-limit."""
    return _bgp_check(cfg, "JR009", "high",
                      lambda r: r[:1] == ["family"] and "prefix-limit" in r and "maximum" in r,
                      "no prefix-limit (a leak or a full table from this peer is accepted without bound)",
                      "set protocols bgp group {g} family inet unicast prefix-limit maximum 1000 teardown 80", True)


def check_JR010(cfg: Config) -> list[Finding]:
    """An external BGP neighbour with no import policy."""
    return _bgp_check(cfg, "JR010", "high", lambda r: r[:1] == ["import"],
                      "no import policy (every route the peer sends is accepted)",
                      "set protocols bgp group {g} import <policy-statement that ends with then reject>", True)


def check_JR011(cfg: Config) -> list[Finding]:
    """An external BGP neighbour with no export policy."""
    return _bgp_check(cfg, "JR011", "high", lambda r: r[:1] == ["export"],
                      "no export policy (every active BGP route is advertised to the peer)",
                      "set protocols bgp group {g} export <policy-statement that advertises only your own prefixes>", True)


def check_JR012(cfg: Config) -> list[Finding]:
    """A routing policy term that accepts everything: then accept with no from clause."""
    out = []
    applied = {x for s in cfg.find("protocols", "bgp") for i, x in enumerate(s.tokens) if i > 0 and s.tokens[i - 1] in ("import", "export")}
    for name, terms in _policy_terms(cfg).items():
        for t in terms:
            if "accept" in t.actions and not t.fields:
                out.append(finding(cfg, "JR012", "high" if name in applied else "medium", t.line,
                                   f"term {t.name} in policy-statement {name} accepts every route (then accept with no from clause).",
                                   "add a from clause (route-filter, prefix-list, community), and end the policy with then reject"))
    return out


def _discardish_nexthops(cfg: Config) -> set[str]:
    hosts = set()
    for s in cfg.find("routing-options", "static", "route"):
        if "discard" in s.tokens[4:] or "reject" in s.tokens[4:]:
            net = parse_net(s.tokens[3]) if len(s.tokens) > 3 else None
            if net is not None and net.num_addresses == 1:
                hosts.add(str(net.network_address))
    for s in cfg.find("interfaces", "dsc"):
        for tok in s.tokens:
            net = parse_net(tok) if "/" in tok or re.fullmatch(r"[\d.]+", tok) else None
            if net is not None:
                hosts.add(str(net.network_address))
    return hosts


def check_JR013(cfg: Config) -> list[Finding]:
    """A remotely triggered black hole (RTBH) style discard with no community check."""
    out = []
    discard_hosts = _discardish_nexthops(cfg)
    for name, terms in _policy_terms(cfg).items():
        for t in terms:
            nh = t.actions.get("next-hop")
            if nh is None:
                continue
            if (nh and nh[0] in ("discard", "reject")) or (nh and nh[0] in discard_hosts):
                if "community" not in t.fields:
                    out.append(finding(cfg, "JR013", "high", t.line,
                                       f"term {t.name} in policy-statement {name} sends routes to a discard next hop without "
                                       "matching a community, so any peer that sends a route can black-hole traffic.",
                                       "add from community <blackhole-community> to the term and accept the community only from "
                                       "peers allowed to trigger it"))
    for s in cfg.find("routing-options", "static", "route"):
        rest = s.tokens[4:]
        net = parse_net(s.tokens[3]) if len(s.tokens) > 3 else None
        if net is not None and net.num_addresses == 1 and ("discard" in rest or "reject" in rest):
            routes = [x for x in cfg.find("routing-options", "static", "route", s.tokens[3])]
            if not any("community" in x.tokens[4:] for x in routes):
                out.append(finding(cfg, "JR013", "medium", s.line,
                                   f"static discard route {s.tokens[3]} looks like a black hole trigger and carries no community.",
                                   f"set routing-options static route {s.tokens[3]} community <blackhole-community>"))
    return out


def check_JR014(cfg: Config) -> list[Finding]:
    """A filter term that discards or rejects with no count, log or syslog."""
    out = []
    for f in filters(cfg):
        for t in f.terms:
            if last_terminal(t) in ("discard", "reject") and not (set(t.actions) & TRACKING):
                out.append(finding(cfg, "JR014", "low", t.line,
                                   f"term {t.name} in filter {f.name} discards traffic with no count and no log, so what it drops "
                                   "is invisible.",
                                   f"set firewall family {f.family} filter {f.name} term {t.name} then count {t.name}-drops then log"))
    return out


def check_JR015(cfg: Config) -> list[Finding]:
    """No NTP server: log timestamps can not be trusted to line up with other systems."""
    if cfg.find("system", "ntp", "server") or cfg.find("system", "ntp", "peer") or cfg.find("system", "ntp", "boot-server"):
        return []
    return [Finding("JR015", "medium", 0, "no NTP server is configured, so timestamps in logs and alerts can drift from other systems.",
                    "set system ntp server <address>", "")]


def check_JR016(cfg: Config) -> list[Finding]:
    """No remote syslog host: logs stay on the device an attacker would clear."""
    if cfg.find("system", "syslog", "host"):
        return []
    return [Finding("JR016", "medium", 0, "no remote syslog host is configured, so logs stay on the device.",
                    "set system syslog host <collector> any notice", "")]


RULES = [check_JR001, check_JR002, check_JR003, check_JR004, check_JR005, check_JR006, check_JR007, check_JR008, check_JR009,
         check_JR010, check_JR011, check_JR012, check_JR013, check_JR014, check_JR015, check_JR016]


def review_text(text: str) -> list[Finding]:
    """Never raises: a rule that fails on odd input is reported as a JR000 finding instead of stopping the review."""
    try:
        cfg = parse_config(text)
    except Exception as exc:  # noqa: BLE001 - hostile input must not crash the reviewer
        return [Finding("JR000", "info", 0, f"the input could not be parsed ({exc.__class__.__name__})", "check that the file is Junos set output")]
    findings: list[Finding] = []
    for note in cfg.notes:
        findings.append(Finding("JR000", "info", 0, note, "run: show configuration | display set"))
    if not cfg.stmts:
        if not cfg.notes:
            findings.append(Finding("JR000", "info", 0, "no set statements found; nothing was reviewed",
                                    "run: show configuration | display set"))
        return findings
    for check in RULES:
        try:
            findings.extend(check(cfg))
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding("JR000", "info", 0, f"{check.__name__} could not read this configuration ({exc.__class__.__name__})",
                                    "report the statement that triggers it"))
    if cfg.unparsed:
        n, first = cfg.unparsed[0]
        findings.append(Finding("JR000", "info", n, f"{len(cfg.unparsed)} line(s) were not set statements and were skipped; first: {first!r}",
                                "check the file is `show configuration | display set` output", first))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.line, f.rule))
    return findings


def review_file(path: Path) -> list[Finding]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        return [Finding("JR000", "info", 0, f"cannot read {path}: {exc.__class__.__name__}", "check the path")]
    return review_text(data[: MAX_BYTES + 1].decode("utf-8", errors="replace"))


def format_text(path: str, findings: list[Finding]) -> str:
    if not findings:
        return f"{path}: no findings"
    lines = [f"{path}: {len(findings)} finding(s)"]
    for f in findings:
        where = f"line {f.line}" if f.line else "whole configuration"
        lines.append(f"  [{f.severity.upper():8}] {f.rule} {where}: {f.message}")
        if f.text:
            lines.append(f"             statement: {f.text}")
        lines.append(f"             fix: {f.fix}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Review Junos set-format configurations.")
    p.add_argument("files", nargs="+")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=SEVERITIES, default="low", help="exit 1 when a finding is at least this severe")
    args = p.parse_args(argv)
    worst, report = -1, {}
    for name in args.files:
        all_found = review_file(Path(name))
        found = [f for f in all_found if f.rule != "JR000"] + [f for f in all_found if f.rule == "JR000"]
        report[name] = found
        for f in found:
            if f.rule != "JR000":
                worst = max(worst, SEVERITIES.index(f.severity))
    if args.format == "json":
        print(json.dumps({k: [f.as_dict() for f in v] for k, v in report.items()}, indent=2))
    else:
        print("\n".join(format_text(k, v) for k, v in report.items()))
    return 1 if worst >= SEVERITIES.index(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
