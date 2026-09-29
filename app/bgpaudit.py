"""Stateless BGP announcement auditing.

This module is pure computation: it never reads or writes the database.  The
input is an AS relationship graph plus a batch of announcements, each carrying
a unique ``id``, an IPv4 ``prefix`` and an ``as_path`` ordered from the
**observer vantage point towards the origin** (the order BGP records the
AS_PATH in).

Path processing
---------------

Consecutive duplicate ASNs are collapsed (prepending is ignored).  An ASN that
reappears *non-consecutively* after folding closes an AS loop and the
announcement is marked ``as_loop``.

Every other hop (a pair of adjacent ASNs after folding) must exist in the
relationship graph, and the hop sequence must be valley-free:

    zero or more customer->provider hops,
    at most one peer hop,
    zero or more provider->customer hops.

The first hop that breaks this order is reported.  The rule is invariant under
path reversal, mirroring the classical Gao-Rexford export rules expressed in
the origin->observer direction.

Prefix comparison
------------------

Only announcements that pass the path audit participate:

* ``moas``          - the same prefix is originated by more than one AS;
* ``origin_change`` - a more-specific prefix is originated by an AS that is not
                      among the origins of its nearest (longest-prefix)
                      covering prefix.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .cidrmath import parse_network

# Relationship kinds as declared in requests.
C2P = "c2p"
PEER = "peer"

# Directional hop relationships as traversed along the (observer->origin) path.
HOP_C2P = "customer_to_provider"
HOP_P2C = "provider_to_customer"
HOP_PEER = "peer"

# Announcement audit outcomes.
STATUS_VALID = "valid"
STATUS_LOOP = "as_loop"
STATUS_INVALID = "invalid_path"


class BgpAuditError(Exception):
    """An audit input that cannot be processed (mapped to HTTP 422)."""

    def __init__(self, detail: str, code: str):
        super().__init__(detail)
        self.detail = detail
        self.code = code


@dataclass(frozen=True)
class HopViolation:
    """The first hop that breaks the c2p* peer? p2c* path order."""

    index: int
    source: int
    target: int
    relationship: str
    reason: str


def fold_as_path(as_path: list[int]) -> list[int]:
    """Collapse consecutive duplicate ASNs (BGP prepending), nothing else."""

    folded: list[int] = []
    for asn in as_path:
        if not folded or folded[-1] != asn:
            folded.append(asn)
    return folded


def _pair_key(a: int, b: int) -> tuple[int, int]:
    return (a, b) if a < b else (b, a)


def _describe_entry(entry: tuple) -> str:
    if entry[0] == PEER:
        return "peer"
    return f"customer {entry[1]} -> provider {entry[2]}"


def build_relationships(
    raw: list[tuple[str, int, int]],
) -> dict[tuple[int, int], tuple]:
    """Index declared relationships by unordered AS pair.

    ``raw`` holds ``("c2p", customer, provider)`` and ``("peer", a, b)``
    triples.  An exact duplicate declaration is accepted; declaring the same
    AS pair both ways (or as c2p and peer) is a conflict.
    """

    rels: dict[tuple[int, int], tuple] = {}
    for kind, a, b in raw:
        if a == b:
            raise BgpAuditError(
                f"relationship declares AS {a} adjacent to itself",
                code="bgp_self_relationship",
            )
        entry = ("c2p", a, b) if kind == C2P else (PEER,)
        key = _pair_key(a, b)
        existing = rels.get(key)
        if existing is not None and existing != entry:
            raise BgpAuditError(
                f"AS pair {key[0]}/{key[1]} declares conflicting relationships: "
                f"{_describe_entry(existing)} vs {_describe_entry(entry)}",
                code="bgp_relationship_conflict",
            )
        rels[key] = entry
    return rels


def hop_relationship(
    rels: dict[tuple[int, int], tuple], a: int, b: int
) -> str | None:
    """Resolve the traversal direction of hop ``a -> b``.

    Returns one of the ``HOP_*`` constants, or ``None`` when the pair is not
    declared.
    """

    entry = rels.get(_pair_key(a, b))
    if entry is None:
        return None
    if entry[0] == PEER:
        return HOP_PEER
    _, customer, provider = entry
    if a == customer and b == provider:
        return HOP_C2P
    return HOP_P2C


def audit_folded_path(
    folded: list[int],
    rels: dict[tuple[int, int], tuple],
) -> HopViolation | None:
    """Validate a folded, loop-free path against the valley-free rule.

    Raises :class:`BgpAuditError` when a hop joins two ASNs with no declared
    relationship.  Otherwise returns the first violating hop, or ``None`` for
    a valid path.
    """

    # "up" allows customer->provider hops; "peer" has consumed the single
    # optional peer hop; "down" only allows provider->customer hops.
    phase = "up"
    for index, (a, b) in enumerate(zip(folded, folded[1:])):
        hop = hop_relationship(rels, a, b)
        if hop is None:
            raise BgpAuditError(
                f"AS {a} and AS {b} are adjacent in an announcement path but "
                "no relationship is declared between them",
                code="bgp_unknown_relationship",
            )
        if hop == HOP_C2P:
            if phase == "peer":
                reason = "customer_to_provider_after_peer"
            elif phase == "down":
                reason = "customer_to_provider_after_provider_to_customer"
            else:
                continue
            return HopViolation(index, a, b, hop, reason)
        if hop == HOP_PEER:
            if phase == "down":
                reason = "peer_after_provider_to_customer"
            elif phase == "peer":
                reason = "multiple_peer_hops"
            else:
                phase = "peer"
                continue
            return HopViolation(index, a, b, hop, reason)
        # provider->customer is legal in every phase and moves into "down".
        phase = "down"
    return None


def _result(
    ann_id: str,
    network: ipaddress.IPv4Network,
    folded: list[int],
    status: str,
    flags: list[str] | None = None,
    violation: HopViolation | None = None,
) -> dict:
    return {
        "id": ann_id,
        "network": network,
        "prefix": str(network),
        "as_path": folded,
        "origin": folded[-1],
        "status": status,
        "flags": flags or [],
        "violating_hop": (
            None
            if violation is None
            else {
                "index": violation.index,
                "source": violation.source,
                "target": violation.target,
                "relationship": violation.relationship,
                "reason": violation.reason,
            }
        ),
    }


def audit_announcements(
    raw_relationships: list[tuple[str, int, int]],
    raw_announcements: list[tuple[str, str, list[int]]],
) -> dict:
    """Audit a batch and compare the announcements that pass path audit.

    ``raw_announcements`` holds ``(id, prefix, as_path)`` triples.  Returns a
    dict with a stable-sorted ``results`` list and a ``summary`` counter.
    Raises :class:`BgpAuditError` for request-wide 422 conditions.
    """

    rels = build_relationships(raw_relationships)

    # Parse and fold every announcement first; duplicate ids and bad prefixes
    # reject the whole batch before any per-announcement outcome is produced.
    seen_ids: set[str] = set()
    parsed: list[tuple[str, ipaddress.IPv4Network, list[int]]] = []
    for ann_id, prefix_value, as_path in raw_announcements:
        if ann_id in seen_ids:
            raise BgpAuditError(
                f"duplicate announcement id {ann_id!r}",
                code="bgp_duplicate_announcement_id",
            )
        seen_ids.add(ann_id)
        try:
            network = parse_network(prefix_value)
        except ValueError as exc:
            raise BgpAuditError(
                f"invalid announcement prefix {prefix_value!r} for "
                f"announcement {ann_id!r}: {exc}",
                code="invalid_cidr",
            )
        parsed.append((ann_id, network, fold_as_path(as_path)))

    results: list[dict] = []
    for ann_id, network, folded in parsed:
        # A non-consecutive repeat closes a loop; such announcements never
        # participate in edge validation or prefix comparison.
        if len(set(folded)) != len(folded):
            results.append(_result(ann_id, network, folded, STATUS_LOOP))
            continue
        violation = audit_folded_path(folded, rels)
        if violation is None:
            results.append(_result(ann_id, network, folded, STATUS_VALID, flags=[]))
        else:
            results.append(_result(ann_id, network, folded, STATUS_INVALID, violation=violation))

    _flag_prefix_findings(results)

    results.sort(
        key=lambda r: (
            int(r["network"].network_address),
            r["network"].prefixlen,
            r["id"],
        )
    )

    summary = {
        "total": len(results),
        "valid": sum(1 for r in results if r["status"] == STATUS_VALID),
        "as_loop": sum(1 for r in results if r["status"] == STATUS_LOOP),
        "invalid_path": sum(1 for r in results if r["status"] == STATUS_INVALID),
        "moas": sum(1 for r in results if "moas" in r["flags"]),
        "origin_change": sum(1 for r in results if "origin_change" in r["flags"]),
    }

    return {
        "results": [
            {key: value for key, value in r.items() if key != "network"}
            for r in results
        ],
        "summary": summary,
    }


def _flag_prefix_findings(results: list[dict]) -> None:
    """Add ``moas`` / ``origin_change`` flags in place (valid announcements only)."""

    valid = [r for r in results if r["status"] == STATUS_VALID]

    # Exact-prefix groups; more than one distinct origin in a group is MOAS.
    groups: dict[ipaddress.IPv4Network, list[dict]] = {}
    for r in valid:
        groups.setdefault(r["network"], []).append(r)
    for items in groups.values():
        if len({r["origin"] for r in items}) > 1:
            for r in items:
                r["flags"].append("moas")

    # A more-specific announcement whose origin is not among the origins of its
    # nearest (longest-prefix) covering prefix is an origin change.
    coverings = list(groups)
    for r in valid:
        network: ipaddress.IPv4Network = r["network"]
        nearest: ipaddress.IPv4Network | None = None
        for other in coverings:
            if other != network and network.subnet_of(other):
                if nearest is None or other.prefixlen > nearest.prefixlen:
                    nearest = other
        if nearest is not None and r["origin"] not in {
            x["origin"] for x in groups[nearest]
        }:
            r["flags"].append("origin_change")
