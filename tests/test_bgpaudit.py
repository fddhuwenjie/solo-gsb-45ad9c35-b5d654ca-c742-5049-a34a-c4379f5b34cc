"""Unit tests for stateless BGP announcement auditing."""

from __future__ import annotations

import ipaddress

import pytest

from app.bgpaudit import (
    BgpAuditError,
    audit_announcements,
    fold_as_path,
)


def _rels(simple: bool = True):
    # Topology:
    #   65001/65002 -> 100 -> 10 ==peer== 20 <- 65003
    return [
        ("c2p", 65001, 100),
        ("c2p", 65002, 100),
        ("c2p", 100, 10),
        ("peer", 10, 20),
        ("c2p", 65003, 20),
    ]


def _audit(announcements, relationships=None, extra_rels=None):
    rels = relationships if relationships is not None else _rels()
    if extra_rels:
        rels = rels + extra_rels
    return audit_announcements(rels, announcements)


def _by_id(out):
    return {r["id"]: r for r in out["results"]}


# ---------------------------------------------------------------------------
# Folding and loops
# ---------------------------------------------------------------------------


def test_fold_collapses_only_consecutive_repeats():
    assert fold_as_path([1, 1, 2, 3, 3, 3, 4]) == [1, 2, 3, 4]
    assert fold_as_path([7, 7, 7]) == [7]
    assert fold_as_path([]) == []


def test_consecutive_prepending_is_folded_and_valid():
    out = _audit([("a", "203.0.113.0/24", [65001, 65001, 100, 100, 10, 20, 65003])])
    r = out["results"][0]
    assert r["status"] == "valid"
    assert r["as_path"] == [65001, 100, 10, 20, 65003]
    assert r["origin"] == 65003


def test_non_consecutive_repeat_is_as_loop():
    out = _audit([("a", "203.0.113.0/24", [65001, 100, 10, 100, 65003])])
    r = out["results"][0]
    assert r["status"] == "as_loop"
    assert r["as_path"] == [65001, 100, 10, 100, 65003]
    assert r["violating_hop"] is None


def test_loop_takes_precedence_over_policy_shape():
    # The path also has a valley, but the loop is reported instead.
    out = _audit([("a", "203.0.113.0/24", [100, 10, 100])])
    assert out["results"][0]["status"] == "as_loop"


def test_single_origin_asn_is_valid():
    out = audit_announcements([], [("a", "203.0.113.0/24", [65001, 65001])])
    r = out["results"][0]
    assert r["status"] == "valid"
    assert r["as_path"] == [65001]
    assert r["origin"] == 65001


# ---------------------------------------------------------------------------
# Valley-free ordering
# ---------------------------------------------------------------------------


def test_c2p_up_then_peer_then_p2c_down_is_valid():
    out = _audit([("a", "203.0.113.0/24", [65001, 100, 10, 20, 65003])])
    assert out["results"][0]["status"] == "valid"


def test_reverse_direction_is_also_valley_free():
    # Observer on the other side: up the c2p links towards 20, peer, then down.
    out = _audit([("a", "203.0.113.0/24", [65003, 20, 10, 100, 65001])])
    assert out["results"][0]["status"] == "valid"


def test_all_customer_to_provider_path_is_valid():
    out = _audit([("a", "203.0.113.0/24", [65001, 100, 10])])
    assert out["results"][0]["status"] == "valid"


def test_all_provider_to_customer_path_is_valid():
    out = _audit([("a", "203.0.113.0/24", [10, 100, 65001])])
    assert out["results"][0]["status"] == "valid"


def test_valley_p2c_then_c2p_locates_first_violation():
    # 99 -> 100 (c2p), 100 -> 65001 (p2c), 65001 -> 50 (c2p)
    rels = _rels() + [("c2p", 99, 100), ("c2p", 65001, 50)]
    out = audit_announcements(rels, [("a", "1.2.3.0/24", [99, 100, 65001, 50])])
    hop = out["results"][0]["violating_hop"]
    assert out["results"][0]["status"] == "invalid_path"
    assert hop == {
        "index": 2,
        "source": 65001,
        "target": 50,
        "relationship": "customer_to_provider",
        "reason": "customer_to_provider_after_provider_to_customer",
    }


def test_second_peer_hop_is_violation():
    # ... 10 ==peer== 20 ==peer== 30 ...
    rels = _rels() + [("peer", 20, 30), ("c2p", 77, 30)]
    out = audit_announcements(
        rels, [("a", "1.2.3.0/24", [65001, 100, 10, 20, 30, 77])]
    )
    hop = out["results"][0]["violating_hop"]
    assert hop["index"] == 3
    assert hop["source"] == 20
    assert hop["target"] == 30
    assert hop["reason"] == "multiple_peer_hops"


def test_peer_after_down_hill_is_violation():
    # p2c then peer: 10 -> 100 -> 65001, then 65001 peers with 88.
    rels = _rels() + [("peer", 65001, 88), ("c2p", 99, 88)]
    out = audit_announcements(
        rels, [("a", "1.2.3.0/24", [10, 100, 65001, 88, 99])]
    )
    hop = out["results"][0]["violating_hop"]
    assert hop["index"] == 2
    assert hop["reason"] == "peer_after_provider_to_customer"


def test_c2p_after_peer_is_violation():
    # peer 10->20, then uphill c2p 20->30
    rels = _rels() + [("c2p", 20, 30), ("c2p", 77, 30)]
    out = audit_announcements(
        rels, [("a", "1.2.3.0/24", [65001, 100, 10, 20, 30, 77])]
    )
    hop = out["results"][0]["violating_hop"]
    assert hop["index"] == 3
    assert hop["reason"] == "customer_to_provider_after_peer"


def test_violation_points_at_first_offending_hop_only():
    rels = _rels() + [("c2p", 99, 100), ("c2p", 65001, 50)]
    folded = [99, 100, 65001, 50, 51]
    rels.append(("c2p", 50, 51))
    out = audit_announcements(rels, [("a", "1.2.3.0/24", folded)])
    # Hop 2 is the valley; hop 3 is fine relative to the reported failure.
    assert out["results"][0]["violating_hop"]["index"] == 2


# ---------------------------------------------------------------------------
# Relationship graph errors (whole-request 422)
# ---------------------------------------------------------------------------


def test_adjacent_asns_without_relationship_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements(
            [("c2p", 65001, 100)],
            [("a", "1.2.3.0/24", [65001, 100, 777])],
        )
    assert exc.value.code == "bgp_unknown_relationship"


def test_loop_announcement_does_not_require_unknown_edge_relationship():
    # The un-declared edge appears inside a looped path; the loop wins and no
    # relationship lookup is demanded.
    out = audit_announcements(
        [("c2p", 65001, 100)],
        [("a", "1.2.3.0/24", [65001, 100, 777, 100])],
    )
    assert out["results"][0]["status"] == "as_loop"


def test_conflicting_c2p_directions_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([("c2p", 1, 2), ("c2p", 2, 1)], [])
    assert exc.value.code == "bgp_relationship_conflict"


def test_conflicting_c2p_and_peer_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([("c2p", 1, 2), ("peer", 2, 1)], [])
    assert exc.value.code == "bgp_relationship_conflict"


def test_exact_duplicate_declaration_accepted():
    out = audit_announcements(
        [("c2p", 1, 2), ("c2p", 1, 2), ("peer", 3, 4), ("peer", 4, 3)],
        [],
    )
    assert out["results"] == []


def test_peer_declaration_is_order_insensitive():
    # Declaring peer as (20, 10) is the same edge as (10, 20).
    out = audit_announcements(
        [
            ("c2p", 65001, 100),
            ("c2p", 100, 10),
            ("peer", 20, 10),
            ("c2p", 65003, 20),
        ],
        [("a", "1.2.3.0/24", [65001, 100, 10, 20, 65003])],
    )
    assert out["results"][0]["status"] == "valid"


def test_self_relationship_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([("c2p", 5, 5)], [])
    assert exc.value.code == "bgp_self_relationship"
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([("peer", 5, 5)], [])
    assert exc.value.code == "bgp_self_relationship"


def test_duplicate_announcement_id_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements(
            [],
            [("x", "1.2.3.0/24", [1]), ("x", "1.2.4.0/24", [1])],
        )
    assert exc.value.code == "bgp_duplicate_announcement_id"


def test_invalid_prefix_rejected():
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([], [("a", "1.2.3.5/24", [1])])
    assert exc.value.code == "invalid_cidr"
    with pytest.raises(BgpAuditError) as exc:
        audit_announcements([], [("a", "not-a-cidr", [1])])
    assert exc.value.code == "invalid_cidr"


def test_ipv6_prefix_rejected():
    with pytest.raises(BgpAuditError):
        audit_announcements([], [("a", "2001:db8::/48", [1])])


# ---------------------------------------------------------------------------
# MOAS and origin change
# ---------------------------------------------------------------------------


def test_same_prefix_multiple_origins_is_moas():
    out = _audit(
        [
            ("a1", "203.0.113.0/24", [65001, 100, 10, 20, 65003]),
            ("a2", "203.0.113.0/24", [65002, 100, 10, 20, 65003, 65004]),
        ],
        extra_rels=[("c2p", 65004, 65003)],
    )
    res = _by_id(out)
    assert res["a1"]["origin"] == 65003
    assert res["a2"]["origin"] == 65004
    assert res["a1"]["flags"] == ["moas"]
    assert res["a2"]["flags"] == ["moas"]
    # Same origin repeated is not MOAS.
    out2 = _audit(
        [
            ("b1", "203.0.113.0/24", [65001, 100, 10, 20, 65003]),
            ("b2", "203.0.113.0/24", [65002, 100, 10, 20, 65003]),
        ]
    )
    assert all(r["flags"] == [] for r in out2["results"])


def test_more_specific_with_different_origin_is_origin_change():
    out = _audit(
        [
            ("cover", "203.0.113.0/24", [65001, 100, 10, 20, 65003]),
            ("spec", "203.0.113.128/25", [65002, 100, 10, 20, 65003, 65004]),
            ("same", "203.0.113.0/26", [65001, 100, 10, 20, 65003]),
        ],
        extra_rels=[("c2p", 65004, 65003)],
    )
    res = _by_id(out)
    assert res["cover"]["flags"] == []
    assert res["spec"]["flags"] == ["origin_change"]
    assert res["same"]["flags"] == []


def test_nearest_covering_prefix_decides_origin_change():
    # /22 originated by 65003, /24 by 65004 (change), /25 by 65003: the /25
    # matches its nearest cover /24 origin 65004, so it is a change even
    # though the outer /22 is originated by 65003.
    rels = [
        ("c2p", 65001, 100),
        ("c2p", 100, 10),
        ("peer", 10, 20),
        ("c2p", 65003, 20),
        ("c2p", 65004, 20),
    ]
    out = audit_announcements(
        rels,
        [
            ("outer", "203.0.112.0/22", [65001, 100, 10, 20, 65003]),
            ("middle", "203.0.113.0/24", [65001, 100, 10, 20, 65004]),
            ("inner", "203.0.113.0/25", [65001, 100, 10, 20, 65003]),
        ],
    )
    res = _by_id(out)
    assert res["inner"]["flags"] == ["origin_change"]
    assert res["middle"]["flags"] == ["origin_change"]
    assert res["outer"]["flags"] == []


def test_failed_path_announcements_excluded_from_comparison():
    # The only /24 announcement is looped; the more-specific therefore has no
    # covering prefix and must not be flagged origin_change.  The looped /24
    # also stops the duplicate-origin /24 from being MOAS.
    out = _audit(
        [
            ("cover", "203.0.113.0/24", [65003, 20, 65003]),
            ("other", "203.0.113.0/24", [65001, 100, 10, 20, 65003]),
            ("spec", "203.0.113.128/25", [65002, 100, 10, 20, 65003]),
        ]
    )
    res = _by_id(out)
    assert res["cover"]["status"] == "as_loop"
    assert res["cover"]["flags"] == []
    assert res["other"]["flags"] == []
    assert res["spec"]["flags"] == []


def test_moas_and_origin_change_can_coexist():
    # Two origins on /24 (MOAS) and a /25 from a third origin.
    out = _audit(
        [
            ("a", "203.0.113.0/24", [65001, 100, 10, 20, 65003]),
            ("b", "203.0.113.0/24", [65002, 100, 10, 20, 65003]),
            ("c", "203.0.113.128/25", [65001, 100, 10, 20, 65003]),
        ]
    )
    res = _by_id(out)
    # c's origin 65003 is among the /24 origins, so no origin_change.
    assert res["c"]["flags"] == []


# ---------------------------------------------------------------------------
# Ordering and summary
# ---------------------------------------------------------------------------


def test_results_sorted_by_network_then_prefixlen_then_id():
    out = _audit(
        [
            ("z", "203.0.113.0/25", [65003]),
            ("a", "203.0.113.0/24", [65003]),
            ("b", "10.0.0.0/8", [65003]),
            ("c", "203.0.113.0/25", [65003]),
        ]
    )
    keys = [
        (ipaddress.ip_network(r["prefix"]), r["id"]) for r in out["results"]
    ]
    assert keys == sorted(
        keys, key=lambda k: (int(k[0].network_address), k[0].prefixlen, k[1])
    )
    order = [(r["prefix"], r["id"]) for r in out["results"]]
    assert order == [
        ("10.0.0.0/8", "b"),
        ("203.0.113.0/24", "a"),
        ("203.0.113.0/25", "c"),
        ("203.0.113.0/25", "z"),
    ]


def test_summary_counts():
    # 9001 -> 9002 (c2p), 9002 -> 9003 (p2c), 9003 -> 9004 (c2p): a valley
    # at hop 2 with four distinct ASNs (no as_loop ambiguity).
    valley_rels = [
        ("c2p", 9001, 9002),
        ("c2p", 9003, 9002),
        ("c2p", 9003, 9004),
    ]
    rels = _rels() + [("c2p", 65004, 65003)] + valley_rels
    out = audit_announcements(
        rels,
        [
            ("ok1", "1.0.0.0/24", [65001, 100, 10, 20, 65003]),
            ("ok2", "1.0.0.0/24", [65002, 100, 10, 20, 65003, 65004]),
            ("loop", "2.0.0.0/24", [65003, 20, 65003]),
            ("bad", "3.0.0.0/24", [9001, 9002, 9003, 9004]),
        ],
    )
    res = _by_id(out)
    assert res["bad"]["status"] == "invalid_path"
    assert res["bad"]["violating_hop"]["index"] == 2
    assert out["summary"] == {
        "total": 4,
        "valid": 2,
        "as_loop": 1,
        "invalid_path": 1,
        "moas": 2,
        "origin_change": 0,
    }


def test_empty_batch():
    out = audit_announcements([], [])
    assert out == {
        "results": [],
        "summary": {
            "total": 0,
            "valid": 0,
            "as_loop": 0,
            "invalid_path": 0,
            "moas": 0,
            "origin_change": 0,
        },
    }
