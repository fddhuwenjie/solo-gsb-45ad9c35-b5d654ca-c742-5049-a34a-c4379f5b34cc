"""Pydantic request/response models."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

# Snapshot format version.  Only version 1 is understood by this service.
SNAPSHOT_VERSION = 1

# Only SHA-256 digests are produced or accepted; exported verbatim in the
# snapshot document's ``digest_algorithm`` field.
DIGEST_ALGORITHM = "SHA-256"


class PoolCreateRequest(BaseModel):
    cidr: str = Field(..., description="Pool network, e.g. 10.0.0.0/16")
    exclusions: list[str] = Field(
        default_factory=list,
        description="CIDRs inside the pool that must never be allocated",
    )


class PoolResponse(BaseModel):
    id: int
    cidr: str
    exclusions: list[str]
    created_at: str


class ExclusionCreateRequest(BaseModel):
    cidr: str


class ExclusionResponse(BaseModel):
    id: int
    excluded: str


class AllocateRequest(BaseModel):
    request_id: str = Field(..., min_length=1, description="Client-generated idempotency key")
    prefix_length: int = Field(..., ge=0, le=32)


class AllocationResponse(BaseModel):
    id: int
    pool_id: int
    cidr: str
    request_id: str
    prefix_length: int
    created_at: str
    replayed: bool


class ReleaseResponse(BaseModel):
    released: str
    request_id: str
    pool_id: int


class AllocationItem(BaseModel):
    cidr: str
    request_id: str
    prefix_length: int
    created_at: str


class PoolStatusResponse(BaseModel):
    id: int
    cidr: str
    exclusions: list[str]
    allocated: list[AllocationItem]
    free_cidrs: list[str]
    free_addresses: int


class ReverseDnsEntryRequest(BaseModel):
    cidr: str = Field(..., description="An existing allocation, e.g. 192.0.2.64/26")
    child_zone: str | None = Field(
        default=None,
        description=(
            "RFC 2317 tagged zone name for a subnet smaller than /24; either a "
            "single label (relative to the enclosing /24) or an absolute name. "
            "Ignored for octet-aligned whole-zone delegations."
        ),
    )
    nameservers: list[str] = Field(
        ...,
        min_length=2,
        description=(
            "Authoritative server FQDNs (at least two); duplicates are "
            "ignored after normalisation, so two identical names still fails"
        ),
    )
    ptr: dict[str, str] = Field(
        default_factory=dict,
        description="Optional address -> hostname PTR records for this subnet",
    )


class ReverseDnsPlanRequest(BaseModel):
    parent_zone: str = Field(
        ...,
        description="Octet-aligned parent reverse zone, e.g. 2.0.192.in-addr.arpa",
    )
    entries: list[ReverseDnsEntryRequest] = Field(..., min_length=1)


class DnsRecord(BaseModel):
    type: str
    name: str
    target: str


class DelegationFragmentResponse(BaseModel):
    cidr: str = Field(..., description="The fragment this delegation covers")
    source_cidr: str = Field(..., description="The allocation that produced it")
    mode: str = Field(..., description="'rfc2317' for tagged zones, 'direct' otherwise")
    enclosing_zone: str = Field(
        ...,
        description="Reverse zone that must host the NS/CNAME records",
    )
    child_zone: str | None = Field(
        default=None,
        description="Delegated zone name (RFC 2317 tag, or the whole zone itself)",
    )
    nameservers: list[str]


class ReverseDnsPlanResponse(BaseModel):
    pool_id: int
    parent_zone: str
    delegations: list[DelegationFragmentResponse]
    records: list[DnsRecord] = Field(
        ...,
        description="All NS, CNAME and PTR records in deterministic order",
    )


class CidrPolicyRuleRequest(BaseModel):
    cidr: str = Field(
        ...,
        min_length=1,
        description="IPv4 CIDR contained in the policy scope, e.g. 10.0.0.0/24",
    )
    action: Literal["allow", "deny"]


class CidrPolicyCompileRequest(BaseModel):
    scope: str = Field(
        ...,
        min_length=1,
        description="IPv4 CIDR the policy is compiled over, e.g. 10.0.0.0/16",
    )
    default_action: Literal["allow", "deny"]
    rules: list[CidrPolicyRuleRequest] = Field(
        default_factory=list,
        description=(
            "Priority-ordered rules; the first rule whose CIDR contains an "
            "address decides its action. Rules may overlap."
        ),
    )


class CidrPolicySegment(BaseModel):
    cidr: str
    action: Literal["allow", "deny"]


class CidrPolicyCompileResponse(BaseModel):
    scope: str
    default_action: Literal["allow", "deny"]
    segments: list[CidrPolicySegment] = Field(
        ...,
        description=(
            "Non-overlapping CIDR segments covering the whole scope, ordered "
            "by network address"
        ),
    )


# ---------------------------------------------------------------------------
# Pool snapshot export / restore
# ---------------------------------------------------------------------------


class SnapshotPool(BaseModel):
    id: int
    cidr: str = Field(..., min_length=1)
    created_at: str = Field(..., min_length=1)


class SnapshotExclusion(BaseModel):
    id: int = Field(..., ge=1, description="Database row id, preserved on restore")
    pool_id: int = Field(
        ..., ge=1, description="Owning pool; must equal the pool in the URL"
    )
    cidr: str = Field(..., min_length=1)
    created_at: str = Field(..., min_length=1)


class SnapshotAllocation(BaseModel):
    id: int = Field(..., ge=1, description="Database row id, preserved on restore")
    pool_id: int = Field(
        ..., ge=1, description="Owning pool; must equal the pool in the URL"
    )
    cidr: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)
    prefix_length: int = Field(..., ge=0, le=32)
    created_at: str = Field(..., min_length=1)


class SnapshotDocument(BaseModel):
    """Canonical, verifiable export of one pool's full state."""

    version: Literal[SNAPSHOT_VERSION]
    digest_algorithm: Literal[DIGEST_ALGORITHM]
    pool: SnapshotPool
    exclusions: list[SnapshotExclusion]
    allocations: list[SnapshotAllocation]


class RestoreRequest(BaseModel):
    restore_id: str = Field(
        ...,
        min_length=1,
        description="Client-generated idempotency key for the restore operation",
    )
    digest: str = Field(
        ...,
        min_length=1,
        description="SHA-256 hex digest of the canonical snapshot document",
    )
    snapshot: SnapshotDocument


class SnapshotResponse(BaseModel):
    pool_id: int
    digest: str = Field(..., description="SHA-256 hex of the canonical snapshot bytes")
    snapshot: SnapshotDocument


class RestoreResponse(BaseModel):
    restore_id: str
    pool_id: int
    digest: str
    replayed: bool
    replaced: bool = Field(
        ...,
        description="True when pool state was replaced; false on an idempotent replay",
    )


# ---------------------------------------------------------------------------
# Stateless BGP announcement auditing
# ---------------------------------------------------------------------------

# 32-bit AS numbers; AS 0 and the reserved 32-bit max are excluded.
BgpAsn = Annotated[int, Field(strict=True, ge=1, le=4294967294)]


class C2PRelationshipRequest(BaseModel):
    """The ``customer`` AS buys transit from the ``provider`` AS."""

    type: Literal["c2p"] = Field(
        ..., description="Relationship kind: customer -> provider"
    )
    customer: BgpAsn
    provider: BgpAsn


class PeerRelationshipRequest(BaseModel):
    """A peering relationship; AS order is insignificant."""

    type: Literal["peer"] = Field(..., description="Relationship kind: peer")
    asn_a: BgpAsn
    asn_b: BgpAsn


RelationshipRequest = Annotated[
    C2PRelationshipRequest | PeerRelationshipRequest,
    Field(discriminator="type"),
]


class BgpAnnouncementRequest(BaseModel):
    id: str = Field(
        ..., min_length=1, description="Client-chosen unique id within the batch"
    )
    prefix: str = Field(..., description="Strictly valid IPv4 CIDR, e.g. 203.0.113.0/24")
    as_path: list[BgpAsn] = Field(
        ...,
        min_length=1,
        description="ASNs ordered observer -> origin (prepending allowed)",
    )


class BgpAuditRequest(BaseModel):
    relationships: list[RelationshipRequest] = Field(
        default_factory=list,
        description="AS relationship declarations: customer->provider or peer links",
    )
    announcements: list[BgpAnnouncementRequest] = Field(
        default_factory=list,
        description="Batch of announcements to audit; every id must be unique",
    )


class BgpViolatingHop(BaseModel):
    index: int = Field(
        ..., description="Zero-based index of the hop within the folded AS path"
    )
    source: BgpAsn
    target: BgpAsn
    relationship: Literal["customer_to_provider", "provider_to_customer", "peer"]
    reason: str = Field(..., description="Why this hop breaks the c2p* peer? p2c* order")


class BgpAuditResult(BaseModel):
    id: str
    prefix: str
    as_path: list[int] = Field(..., description="The folded path (consecutive repeats collapsed)")
    origin: BgpAsn = Field(..., description="Last AS of the folded path")
    status: Literal["valid", "as_loop", "invalid_path"]
    flags: list[Literal["moas", "origin_change"]]
    violating_hop: BgpViolatingHop | None = None


class BgpAuditSummary(BaseModel):
    total: int
    valid: int
    as_loop: int
    invalid_path: int
    moas: int
    origin_change: int


class BgpAuditResponse(BaseModel):
    results: list[BgpAuditResult] = Field(
        ...,
        description=(
            "Sorted by network address, prefix length, then announcement id"
        ),
    )
    summary: BgpAuditSummary
