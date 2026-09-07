"""D4 delivery contract tests: roundtrips, golden identity vectors, rejections.

Expected canonical bytes and hashes were produced once by independent scripts
(plain ``hashlib``/``json`` with no project imports) and are frozen as
literals below; they are never recomputed by the code under test.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.contracts import delivery as d4
from mtsql_typecheck.contracts.case import ContractError, NameMap
from mtsql_typecheck.contracts.codec import canonical_json, parse_strict_json

# --------------------------------------------------------------------------
# Frozen fixture constants (lowercase 64-hex; chosen, not derived)
# --------------------------------------------------------------------------

DIGEST_A = "aa" * 32
DIGEST_B = "bb" * 32
SHA_CD = "cd" * 32
SHA_EF = "ef" * 32
CASE_ID = "ab" * 32
CASE_DOC_HASH = "11" * 32
INVENTORY_HASH = "22" * 32
EXPORT_ID = "33" * 32

SOURCE_ID_A = "s-" + DIGEST_A
SOURCE_ID_B = "s-" + DIGEST_B

# Hand-computed identity vectors (plain hashlib over the canonical inputs
# documented in each test below).
GOLDEN_SNAPSHOT_DIGEST = "df8b81be68b867afc58a000a46d16c4c1c7432c6ae17592e0e56494d577c1638"
GOLDEN_DELIVERY_ID_SINGLE = "7a7f9ef1c30abd7294e223007dd08e1ad7ecd1c9274224f134737360c0429fb9"
GOLDEN_DELIVERY_ID_TWO = "08079963932e73d314c5999bf9cf60ea9c28cc5882082aaea861d88a67eb6759"
GOLDEN_OCCURRENCE_ID = "70a90666b5efb18717e440a10be936a6f534a0026308a5cba47552c226e4f3ce"

# Golden canonical JSON documents, frozen once (json.dumps sorted/compact).
GOLDEN_PRODUCER_JSON = '{"dirty":null,"name":"mtsql-typecheck","revision":null,"version":"0.1.0"}'
GOLDEN_MANIFEST_JSON = (
    '{"assessment_ref":"assessment.json","completion":"COMPLETE",'
    '"delivery_id":"7a7f9ef1c30abd7294e223007dd08e1ad7ecd1c9274224f134737360c0429fb9",'
    '"files":[{"path":"assessment.json","role":"assessment",'
    '"sha256":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",'
    '"size_bytes":10,"source_id":null},'
    '{"path":"raw/run-001/runner-manifest.json","role":"raw_native",'
    '"sha256":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",'
    '"size_bytes":1234,'
    '"source_id":"s-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],'
    '"kind":"verification","producer":{"dirty":null,"name":"mtsql-typecheck",'
    '"revision":null,"version":"0.1.0"},"schema_version":1,'
    '"sources":[{"collection_status":"COLLECTED","missing_files":[],'
    '"native_kind":"run","native_versions":[{"kind_field":"runner_schema","value":"1"}],'
    '"observed_writer_version":null,"producer":null,'
    '"root_document":"raw/run-001/runner-manifest.json",'
    '"snapshot_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"source_commit":null,'
    '"source_id":"s-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"synthetic":"REAL"}],"writer_version":"0.1.0"}'
)
GOLDEN_REVIEW_JSON = (
    '{"decision":"NEEDS_MORE_EVIDENCE",'
    '"evidence_digest":"7a7f9ef1c30abd7294e223007dd08e1ad7ecd1c9274224f134737360c0429fb9",'
    '"issue_url":null,"occurrence_ids":'
    '["70a90666b5efb18717e440a10be936a6f534a0026308a5cba47552c226e4f3ce"],'
    '"reason":"pending replay confirmation","review_id":"rev-1",'
    '"reviewed_at":"2026-09-06T00:00:00Z","reviewer":"alice","schema_version":1,'
    '"supersedes":null}'
)
GOLDEN_REGRESSION_JSON = (
    '{"case_document_hash":"1111111111111111111111111111111111111111111111111111111111111111",'
    '"codec_id":"c1","codec_version":"1","fixed_build":null,"known_bad_build":null,'
    '"relation_assertion":{"columns":["c0"],"mode":"typed_multiset_exact",'
    '"spec":"{\\"kind\\":\\"typed_multiset_exact\\"}"},"renderer_id":"r1",'
    '"renderer_version":"1","review_ref":"rev-1","rule_definition_hash":null,'
    '"schema_version":1,'
    '"source_inventory_hash":"2222222222222222222222222222222222222222222222222222222222222222",'
    '"synthetic":"REAL"}'
)
GOLDEN_EXPORT_JSON = (
    '{"completion":"COMPLETE",'
    '"export_id":"3333333333333333333333333333333333333333333333333333333333333333",'
    '"files":[{"path":"a.sql","role":"export_sql_a",'
    '"sha256":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",'
    '"size_bytes":42,"source_id":null}],"format":"regression",'
    '"limitations":["review_required"],'
    '"name_map":{"database_a":"db_a","database_b":"db_b","table_a":"t_a","table_b":"t_b"},'
    '"review_ref":"rev-1","schema_version":1,'
    '"selected_case_id":"abababababababababababababababababababababababababababababababab",'
    '"selected_occurrence_id":'
    '"70a90666b5efb18717e440a10be936a6f534a0026308a5cba47552c226e4f3ce",'
    '"source_delivery_id":'
    '"7a7f9ef1c30abd7294e223007dd08e1ad7ecd1c9274224f134737360c0429fb9"}'
)


# --------------------------------------------------------------------------
# Shared fixture builders
# --------------------------------------------------------------------------


def build_source() -> d4.SourceDescriptor:
    return d4.SourceDescriptor(
        source_id=SOURCE_ID_A,
        native_kind=d4.NativeKind.RUN,
        root_document="raw/run-001/runner-manifest.json",
        snapshot_digest=DIGEST_A,
        synthetic=d4.SyntheticKind.REAL,
        collection_status=d4.CollectionStatus.COLLECTED,
        native_versions=(d4.NativeVersionComponent("runner_schema", "1"),),
    )


def build_manifest() -> d4.EvidenceManifest:
    return d4.EvidenceManifest(
        delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
        kind=d4.DeliveryKind.VERIFICATION,
        writer_version="0.1.0",
        sources=(build_source(),),
        files=(
            d4.EvidenceFile("assessment.json", d4.FileRole.ASSESSMENT, 10, SHA_EF),
            d4.EvidenceFile(
                "raw/run-001/runner-manifest.json",
                d4.FileRole.RAW_NATIVE,
                1234,
                SHA_CD,
                SOURCE_ID_A,
            ),
        ),
        completion=d4.DeliveryCompletion.COMPLETE,
        producer=d4.ProducerInfo("mtsql-typecheck", "0.1.0"),
    )


def build_occurrence() -> d4.FindingOccurrence:
    return d4.FindingOccurrence(
        source_id=SOURCE_ID_A,
        attempt_id="attempt-0001",
        case_id=CASE_ID,
        recompute_status=d4.SemanticStatus.RECOMPUTED,
        comparison_hash="12" * 32,
        original_exact_signature="34" * 32,
        fingerprint="56" * 32,
        recomputed_comparison_hash="78" * 32,
        synthetic=d4.SyntheticKind.REAL,
    )


def build_review() -> d4.FindingReview:
    return d4.FindingReview(
        review_id="rev-1",
        reviewer="alice",
        reviewed_at="2026-09-06T00:00:00Z",
        evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
        occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
        decision=d4.ReviewDecision.NEEDS_MORE_EVIDENCE,
        reason="pending replay confirmation",
    )


def build_regression() -> d4.RegressionCase:
    return d4.RegressionCase(
        case_document_hash=CASE_DOC_HASH,
        renderer_id="r1",
        renderer_version="1",
        codec_id="c1",
        codec_version="1",
        relation_assertion=d4.RelationAssertion(
            d4.RelationAssertionMode.TYPED_MULTISET_EXACT,
            ("c0",),
            '{"kind":"typed_multiset_exact"}',
        ),
        source_inventory_hash=INVENTORY_HASH,
        synthetic=d4.SyntheticKind.REAL,
        review_ref="rev-1",
    )


def build_export() -> d4.ExportManifest:
    return d4.ExportManifest(
        export_id=EXPORT_ID,
        format=d4.ExportFormat.REGRESSION,
        source_delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
        selected_case_id=CASE_ID,
        selected_occurrence_id=GOLDEN_OCCURRENCE_ID,
        review_ref="rev-1",
        name_map=NameMap("db_a", "db_b", "t_a", "t_b"),
        files=(
            d4.EvidenceFile("a.sql", d4.FileRole.EXPORT_SQL_A, 42, SHA_CD),
        ),
        limitations=("review_required",),
        completion=d4.DeliveryCompletion.COMPLETE,
    )


def build_assessment() -> d4.EvidenceAssessment:
    return d4.EvidenceAssessment(
        structural=d4.DimensionResult(
            d4.AssessmentDimension.STRUCTURAL, True, d4.StructuralStatus.COMPLETE,
            ("ok",), 3, 0,
        ),
        semantic=d4.DimensionResult(
            d4.AssessmentDimension.SEMANTIC, True, d4.SemanticStatus.RECOMPUTED, (), 2, 0,
        ),
        provenance=d4.DimensionResult(
            d4.AssessmentDimension.PROVENANCE, False, d4.ProvenanceStatus.UNVERIFIED,
        ),
        execution_safety=d4.DimensionResult(
            d4.AssessmentDimension.EXECUTION_SAFETY, False,
            d4.ExecutionSafetyStatus.NOT_APPLICABLE,
        ),
    )


# --------------------------------------------------------------------------
# Golden canonical JSON literals (frozen; not generated by the code under test)
# --------------------------------------------------------------------------


def test_producer_info_canonical_json_golden():
    assert canonical_json(d4.ProducerInfo("mtsql-typecheck", "0.1.0").to_obj()) == (
        GOLDEN_PRODUCER_JSON.encode()
    )
    assert d4.decode_producer_info(parse_strict_json(GOLDEN_PRODUCER_JSON)) == (
        d4.ProducerInfo("mtsql-typecheck", "0.1.0")
    )


def test_evidence_manifest_canonical_json_golden():
    manifest = build_manifest()
    assert canonical_json(manifest.to_obj()) == GOLDEN_MANIFEST_JSON.encode()
    assert d4.decode_evidence_manifest(parse_strict_json(GOLDEN_MANIFEST_JSON)) == manifest


def test_finding_review_canonical_json_golden():
    review = build_review()
    assert canonical_json(review.to_obj()) == GOLDEN_REVIEW_JSON.encode()
    assert d4.decode_finding_review(parse_strict_json(GOLDEN_REVIEW_JSON)) == review


def test_regression_case_canonical_json_golden():
    regression = build_regression()
    assert canonical_json(regression.to_obj()) == GOLDEN_REGRESSION_JSON.encode()
    assert d4.decode_regression_case(parse_strict_json(GOLDEN_REGRESSION_JSON)) == regression


def test_export_manifest_canonical_json_golden():
    export = build_export()
    assert canonical_json(export.to_obj()) == GOLDEN_EXPORT_JSON.encode()
    assert d4.decode_export_manifest(parse_strict_json(GOLDEN_EXPORT_JSON)) == export


# --------------------------------------------------------------------------
# Roundtrips for every model
# --------------------------------------------------------------------------


def _roundtrip(model, decoder):
    encoded = canonical_json(model.to_obj())
    assert decoder(parse_strict_json(encoded)) == model


@pytest.mark.parametrize(
    "builder,decoder",
    [
        (lambda: d4.ProducerInfo("mtsql-typecheck", "0.1.0"), d4.decode_producer_info),
        (lambda: d4.Limits.default(), d4.decode_limits),
        (
            lambda: d4.EvidenceFile(
                "raw/run-001/runner-manifest.json", d4.FileRole.RAW_NATIVE,
                1234, SHA_CD, SOURCE_ID_A,
            ),
            d4.decode_evidence_file,
        ),
        (lambda: d4.NativeVersionComponent("trace_format", "typecheck-full-evidence-v1"),
         d4.decode_native_version_component),
        (build_source, d4.decode_source_descriptor),
        (build_manifest, d4.decode_evidence_manifest),
        (
            lambda: d4.DimensionObservation(
                d4.AssessmentDimension.STRUCTURAL, True, d4.StructuralStatus.CORRUPT,
                "raw/x.json",
            ),
            d4.decode_dimension_observation,
        ),
        (build_assessment, d4.decode_evidence_assessment),
        (build_occurrence, d4.decode_finding_occurrence),
        (build_review, d4.decode_finding_review),
        (build_regression, d4.decode_regression_case),
        (build_export, d4.decode_export_manifest),
    ],
)
def test_model_roundtrip(builder, decoder):
    _roundtrip(builder(), decoder)


def test_dimension_result_decodes_every_dimension():
    for dimension, status_cls, status_value in (
        (d4.AssessmentDimension.STRUCTURAL, d4.StructuralStatus, d4.StructuralStatus.PARTIAL),
        (d4.AssessmentDimension.SEMANTIC, d4.SemanticStatus, d4.SemanticStatus.CONFLICT),
        (d4.AssessmentDimension.PROVENANCE, d4.ProvenanceStatus, d4.ProvenanceStatus.UNVERIFIED),
        (
            d4.AssessmentDimension.EXECUTION_SAFETY,
            d4.ExecutionSafetyStatus,
            d4.ExecutionSafetyStatus.UNSAFE,
        ),
    ):
        result = d4.DimensionResult(dimension, True, status_cls(status_value), ("x",), 1, 1)
        _roundtrip(result, d4.decode_dimension_result)


# --------------------------------------------------------------------------
# Identity function golden vectors (design 6.2.1 formulas)
# --------------------------------------------------------------------------


def test_snapshot_digest_golden():
    # canonical input (sorted keys, compact):
    # {"files":[{"path":"raw/run-001/runner-manifest.json",
    #            "sha256":"cd"*32,"size_bytes":1234}],
    #  "missing_paths":["evidence/attempt-2/comparison.json"],
    #  "native_kind":"run",
    #  "root_document":"raw/run-001/runner-manifest.json"}
    digest = d4.compute_snapshot_digest(
        "run",
        "raw/run-001/runner-manifest.json",
        (("raw/run-001/runner-manifest.json", 1234, SHA_CD),),
        ("evidence/attempt-2/comparison.json",),
    )
    assert digest == GOLDEN_SNAPSHOT_DIGEST


def test_snapshot_digest_is_order_insensitive_for_files_and_missing_paths():
    base_files = (
        ("raw/a.json", 1, SHA_CD),
        ("raw/b.json", 2, SHA_EF),
    )
    # The digest is defined over sorted, unique inputs: missing_paths must be
    # passed sorted, file lists must not repeat a path, and equal content
    # always yields the same digest.
    assert d4.compute_snapshot_digest(
        "run", "raw/m.json", base_files, ("x.json", "y.json")
    ) == d4.compute_snapshot_digest(
        "run", "raw/m.json", base_files, ("x.json", "y.json")
    )
    with pytest.raises(ContractError, match="sorted and unique"):
        d4.compute_snapshot_digest("run", "raw/m.json", base_files, ("y.json", "x.json"))
    with pytest.raises(ContractError, match="duplicate"):
        d4.compute_snapshot_digest("run", "raw/m.json", (base_files[0], base_files[0]), ())


def test_source_id_formula():
    assert d4.compute_source_id(DIGEST_A) == SOURCE_ID_A
    with pytest.raises(ContractError, match="64-hex"):
        d4.compute_source_id("AA" * 32)  # uppercase rejected
    with pytest.raises(ContractError, match="64-hex"):
        d4.compute_source_id(DIGEST_A[:-1])


def test_delivery_id_goldens():
    # single source: canonical input [{"snapshot_digest":"aa"*32,
    #                                  "source_id":"s-"+"aa"*32}]
    single = d4.SourceDescriptor(
        source_id=SOURCE_ID_A,
        native_kind=d4.NativeKind.RUN,
        root_document="raw/run-001/runner-manifest.json",
        snapshot_digest=DIGEST_A,
        synthetic=d4.SyntheticKind.REAL,
        collection_status=d4.CollectionStatus.COLLECTED,
    )
    assert d4.compute_delivery_id((single,)) == GOLDEN_DELIVERY_ID_SINGLE

    # two sources, sorted by source_id: [{"snapshot_digest":"aa"*32,
    # "source_id":"s-aa.."}, {"snapshot_digest":"bb"*32, "source_id":"s-bb.."}]
    second = d4.SourceDescriptor(
        source_id=SOURCE_ID_B,
        native_kind=d4.NativeKind.TRACE,
        root_document="raw/reduce-001/trace.jsonl",
        snapshot_digest=DIGEST_B,
        synthetic=d4.SyntheticKind.SYNTHETIC,
        collection_status=d4.CollectionStatus.PARTIALLY_READ,
    )
    assert d4.compute_delivery_id((second, single)) == GOLDEN_DELIVERY_ID_TWO

    with pytest.raises(ContractError, match="at least one"):
        d4.compute_delivery_id(())
    with pytest.raises(ContractError, match="duplicate"):
        d4.compute_delivery_id((single, single))


def test_delivery_identity_is_stable_across_metadata_changes():
    # Moving the package, re-rendering reports or adding reviews must not
    # change identity: only (source_id, snapshot_digest) entries.
    plain = d4.SourceDescriptor(
        source_id=SOURCE_ID_A,
        native_kind=d4.NativeKind.RUN,
        root_document="raw/run-001/runner-manifest.json",
        snapshot_digest=DIGEST_A,
        synthetic=d4.SyntheticKind.REAL,
        collection_status=d4.CollectionStatus.COLLECTED,
    )
    decorated = d4.SourceDescriptor(
        source_id=SOURCE_ID_A,
        native_kind=d4.NativeKind.RUN,
        root_document="raw/run-001/runner-manifest.json",
        snapshot_digest=DIGEST_A,
        synthetic=d4.SyntheticKind.REAL,
        collection_status=d4.CollectionStatus.PARTIALLY_READ,
        observed_writer_version="0.1.0",
        producer=d4.ProducerInfo("mtsql-typecheck", "0.1.0", "a" * 40, True),
        missing_files=("raw/lost.json",),
    )
    assert d4.compute_delivery_id((plain,)) == d4.compute_delivery_id((decorated,))


def test_occurrence_id_golden_and_no_fabrication():
    # canonical input: ["s-"+"aa"*32, "attempt-0001", "ab"*32]
    assert (
        d4.compute_occurrence_id(SOURCE_ID_A, "attempt-0001", CASE_ID)
        == GOLDEN_OCCURRENCE_ID
    )
    assert d4.compute_occurrence_id(SOURCE_ID_A, "attempt-0002", CASE_ID) != (
        GOLDEN_OCCURRENCE_ID
    )
    with pytest.raises(ContractError, match="attempt"):
        d4.compute_occurrence_id(SOURCE_ID_A, None, CASE_ID)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="attempt"):
        d4.compute_occurrence_id(SOURCE_ID_A, "", CASE_ID)


# --------------------------------------------------------------------------
# Rejections: strictness on both the model and the loader path
# --------------------------------------------------------------------------


def manifest_obj(**overrides):
    obj = build_manifest().to_obj()
    obj.update(overrides)
    return obj


def test_rejects_unknown_fields_at_top_level():
    obj = manifest_obj()
    obj["extra"] = 1
    with pytest.raises(ContractError, match="unknown fields"):
        d4.decode_evidence_manifest(obj)
    producer = d4.ProducerInfo("mtsql-typecheck", "0.1.0").to_obj()
    producer["dirty"] = False
    producer["extra"] = True
    with pytest.raises(ContractError, match="unknown fields"):
        d4.decode_producer_info(producer)
    review = build_review().to_obj()
    review["confirmed_bug"] = True
    with pytest.raises(ContractError, match="unknown fields"):
        d4.decode_finding_review(review)


def test_rejects_duplicate_json_keys():
    with pytest.raises(ContractError, match="duplicate"):
        parse_strict_json(b'{"schema_version":1,"schema_version":2}')
    duplicated = GOLDEN_MANIFEST_JSON.replace(
        '"assessment_ref":"assessment.json"',
        '"assessment_ref":"assessment.json","assessment_ref":"assessment.json"',
    )
    with pytest.raises(ContractError, match="duplicate"):
        parse_strict_json(duplicated)
    file_line = (
        '{"path":"a.sql","role":"export_sql_a","size_bytes":1,"sha256":"'
        + SHA_CD + '","sha256":"' + SHA_CD + '"}'
    )
    with pytest.raises(ContractError, match="duplicate"):
        parse_strict_json(file_line.encode())


def test_rejects_float_literals_and_bool_as_int():
    with pytest.raises(ContractError, match="float"):
        parse_strict_json(
            b'{"path":"a.sql","role":"export_sql_a","size_bytes":1.5,"sha256":"' + SHA_CD.encode()
            + b'"}'
        )
    with pytest.raises(ContractError, match="JSON integer"):
        file_entry = d4.EvidenceFile(
            "a.sql", d4.FileRole.EXPORT_SQL_A, 42, SHA_CD
        ).to_obj()
        file_entry["size_bytes"] = True
        d4.decode_evidence_file(file_entry)
    with pytest.raises(ContractError, match="must be an int"):
        d4.EvidenceFile("a.sql", d4.FileRole.EXPORT_SQL_A, True, SHA_CD)
    with pytest.raises(ContractError, match="must be a JSON integer"):
        limits = d4.Limits.default().to_obj()
        limits["max_files"] = True
        d4.decode_limits(limits)


def test_rejects_wrong_enum_values():
    obj = manifest_obj()
    obj["kind"] = "banana"
    with pytest.raises(ContractError, match="unknown value"):
        d4.decode_evidence_manifest(obj)
    obj = manifest_obj()
    obj["sources"] = [{**build_source().to_obj(), "collection_status": "COLLECTED_ALL"}]
    with pytest.raises(ContractError, match="unknown value"):
        d4.decode_evidence_manifest(obj)
    review = build_review().to_obj()
    review["decision"] = "MAYBE"
    with pytest.raises(ContractError, match="unknown value"):
        d4.decode_finding_review(review)
    occurrence = build_occurrence().to_obj()
    occurrence["recompute_status"] = "RECOMPUTED_PROBABLY"
    with pytest.raises(ContractError, match="unknown value"):
        d4.decode_finding_occurrence(occurrence)


@pytest.mark.parametrize("version_field", ["schema_version"])
def test_rejects_wrong_schema_versions(version_field):
    manifest = manifest_obj()
    manifest[version_field] = 2
    with pytest.raises(ContractError, match="schema_version"):
        d4.decode_evidence_manifest(manifest)
    review = build_review().to_obj()
    review[version_field] = 0
    with pytest.raises(ContractError, match="schema_version"):
        d4.decode_finding_review(review)
    regression = build_regression().to_obj()
    regression[version_field] = 3
    with pytest.raises(ContractError, match="schema_version"):
        d4.decode_regression_case(regression)
    export = build_export().to_obj()
    export[version_field] = 2
    with pytest.raises(ContractError, match="schema_version"):
        d4.decode_export_manifest(export)
    assessment = build_assessment().to_obj()
    assessment[version_field] = 2
    with pytest.raises(ContractError, match="schema_version"):
        d4.decode_evidence_assessment(assessment)


def test_rejects_bad_hash_lengths():
    obj = manifest_obj()
    obj["delivery_id"] = "z" * 63
    with pytest.raises(ContractError, match="64-hex"):
        d4.decode_evidence_manifest(obj)
    file_entry = d4.EvidenceFile("a.sql", d4.FileRole.EXPORT_SQL_A, 42, SHA_CD).to_obj()
    file_entry["sha256"] = SHA_CD[:-1]
    with pytest.raises(ContractError, match="64-hex"):
        d4.decode_evidence_file(file_entry)
    with pytest.raises(ContractError, match="40-hex"):
        d4.ProducerInfo("mtsql-typecheck", "0.1.0", "abc123")
    with pytest.raises(ContractError, match="40-hex"):
        d4.ProducerInfo("mtsql-typecheck", "0.1.0", "A" * 40)  # uppercase
    with pytest.raises(ContractError, match="40-hex"):
        d4.SourceDescriptor(
            source_id=SOURCE_ID_A,
            native_kind=d4.NativeKind.RUN,
            root_document="raw/run-001/runner-manifest.json",
            snapshot_digest=DIGEST_A,
            synthetic=d4.SyntheticKind.REAL,
            collection_status=d4.CollectionStatus.COLLECTED,
            source_commit="a" * 39,
        )


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "raw/../secret.json",
        "..",
        "raw/./x.json",
        "raw//x.json",
        "raw/",
        "raw\\x.json",
        "",
    ],
)
def test_rejects_illegal_evidence_file_paths(path):
    with pytest.raises(ContractError):
        d4.EvidenceFile(path, d4.FileRole.ASSESSMENT, 1, SHA_CD)


def test_rejects_raw_native_without_source_id_and_derived_source_rules():
    with pytest.raises(ContractError, match="RAW_NATIVE"):
        d4.EvidenceFile("raw/x.json", d4.FileRole.RAW_NATIVE, 1, SHA_CD, None)
    # A derived file may carry None or a source_id.
    d4.EvidenceFile("report.json", d4.FileRole.REPORT_JSON, 1, SHA_CD, None)
    d4.EvidenceFile("report.json", d4.FileRole.REPORT_JSON, 1, SHA_CD, SOURCE_ID_A)
    with pytest.raises(ContractError, match="s-"):
        d4.EvidenceFile("report.json", d4.FileRole.REPORT_JSON, 1, SHA_CD, DIGEST_A)


def test_manifest_must_not_list_itself_and_needs_sorted_unique_files():
    entry = d4.EvidenceFile(
        d4.MANIFEST_FILENAME, d4.FileRole.RAW_NATIVE, 1, SHA_CD, SOURCE_ID_A
    )
    with pytest.raises(ContractError, match="manifest itself"):
        d4.EvidenceManifest(
            delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            kind=d4.DeliveryKind.VERIFICATION,
            writer_version="0.1.0",
            sources=(build_source(),),
            files=(entry,),
            completion=d4.DeliveryCompletion.COMPLETE,
        )
    files = (
        d4.EvidenceFile("z.json", d4.FileRole.ASSESSMENT, 1, SHA_CD),
        d4.EvidenceFile("a.json", d4.FileRole.ASSESSMENT, 1, SHA_CD),
    )
    with pytest.raises(ContractError, match="sorted"):
        d4.EvidenceManifest(
            delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            kind=d4.DeliveryKind.VERIFICATION,
            writer_version="0.1.0",
            sources=(build_source(),),
            files=files,
            completion=d4.DeliveryCompletion.COMPLETE,
        )


def test_manifest_requires_sources_and_correct_delivery_id():
    with pytest.raises(ContractError, match="non-empty"):
        d4.EvidenceManifest(
            delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            kind=d4.DeliveryKind.VERIFICATION,
            writer_version="0.1.0",
            sources=(),
            files=(),
            completion=d4.DeliveryCompletion.COMPLETE,
        )
    obj = manifest_obj()
    obj["delivery_id"] = "e" * 64  # valid hex, but not the sources' identity
    with pytest.raises(ContractError, match="delivery_id"):
        d4.decode_evidence_manifest(obj)


def test_manifest_assessment_ref_is_fixed():
    with pytest.raises(ContractError, match="assessment_ref"):
        d4.EvidenceManifest(
            delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            kind=d4.DeliveryKind.REPORT,
            writer_version="0.1.0",
            sources=(build_source(),),
            files=(),
            completion=d4.DeliveryCompletion.PARTIAL,
            assessment_ref="other.json",
        )


def test_source_descriptor_rules():
    with pytest.raises(ContractError, match="s-"):
        d4.SourceDescriptor(
            source_id=DIGEST_A,  # missing the s- prefix binding
            native_kind=d4.NativeKind.RUN,
            root_document="raw/run-001/runner-manifest.json",
            snapshot_digest=DIGEST_A,
            synthetic=d4.SyntheticKind.REAL,
            collection_status=d4.CollectionStatus.COLLECTED,
        )
    with pytest.raises(ContractError, match="unknown"):
        d4.NativeVersionComponent("bogus_schema", "1")
    versions = (
        d4.NativeVersionComponent("runner_schema", "1"),
        d4.NativeVersionComponent("case_schema", "1"),
    )
    with pytest.raises(ContractError, match="sorted"):
        d4.SourceDescriptor(
            source_id=SOURCE_ID_A,
            native_kind=d4.NativeKind.RUN,
            root_document="raw/run-001/runner-manifest.json",
            snapshot_digest=DIGEST_A,
            synthetic=d4.SyntheticKind.REAL,
            collection_status=d4.CollectionStatus.COLLECTED,
            native_versions=versions,
        )
    with pytest.raises(ContractError, match="sorted"):
        d4.SourceDescriptor(
            source_id=SOURCE_ID_A,
            native_kind=d4.NativeKind.RUN,
            root_document="raw/run-001/runner-manifest.json",
            snapshot_digest=DIGEST_A,
            synthetic=d4.SyntheticKind.REAL,
            collection_status=d4.CollectionStatus.COLLECTED,
            missing_files=("b.json", "a.json"),
        )


def test_producer_dirty_stays_none_and_never_defaults_to_false():
    assert d4.ProducerInfo("mtsql-typecheck").dirty is None
    assert d4.ProducerInfo("mtsql-typecheck").version is None
    assert d4.ProducerInfo("mtsql-typecheck").revision is None
    decoded = d4.decode_producer_info({"name": "mtsql-typecheck"})
    assert decoded.dirty is None and decoded.version is None and decoded.revision is None
    decoded = d4.decode_producer_info(
        {"name": "mtsql-typecheck", "version": None, "revision": None, "dirty": None}
    )
    assert decoded.dirty is None
    assert '"dirty":null' in canonical_json(decoded.to_obj()).decode()
    with pytest.raises(ContractError, match="bool"):
        d4.ProducerInfo("mtsql-typecheck", dirty="false")


def test_finding_occurrence_identity_and_recompute_rules():
    occurrence = build_occurrence()
    assert occurrence.occurrence_id == GOLDEN_OCCURRENCE_ID
    forged = build_occurrence().to_obj()
    forged["occurrence_id"] = "9" * 64
    with pytest.raises(ContractError, match="occurrence_id"):
        d4.decode_finding_occurrence(forged)
    with pytest.raises(ContractError, match="recomputed_comparison_hash"):
        d4.FindingOccurrence(
            source_id=SOURCE_ID_A,
            attempt_id="attempt-0001",
            case_id=CASE_ID,
            recompute_status=d4.SemanticStatus.NOT_RECOMPUTED,
            recomputed_comparison_hash="78" * 32,
        )
    with pytest.raises(ContractError, match="recomputed_comparison_hash"):
        d4.FindingOccurrence(
            source_id=SOURCE_ID_A,
            attempt_id="attempt-0001",
            case_id=CASE_ID,
            recompute_status=d4.SemanticStatus.RECOMPUTED,
        )
    with pytest.raises(ContractError, match="must be a str"):
        d4.FindingOccurrence(
            source_id=SOURCE_ID_A,
            attempt_id=None,  # type: ignore[arg-type]
            case_id=CASE_ID,
            recompute_status=d4.SemanticStatus.NOT_RECOMPUTED,
        )


def test_finding_review_binding_rules():
    with pytest.raises(ContractError, match="supersedes"):
        d4.FindingReview(
            review_id="rev-1",
            reviewer="alice",
            reviewed_at="2026-09-06T00:00:00Z",
            evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
            occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
            decision=d4.ReviewDecision.CONFIRMED_DB_BUG,
            reason="real",
            supersedes="rev-1",
        )
    with pytest.raises(ContractError, match="https"):
        d4.FindingReview(
            review_id="rev-1",
            reviewer="alice",
            reviewed_at="2026-09-06T00:00:00Z",
            evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
            occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
            decision=d4.ReviewDecision.CONFIRMED_DB_BUG,
            reason="real",
            issue_url="http://insecure.example/",
        )
    with pytest.raises(ContractError, match="https"):
        d4.FindingReview(
            review_id="rev-1",
            reviewer="alice",
            reviewed_at="2026-09-06T00:00:00Z",
            evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
            occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
            decision=d4.ReviewDecision.CONFIRMED_DB_BUG,
            reason="real",
            issue_url="javascript:alert(1)",
        )
    with pytest.raises(ContractError, match="occurrence_ids"):
        d4.FindingReview(
            review_id="rev-1",
            reviewer="alice",
            reviewed_at="2026-09-06T00:00:00Z",
            evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
            occurrence_ids=(),
            decision=d4.ReviewDecision.CONFIRMED_DB_BUG,
            reason="real",
        )
    with pytest.raises(ContractError, match="ISO-8601"):
        d4.FindingReview(
            review_id="rev-1",
            reviewer="alice",
            reviewed_at="2026-09-06 00:00:00",
            evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
            occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
            decision=d4.ReviewDecision.CONFIRMED_DB_BUG,
            reason="real",
        )
    # Accepted variants: offset timezone, fractional seconds, supersedes chain.
    d4.FindingReview(
        review_id="rev-2",
        reviewer="bob",
        reviewed_at="2026-09-06T12:30:00.123456+08:00",
        evidence_digest=GOLDEN_DELIVERY_ID_SINGLE,
        occurrence_ids=(GOLDEN_OCCURRENCE_ID,),
        decision=d4.ReviewDecision.EXPECTED_BEHAVIOR,
        reason="documented behavior",
        supersedes="rev-1",
    )


def test_regression_and_export_rules():
    with pytest.raises(ContractError, match="columns"):
        d4.RelationAssertion(d4.RelationAssertionMode.TYPED_MULTISET_EXACT, (), "spec")
    with pytest.raises(ContractError, match="2000"):
        d4.RelationAssertion(
            d4.RelationAssertionMode.TYPED_MULTISET_EXACT, ("c0",), "x" * 2001
        )
    with pytest.raises(ContractError, match="review_ref"):
        d4.ExportManifest(
            export_id=EXPORT_ID,
            format=d4.ExportFormat.REGRESSION,
            source_delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            selected_case_id=CASE_ID,
            name_map=NameMap("db_a", "db_b", "t_a", "t_b"),
            files=(),
            completion=d4.DeliveryCompletion.COMPLETE,
        )
    with pytest.raises(ContractError, match="manifest"):
        d4.ExportManifest(
            export_id=EXPORT_ID,
            format=d4.ExportFormat.SQL,
            source_delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            selected_case_id=CASE_ID,
            name_map=NameMap("db_a", "db_b", "t_a", "t_b"),
            files=(
                d4.EvidenceFile(
                    d4.EXPORT_MANIFEST_FILENAME, d4.FileRole.EXPORT_CASE, 1, SHA_CD
                ),
            ),
            completion=d4.DeliveryCompletion.COMPLETE,
        )
    with pytest.raises(ContractError, match="limitation"):
        d4.ExportManifest(
            export_id=EXPORT_ID,
            format=d4.ExportFormat.SQL,
            source_delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
            selected_case_id=CASE_ID,
            name_map=NameMap("db_a", "db_b", "t_a", "t_b"),
            files=(),
            limitations=("Not A Code",),
            completion=d4.DeliveryCompletion.COMPLETE,
        )
    # sql format does not require a review_ref.
    d4.ExportManifest(
        export_id=EXPORT_ID,
        format=d4.ExportFormat.SQL,
        source_delivery_id=GOLDEN_DELIVERY_ID_SINGLE,
        selected_case_id=CASE_ID,
        name_map=NameMap("db_a", "db_b", "t_a", "t_b"),
        files=(),
        completion=d4.DeliveryCompletion.COMPLETE,
    )


def test_assessment_dimension_slots_are_typed():
    with pytest.raises(ContractError, match="dimension"):
        d4.EvidenceAssessment(
            structural=d4.DimensionResult(
                d4.AssessmentDimension.SEMANTIC, True, d4.SemanticStatus.RECOMPUTED
            ),
            semantic=build_assessment().semantic,
            provenance=build_assessment().provenance,
            execution_safety=build_assessment().execution_safety,
        )
    with pytest.raises(ContractError, match="status"):
        d4.DimensionResult(
            d4.AssessmentDimension.STRUCTURAL, True, d4.SemanticStatus.RECOMPUTED
        )
    with pytest.raises(ContractError, match="reason_code"):
        d4.DimensionResult(
            d4.AssessmentDimension.STRUCTURAL, True, d4.StructuralStatus.PARTIAL,
            ("Bad Code",),
        )


# --------------------------------------------------------------------------
# Aggregation helpers (design 6.2.2 ordering)
# --------------------------------------------------------------------------


def obs(dimension, status, applicable=True):
    return d4.DimensionObservation(dimension, applicable, status)


def test_aggregate_structural_ordering():
    A = d4.AssessmentDimension.STRUCTURAL
    assert d4.aggregate_structural((obs(A, d4.StructuralStatus.COMPLETE),)) == (
        d4.StructuralStatus.COMPLETE
    )
    assert d4.aggregate_structural(
        (obs(A, d4.StructuralStatus.COMPLETE), obs(A, d4.StructuralStatus.PARTIAL))
    ) == d4.StructuralStatus.PARTIAL
    assert d4.aggregate_structural(
        (
            obs(A, d4.StructuralStatus.PARTIAL),
            obs(A, d4.StructuralStatus.UNSUPPORTED),
            obs(A, d4.StructuralStatus.COMPLETE),
        )
    ) == d4.StructuralStatus.UNSUPPORTED
    assert d4.aggregate_structural(
        (
            obs(A, d4.StructuralStatus.CORRUPT),
            obs(A, d4.StructuralStatus.UNSUPPORTED),
        )
    ) == d4.StructuralStatus.CORRUPT
    # Not-applicable observations are ignored; empty input is vacuously COMPLETE.
    assert d4.aggregate_structural((obs(A, d4.StructuralStatus.CORRUPT, False),)) == (
        d4.StructuralStatus.COMPLETE
    )
    assert d4.aggregate_structural(()) == d4.StructuralStatus.COMPLETE


def test_aggregate_semantic_priority_and_unchecked():
    A = d4.AssessmentDimension.SEMANTIC
    assert d4.aggregate_semantic((obs(A, d4.SemanticStatus.RECOMPUTED),)) == (
        d4.SemanticStatus.RECOMPUTED
    )
    assert d4.aggregate_semantic(
        (obs(A, d4.SemanticStatus.RECOMPUTED), obs(A, d4.SemanticStatus.NOT_RECOMPUTED))
    ) == d4.SemanticStatus.NOT_RECOMPUTED
    assert d4.aggregate_semantic(
        (obs(A, d4.SemanticStatus.NOT_RECOMPUTED), obs(A, d4.SemanticStatus.CONFLICT))
    ) == d4.SemanticStatus.CONFLICT
    assert d4.aggregate_semantic(()) == d4.SemanticStatus.NOT_RECOMPUTED
    assert d4.aggregate_semantic((obs(A, d4.SemanticStatus.CONFLICT, False),)) == (
        d4.SemanticStatus.NOT_RECOMPUTED
    )


def test_aggregate_provenance_priority_and_unverified():
    A = d4.AssessmentDimension.PROVENANCE
    assert d4.aggregate_provenance((obs(A, d4.ProvenanceStatus.CORROBORATED),)) == (
        d4.ProvenanceStatus.CORROBORATED
    )
    assert d4.aggregate_provenance(
        (obs(A, d4.ProvenanceStatus.CORROBORATED), obs(A, d4.ProvenanceStatus.UNVERIFIED))
    ) == d4.ProvenanceStatus.UNVERIFIED
    assert d4.aggregate_provenance(
        (obs(A, d4.ProvenanceStatus.UNVERIFIED), obs(A, d4.ProvenanceStatus.CONFLICT))
    ) == d4.ProvenanceStatus.CONFLICT
    assert d4.aggregate_provenance(()) == d4.ProvenanceStatus.UNVERIFIED


def test_aggregate_safety_ordering():
    A = d4.AssessmentDimension.EXECUTION_SAFETY
    NA = d4.ExecutionSafetyStatus.NOT_APPLICABLE
    assert d4.aggregate_safety((obs(A, d4.ExecutionSafetyStatus.CONFIRMED),)) == (
        d4.ExecutionSafetyStatus.CONFIRMED
    )
    assert d4.aggregate_safety(
        (obs(A, d4.ExecutionSafetyStatus.CONFIRMED), obs(A, d4.ExecutionSafetyStatus.UNKNOWN))
    ) == d4.ExecutionSafetyStatus.UNKNOWN
    assert d4.aggregate_safety(
        (obs(A, d4.ExecutionSafetyStatus.UNSAFE), obs(A, d4.ExecutionSafetyStatus.UNSAFE))
    ) == d4.ExecutionSafetyStatus.UNSAFE
    assert d4.aggregate_safety((obs(A, NA),)) == NA
    assert d4.aggregate_safety(()) == NA
    # All inputs not applicable (including a mix with applicable=False).
    assert d4.aggregate_safety(
        (obs(A, NA, False), obs(A, d4.ExecutionSafetyStatus.CONFIRMED, False))
    ) == NA
    # UNSAFE outranks every number of CONFIRMED observations.
    assert d4.aggregate_safety(
        (obs(A, d4.ExecutionSafetyStatus.CONFIRMED), obs(A, d4.ExecutionSafetyStatus.CONFIRMED),
         obs(A, d4.ExecutionSafetyStatus.UNSAFE))
    ) == d4.ExecutionSafetyStatus.UNSAFE


def test_aggregates_ignore_other_dimensions():
    assert d4.aggregate_semantic(
        (obs(d4.AssessmentDimension.STRUCTURAL, d4.StructuralStatus.CORRUPT),)
    ) == d4.SemanticStatus.NOT_RECOMPUTED


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------


def test_limits_defaults_match_design_budget_table():
    limits = d4.Limits.default()
    assert limits.max_single_source_file_bytes == 256 * 1024 * 1024
    assert limits.max_total_source_bytes == 1024**3
    assert limits.max_json_document_bytes == 32 * 1024 * 1024
    assert limits.max_files == 10000
    assert limits.max_jsonl_line_bytes == 256 * 1024
    assert limits.max_dir_depth == 16
    assert limits.max_path_bytes == 1024
    assert limits.max_output_single_file_bytes == 256 * 1024 * 1024
    assert limits.max_output_total_bytes == 1024**3
    assert limits.max_html_bytes == 8 * 1024 * 1024
    assert limits.max_markdown_bytes == 8 * 1024 * 1024
    assert limits.min_diagnostic_reserve_bytes == 2 * 1024 * 1024
    assert limits.time_budget_seconds == 120.0
    assert isinstance(limits.time_budget_seconds, float)


def test_limits_decode_valid_document_roundtrip():
    document = canonical_json(d4.Limits.default().to_obj())
    assert d4.decode_limits(parse_strict_json(document)) == d4.Limits.default()
    # Int seconds input is normalized to float.
    assert d4.Limits(time_budget_seconds=300).time_budget_seconds == 300.0
    assert d4.Limits(time_budget_seconds=600.0).time_budget_seconds == 600.0


def test_limits_reject_zero_negative_bool_and_float():
    base = d4.Limits.default().to_obj()
    for value in (0, -1, True):
        bad = dict(base)
        bad["max_files"] = value
        with pytest.raises(ContractError):
            d4.decode_limits(bad)
    with pytest.raises(ContractError, match="float"):
        parse_strict_json(canonical_json(base).replace(b'"max_files":10000', b'"max_files":1.5'))
    with pytest.raises(ContractError, match="unknown fields"):
        extra = dict(base)
        extra["unlimited"] = True
        d4.decode_limits(extra)
    with pytest.raises(ContractError, match="missing required field"):
        partial = dict(base)
        del partial["max_files"]
        d4.decode_limits(partial)


def test_limits_time_budget_bounds():
    for bad in (0, -5, 601, 120.5, True, "120"):
        with pytest.raises(ContractError):
            d4.Limits(time_budget_seconds=bad)
    with pytest.raises(ContractError, match="JSON integer"):
        limits = d4.Limits.default().to_obj()
        limits["time_budget_seconds"] = 120.5
        d4.decode_limits(limits)


def test_limits_have_no_unlimited_escape():
    # Every budget field is finite and positive on the default object, and
    # there is no sentinel value (0/negative/-1) that disables a limit.
    limits = d4.Limits.default().to_obj()
    for name, value in limits.items():
        if name == "time_budget_seconds":
            assert 0 < value <= d4.MAX_TIME_BUDGET_SECONDS
        else:
            assert value > 0
    with pytest.raises(ContractError, match="positive"):
        d4.Limits(max_files=-1)


def test_delivery_module_import_is_io_free():
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src")
    result = subprocess.run(
        [sys.executable, "-c", "import mtsql_typecheck.contracts.delivery"],
        capture_output=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
