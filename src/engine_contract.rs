// SPDX-License-Identifier: AGPL-3.0-only

//! Engine contract handshake (O1).
//!
//! The connector and the engine are two processes shipped as one runtime
//! bundle, and their JSON-RPC contract grows on both sides. A connector that
//! silently talks to an engine whose contract revision it does not know is
//! the three-repo drift shape governance calls out: the wire looks alive, the
//! state machine is not. This module is the one gate between "the engine
//! process is up" and "the account pipeline may touch it".
//!
//! The handshake is two read-only calls on the engine's own pinned surface,
//! each under a five-second budget:
//!
//! 1. 'version' - the engine's own identity ('{name, version}'). A live engine
//!    that answers an error here, or answers without a usable identity, cannot
//!    be verified at all: that is the *missing identity* fault.
//! 2. 'engine.protocolCapabilities' - the self-certification face. Engines that
//!    carry it may state the contract revision they implement
//!    ('contractRevision'); an engine that predates the face answers the
//!    upstream error class and is classified **legacy** (degraded, still
//!    served) - the degradation the compatibility ledger promises, never a
//!    fatal.
//!
//! The contract revision itself is a closed interval of the shared connector
//! contract numbering (docs/implementation-plan.md). The constants below are
//! the connector's half of the release-service 'engineContractRevision'
//! declaration: engine min == max, connector min ... max (see
//! data/components/signal-runtime/catalog.json in the release service). A
//! revision outside the interval - or an unparsable one - is a fatal that is
//! **not** retryable: the same binary answers the same revision on every
//! restart, so retrying it only burns the launcher's restart budget.
//!
//! Degradations and their contracts:
//!
//! - transport failure / silence inside the probe budget -> 'Unavailable'
//!   (startup failure, retryable: the next spawn may win a woken engine);
//! - an answered engine without identity -> 'Mismatch' (fatal, not retryable);
//! - capabilities face absent (old engine) -> report status 'legacy';
//! - revision present and in range -> report status 'match';
//! - revision present and out of range / malformed -> 'Mismatch' (fatal).
//!
//! Nothing here invents an engine value: the strings the report carries are
//! the engine's own verbatim answers, and absence stays absence (no
//! fabricated "0.0.0").

use std::time::Duration;

use serde_json::{Value, json};

use crate::engine::{CallClass, EngineError, EngineHandle};

/// The probe budget for the handshake: five seconds covers both calls on a
/// cold engine (the diagnostic budget is three; this is a startup gate, not a
/// diagnostic, so it gets the launcher's own start budget shape). A woken
/// engine answers in milliseconds; silence for five seconds means the child is
/// wedged, not slow.
pub const ENGINE_CONTRACT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Oldest engine contract revision this connector still speaks (closed
/// interval, the 'engineContractRevision.min' half of the release-service
/// declaration). Bump only together with a compatibility entry.
pub const ENGINE_CONTRACT_MIN_REVISION: &str = "1.200";

/// Newest engine contract revision this connector speaks - its own current
/// contract revision. The release-service declaration pins the engine side to
/// min == max; the connector side is this interval.
pub const ENGINE_CONTRACT_MAX_REVISION: &str = "1.285";

/// The interval as the launcher-facing fatal line renders it
/// ('supported=<range>').
pub const SUPPORTED_ENGINE_CONTRACT_RANGE: &str = "1.200-1.285";

/// The engine answers 'version' with an identity and states a revision inside
/// the supported interval.
pub const CONTRACT_STATUS_MATCH: &str = "match";

/// The engine answers 'version' (identity known) but does not state a contract
/// revision: a pre-handshake engine. Degraded, still served.
pub const CONTRACT_STATUS_LEGACY: &str = "legacy";

/// No verdict has been reached yet this process (the engine has not landed, or
/// the start is in flight).
pub const CONTRACT_STATUS_UNVERIFIED: &str = "unverified";

/// The handshake refused the engine: identity missing or revision out of
/// range. Latched for the process lifetime - never retried.
pub const CONTRACT_STATUS_MISMATCH: &str = "mismatch";

/// Why a handshake fault was raised. Fixed literals only; they reach the
/// doctor/log faces but never the launcher's byte-exact fatal line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MismatchReason {
    /// The engine did not answer 'version' with a usable identity (it answered
    /// an error, or an object without the two strings).
    VersionMissing,
    /// The engine stated a revision, but it is outside
    /// [ENGINE_CONTRACT_MIN_REVISION, ENGINE_CONTRACT_MAX_REVISION].
    RevisionOutOfRange,
    /// The engine stated a revision that is not a major.minor[.patch] number,
    /// so the interval cannot be applied.
    RevisionMalformed,
}

impl MismatchReason {
    /// The stable classification literal (doctor 'engineContractReason', the
    /// metrics line, the log line).
    pub fn as_str(self) -> &'static str {
        match self {
            MismatchReason::VersionMissing => "version_missing",
            MismatchReason::RevisionOutOfRange => "revision_out_of_range",
            MismatchReason::RevisionMalformed => "revision_malformed",
        }
    }
}

/// The latched refusal: everything the launcher's fatal line and the doctor's
/// diagnosis need. Every field is a version string or a fixed literal - no
/// path, no account material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineContractFault {
    pub engine_name: Option<String>,
    pub engine_version: Option<String>,
    pub contract_revision: Option<String>,
    pub reason: MismatchReason,
}

impl EngineContractFault {
    /// The launcher-facing line, byte for byte (contract revision 1.285,
    /// section 4.269):
    /// 'KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine=<v>
    /// supported=<range>'. 'engine=unknown' is used exactly when the engine
    /// failed to state its identity - never a fabricated version.
    pub fn fatal_line(&self) -> String {
        format!(
            "KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine={} supported={}",
            self.engine_version.as_deref().unwrap_or("unknown"),
            SUPPORTED_ENGINE_CONTRACT_RANGE
        )
    }

    /// The structured 'error.data' facts that ride the host wire answer - the
    /// same three facts as the fatal line plus the classification reason, so a
    /// launcher that only reads the RPC face still knows what to repair.
    pub fn report_data(&self) -> Value {
        json!({
            "retryable": false,
            "engine": self.engine_version.as_deref().unwrap_or("unknown"),
            "supported": SUPPORTED_ENGINE_CONTRACT_RANGE,
            "reason": self.reason.as_str(),
        })
    }
}

/// A completed handshake verdict the runtime keeps for the doctor/metrics
/// faces: the engine's own identity plus the connector's classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineContractReport {
    pub engine_name: String,
    pub engine_version: String,
    /// The revision the engine stated, verbatim; None for a legacy engine.
    pub contract_revision: Option<String>,
    /// 'match' or 'legacy' - the two served outcomes.
    pub status: &'static str,
}

/// What one engine slot knows about its handshake: the last served verdict, or
/// the latched fault that refuses further starts. Default is "no verdict yet
/// this process".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineContractState {
    pub report: Option<EngineContractReport>,
    pub fault: Option<EngineContractFault>,
}

impl EngineContractState {
    /// The stable classification literal for a doctor/metrics face.
    pub fn status(&self) -> &'static str {
        match (&self.report, &self.fault) {
            (_, Some(_)) => CONTRACT_STATUS_MISMATCH,
            (Some(report), None) => report.status,
            (None, None) => CONTRACT_STATUS_UNVERIFIED,
        }
    }

    /// The engine's own version, whichever face knows it (a latched fault can
    /// remember it even though no engine is served).
    pub fn engine_version(&self) -> Option<&str> {
        self.report
            .as_ref()
            .map(|report| report.engine_version.as_str())
            .or_else(|| {
                self.fault
                    .as_ref()
                    .and_then(|fault| fault.engine_version.as_deref())
            })
    }

    /// The stated contract revision, whichever face knows it.
    pub fn contract_revision(&self) -> Option<&str> {
        self.report
            .as_ref()
            .and_then(|report| report.contract_revision.as_deref())
            .or_else(|| {
                self.fault
                    .as_ref()
                    .and_then(|fault| fault.contract_revision.as_deref())
            })
    }
}

/// The two handshake outcomes a caller must distinguish: a retryable
/// availability failure, or the latched contract refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineContractError {
    /// The engine stopped answering inside the probe budget (timeout, exit,
    /// queue backpressure, invalid protocol output). The start is a plain
    /// startup failure: retryable.
    Unavailable,
    /// The engine answered but cannot be verified. Not retryable.
    Mismatch(EngineContractFault),
}

/// Run the handshake against a freshly started engine.
pub async fn verify(engine: &EngineHandle) -> Result<EngineContractReport, EngineContractError> {
    let version_payload = match engine
        .call_with_timeout(
            "version",
            json!({}),
            CallClass::ReadOnly,
            ENGINE_CONTRACT_PROBE_TIMEOUT,
        )
        .await
    {
        Ok(payload) => payload,
        Err(error) if is_unavailable(&error) => return Err(EngineContractError::Unavailable),
        // The engine answered a JSON-RPC error: it is alive but cannot state
        // its identity, which is exactly the missing-identity fault.
        Err(_) => return Err(EngineContractError::Mismatch(identity_missing(None, None))),
    };
    let capabilities = match engine
        .call_with_timeout(
            "engine.protocolCapabilities",
            json!({}),
            CallClass::ReadOnly,
            ENGINE_CONTRACT_PROBE_TIMEOUT,
        )
        .await
    {
        Ok(payload) => Some(payload),
        Err(error) if is_unavailable(&error) => return Err(EngineContractError::Unavailable),
        // An engine predating the self-certification face answers the
        // upstream error class - that is the documented legacy degradation,
        // not a fault.
        Err(_) => None,
    };
    evaluate(&version_payload, capabilities.as_ref()).map_err(EngineContractError::Mismatch)
}

/// The pure half: fold the two engine answers into a verdict. Split out so the
/// whole decision table is testable without a child process.
pub fn evaluate(
    version_payload: &Value,
    capabilities: Option<&Value>,
) -> Result<EngineContractReport, EngineContractFault> {
    let engine_name = string_field(version_payload, "name");
    let engine_version = string_field(version_payload, "version");
    let (Some(engine_name), Some(engine_version)) = (engine_name, engine_version) else {
        return Err(identity_missing(engine_name, engine_version));
    };
    let identity_name = engine_name.to_owned();
    let identity_version = engine_version.to_owned();
    // The capabilities face is authoritative when it states a revision; the
    // version answer is the additive fallback so an engine may carry the fact
    // on either face without a wire break here.
    let revision = capabilities
        .and_then(contract_revision)
        .or_else(|| contract_revision(version_payload));
    let Some(revision) = revision else {
        return Ok(EngineContractReport {
            engine_name: identity_name,
            engine_version: identity_version,
            contract_revision: None,
            status: CONTRACT_STATUS_LEGACY,
        });
    };
    let Some(parsed) = parse_revision(revision) else {
        return Err(EngineContractFault {
            engine_name: Some(identity_name),
            engine_version: Some(identity_version),
            contract_revision: Some(revision.to_owned()),
            reason: MismatchReason::RevisionMalformed,
        });
    };
    if !revision_in_supported_range(parsed) {
        return Err(EngineContractFault {
            engine_name: Some(identity_name),
            engine_version: Some(identity_version),
            contract_revision: Some(revision.to_owned()),
            reason: MismatchReason::RevisionOutOfRange,
        });
    }
    Ok(EngineContractReport {
        engine_name: identity_name,
        engine_version: identity_version,
        contract_revision: Some(revision.to_owned()),
        status: CONTRACT_STATUS_MATCH,
    })
}

fn identity_missing(
    engine_name: Option<&str>,
    engine_version: Option<&str>,
) -> EngineContractFault {
    EngineContractFault {
        engine_name: engine_name.map(str::to_owned),
        engine_version: engine_version.map(str::to_owned),
        contract_revision: None,
        reason: MismatchReason::VersionMissing,
    }
}

/// A non-empty string member of an engine answer.
fn string_field<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The engine's stated contract revision on one answer face.
fn contract_revision(payload: &Value) -> Option<&str> {
    string_field(payload, "contractRevision")
}

/// Transport/availability classes: the engine never gave an answer. Every
/// other class means the engine answered a JSON-RPC error object.
fn is_unavailable(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::Timeout
            | EngineError::NotRunning
            | EngineError::Exited
            | EngineError::Backpressure
            | EngineError::Protocol
    )
}

/// major.minor[.patch]; anything else (an empty string, a date, a range token)
/// is malformed and refuses the engine instead of being compared
/// lexicographically.
fn parse_revision(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.trim().split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Closed interval over the two pinned endpoints.
fn revision_in_supported_range(revision: (u64, u64, u64)) -> bool {
    let min = parse_revision(ENGINE_CONTRACT_MIN_REVISION)
        .expect("the supported-range floor is a valid revision literal");
    let max = parse_revision(ENGINE_CONTRACT_MAX_REVISION)
        .expect("the supported-range ceiling is a valid revision literal");
    revision >= min && revision <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(name: &str, version: &str) -> Value {
        json!({ "name": name, "version": version })
    }

    #[test]
    fn the_pinned_range_is_parseable_and_ordered() {
        let min = parse_revision(ENGINE_CONTRACT_MIN_REVISION).expect("floor parses");
        let max = parse_revision(ENGINE_CONTRACT_MAX_REVISION).expect("ceiling parses");
        assert!(min <= max, "the supported interval must be ordered");
        assert_eq!(SUPPORTED_ENGINE_CONTRACT_RANGE, "1.200-1.285");
    }

    #[test]
    fn a_matching_revision_is_served_with_the_engines_own_strings() {
        let report = evaluate(
            &version("kt-signal-engine", "0.1.0-dev.29"),
            Some(&json!({ "contractRevision": "1.285", "baseline": {} })),
        )
        .expect("in-range revision is a match");
        assert_eq!(report.status, CONTRACT_STATUS_MATCH);
        assert_eq!(report.engine_name, "kt-signal-engine");
        assert_eq!(report.engine_version, "0.1.0-dev.29");
        assert_eq!(report.contract_revision.as_deref(), Some("1.285"));
    }

    #[test]
    fn the_closed_interval_accepts_both_endpoints() {
        for revision in [ENGINE_CONTRACT_MIN_REVISION, ENGINE_CONTRACT_MAX_REVISION] {
            let report = evaluate(
                &version("kt-signal-engine", "0.1.0"),
                Some(&json!({ "contractRevision": revision })),
            )
            .expect("both closed endpoints are supported");
            assert_eq!(report.status, CONTRACT_STATUS_MATCH);
        }
    }

    #[test]
    fn a_revision_outside_the_interval_is_a_non_retryable_fault() {
        let fault = evaluate(
            &version("kt-signal-engine", "0.1.0-dev.29"),
            Some(&json!({ "contractRevision": "1.100" })),
        )
        .expect_err("an older engine contract is refused");
        assert_eq!(fault.reason, MismatchReason::RevisionOutOfRange);
        assert_eq!(
            fault.fatal_line(),
            "KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine=0.1.0-dev.29 supported=1.200-1.285"
        );
        assert_eq!(
            fault.report_data(),
            json!({
                "retryable": false,
                "engine": "0.1.0-dev.29",
                "supported": "1.200-1.285",
                "reason": "revision_out_of_range",
            })
        );
    }

    #[test]
    fn an_engine_without_capabilities_is_a_legacy_degradation() {
        let report = evaluate(&version("kt-signal-engine", "0.1.0"), None)
            .expect("an engine predating the face is served");
        assert_eq!(report.status, CONTRACT_STATUS_LEGACY);
        assert!(report.contract_revision.is_none(), "absence stays absence");
        assert_eq!(report.engine_version, "0.1.0");
    }

    #[test]
    fn an_engine_with_capabilities_but_no_revision_is_also_legacy() {
        let report = evaluate(
            &version("kt-signal-engine", "0.1.0"),
            Some(&json!({ "baseline": { "presageRev": "abc" } })),
        )
        .expect("the self-certification face without a revision stays legacy");
        assert_eq!(report.status, CONTRACT_STATUS_LEGACY);
        assert!(report.contract_revision.is_none());
    }

    #[test]
    fn the_version_answer_is_the_additive_revision_fallback() {
        let report = evaluate(
            &json!({
                "name": "kt-signal-engine",
                "version": "0.1.0",
                "contractRevision": "1.250",
            }),
            Some(&json!({ "baseline": {} })),
        )
        .expect("the revision may ride the version answer");
        assert_eq!(report.status, CONTRACT_STATUS_MATCH);
        assert_eq!(report.contract_revision.as_deref(), Some("1.250"));
    }

    #[test]
    fn a_malformed_revision_refuses_the_engine() {
        let fault = evaluate(
            &version("kt-signal-engine", "0.1.0"),
            Some(&json!({ "contractRevision": "not-a-revision" })),
        )
        .expect_err("a range token is not a revision");
        assert_eq!(fault.reason, MismatchReason::RevisionMalformed);
        assert_eq!(fault.contract_revision.as_deref(), Some("not-a-revision"));
    }

    #[test]
    fn a_missing_identity_is_the_missing_fault() {
        let fault = evaluate(&json!({ "method": "version" }), None)
            .expect_err("an echo without identity refuses the engine");
        assert_eq!(fault.reason, MismatchReason::VersionMissing);
        assert_eq!(
            fault.fatal_line(),
            "KT_FATAL code=ENGINE_CONTRACT_MISMATCH retryable=false engine=unknown supported=1.200-1.285"
        );
    }

    #[test]
    fn a_partial_identity_keeps_the_version_it_did_state() {
        let fault = evaluate(&json!({ "version": "0.1.0" }), None)
            .expect_err("name-less identity is refused");
        assert_eq!(fault.reason, MismatchReason::VersionMissing);
        assert!(fault.fatal_line().contains("engine=0.1.0"));
    }

    #[test]
    fn states_report_the_driving_face() {
        let unverified = EngineContractState::default();
        assert_eq!(unverified.status(), CONTRACT_STATUS_UNVERIFIED);
        assert!(unverified.engine_version().is_none());

        let legacy = EngineContractState {
            report: Some(EngineContractReport {
                engine_name: "kt-signal-engine".into(),
                engine_version: "0.1.0".into(),
                contract_revision: None,
                status: CONTRACT_STATUS_LEGACY,
            }),
            fault: None,
        };
        assert_eq!(legacy.status(), CONTRACT_STATUS_LEGACY);
        assert_eq!(legacy.engine_version(), Some("0.1.0"));
        assert_eq!(legacy.contract_revision(), None);

        let mismatched = EngineContractState {
            report: None,
            fault: Some(EngineContractFault {
                engine_name: Some("kt-signal-engine".into()),
                engine_version: Some("0.1.0".into()),
                contract_revision: Some("1.100".into()),
                reason: MismatchReason::RevisionOutOfRange,
            }),
        };
        assert_eq!(mismatched.status(), CONTRACT_STATUS_MISMATCH);
        assert_eq!(mismatched.engine_version(), Some("0.1.0"));
        assert_eq!(mismatched.contract_revision(), Some("1.100"));
    }
}
