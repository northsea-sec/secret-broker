//! Hand-rolled chained-HMAC macaroons for broker handle authorization.
//!
//! A macaroon is a bearer credential with embedded caveats (restrictions).
//! The HMAC chain ensures: anyone can ADD caveats, nobody can REMOVE them
//! (monotonic attenuation).
//!
//! Algorithm:
//!   sig_0 = HMAC(root_key, identifier)
//!   sig_i = HMAC(sig_{i-1}, caveat_i)
//!   final_sig = sig_n
//!
//! Verification: recompute chain from root_key, compare final sig.

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum MacaroonError {
    #[error("invalid macaroon format")]
    InvalidFormat,
    #[error("HMAC chain verification failed")]
    SignatureInvalid,
    #[error("caveat check failed: {0}")]
    CaveatFailed(String),
    #[error("macaroon expired")]
    Expired,
    #[error("unknown caveat key: {0}")]
    UnknownCaveat(String),
}

/// A caveat embedded in the macaroon - either first-party (self-verifiable)
/// or third-party (requires a discharge macaroon from an external service).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    // First-party caveats.
    TenantId(String),
    Provider(String),
    Expires(DateTime<Utc>),
    CircuitId(String),
    NodeId(String),
    Action(String),
    /// Single-use: exactly one unwrap permitted. The parameter is always 1;
    /// the runtime rejects any other value. Removing the u32 parameter makes
    /// the intent explicit and prevents callers from assuming >1 is supported.
    MaxUses,
    // Third-party caveats.
    /// A third-party caveat selected by an opaque per-secret identifier.
    /// The predicate remains in sealed broker state and never appears in the handle.
    ThirdParty {
        location: String,
        key_id: String,
    },
}

impl Caveat {
    pub fn encode(&self) -> String {
        match self {
            Caveat::TenantId(v) => format!("tenant_id = {v}"),
            Caveat::Provider(v) => format!("provider = {v}"),
            Caveat::Expires(v) => format!("expires = {}", v.to_rfc3339()),
            Caveat::CircuitId(v) => format!("circuit_id = {v}"),
            Caveat::NodeId(v) => format!("node_id = {v}"),
            Caveat::Action(v) => format!("action = {v}"),
            Caveat::MaxUses => "max_uses = 1".to_string(),
            Caveat::ThirdParty { location, key_id } => format!(
                "3p = v3:{}:{}",
                URL_SAFE_NO_PAD.encode(location.as_bytes()),
                URL_SAFE_NO_PAD.encode(key_id.as_bytes()),
            ),
        }
    }

    pub fn parse(s: &str) -> Result<Self, MacaroonError> {
        let (key, value) = s.split_once(" = ").ok_or(MacaroonError::InvalidFormat)?;
        match key {
            "tenant_id" => Ok(Caveat::TenantId(value.to_string())),
            "provider" => Ok(Caveat::Provider(value.to_string())),
            "expires" => {
                let dt = DateTime::parse_from_rfc3339(value)
                    .map_err(|_| MacaroonError::InvalidFormat)?
                    .with_timezone(&Utc);
                Ok(Caveat::Expires(dt))
            }
            "circuit_id" => Ok(Caveat::CircuitId(value.to_string())),
            "node_id" => Ok(Caveat::NodeId(value.to_string())),
            "action" => Ok(Caveat::Action(value.to_string())),
            "max_uses" => {
                let n: u32 = value.parse().map_err(|_| MacaroonError::InvalidFormat)?;
                if n != 1 {
                    return Err(MacaroonError::CaveatFailed(format!(
                        "max_uses only supports value 1, got {n}"
                    )));
                }
                Ok(Caveat::MaxUses)
            }
            "3p" => {
                let encoded = value
                    .strip_prefix("v3:")
                    .ok_or(MacaroonError::InvalidFormat)?;
                let (location, key_id) = encoded
                    .split_once(':')
                    .ok_or(MacaroonError::InvalidFormat)?;
                if key_id.contains(':') {
                    return Err(MacaroonError::InvalidFormat);
                }
                let location = String::from_utf8(
                    URL_SAFE_NO_PAD
                        .decode(location.as_bytes())
                        .map_err(|_| MacaroonError::InvalidFormat)?,
                )
                .map_err(|_| MacaroonError::InvalidFormat)?;
                let key_id = String::from_utf8(
                    URL_SAFE_NO_PAD
                        .decode(key_id.as_bytes())
                        .map_err(|_| MacaroonError::InvalidFormat)?,
                )
                .map_err(|_| MacaroonError::InvalidFormat)?;
                if location.is_empty() || key_id.is_empty() {
                    return Err(MacaroonError::InvalidFormat);
                }
                Ok(Caveat::ThirdParty { location, key_id })
            }
            other => Err(MacaroonError::UnknownCaveat(other.to_string())),
        }
    }

    /// Returns true if this is a third-party caveat requiring a discharge.
    pub fn is_third_party(&self) -> bool {
        matches!(self, Caveat::ThirdParty { .. })
    }
}

/// Chained-HMAC macaroon.
#[derive(Clone)]
pub struct Macaroon {
    pub identifier: Uuid,
    pub caveats: Vec<String>,
    signature: [u8; 32],
}

impl Macaroon {
    /// Mint a new macaroon with the given caveats.
    pub fn mint(root_key: &[u8; 32], identifier: Uuid, caveats: Vec<Caveat>) -> Self {
        let mut sig = hmac_compute(root_key, identifier.as_bytes());
        let caveat_strings: Vec<String> = caveats.iter().map(|c| c.encode()).collect();
        for c in &caveat_strings {
            sig = hmac_compute(&sig, c.as_bytes());
        }
        Self {
            identifier,
            caveats: caveat_strings,
            signature: sig,
        }
    }

    /// Add a caveat (attenuate). Re-chains the HMAC - the caller
    /// does NOT need the root key to add restrictions.
    pub fn add_caveat(&mut self, caveat: Caveat) {
        let encoded = caveat.encode();
        self.signature = hmac_compute(&self.signature, encoded.as_bytes());
        self.caveats.push(encoded);
    }

    /// Verify the HMAC chain and all caveats against the provided context.
    pub fn verify(
        &self,
        root_key: &[u8; 32],
        verifier: &CaveatVerifier,
    ) -> Result<(), MacaroonError> {
        let mut sig = hmac_compute(root_key, self.identifier.as_bytes());
        let mut caveat_signatures = Vec::with_capacity(self.caveats.len());
        for c in &self.caveats {
            sig = hmac_compute(&sig, c.as_bytes());
            caveat_signatures.push(sig);
        }
        if sig.ct_eq(&self.signature).unwrap_u8() == 0 {
            return Err(MacaroonError::SignatureInvalid);
        }
        for (raw, primary_signature) in self.caveats.iter().zip(caveat_signatures.iter()) {
            let caveat = Caveat::parse(raw)?;
            verifier.check(&caveat, Some(primary_signature))?;
        }
        Ok(())
    }

    pub fn third_party_binding_info_by_key_id(
        &self,
        root_key: &[u8; 32],
        location: &str,
        key_id: &str,
    ) -> Result<[u8; 32], MacaroonError> {
        let mut sig = hmac_compute(root_key, self.identifier.as_bytes());
        let mut matched: Option<[u8; 32]> = None;
        for raw in &self.caveats {
            sig = hmac_compute(&sig, raw.as_bytes());
            match Caveat::parse(raw)? {
                Caveat::ThirdParty {
                    location: caveat_location,
                    key_id: caveat_key_id,
                } if caveat_location == location && caveat_key_id == key_id => {
                    if matched.is_some() {
                        return Err(MacaroonError::CaveatFailed(format!(
                            "multiple third-party caveats match {location} with opaque key"
                        )));
                    }
                    matched = Some(sig);
                }
                _ => {}
            }
        }
        matched.ok_or_else(|| {
            MacaroonError::CaveatFailed(format!(
                "no third-party caveat for {location} with requested opaque key"
            ))
        })
    }

    /// Serialize to compact binary, then base64.
    ///
    /// Wire format:
    ///   [16 bytes identifier (UUID)]
    ///   [u16 LE num_caveats]
    ///   [u16 LE len][caveat bytes] x num_caveats
    ///   [32 bytes signature]
    pub fn serialize(&self) -> String {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.identifier.as_bytes());
        let n = self.caveats.len() as u16;
        buf.extend_from_slice(&n.to_le_bytes());
        for c in &self.caveats {
            let len = c.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(c.as_bytes());
        }
        buf.extend_from_slice(&self.signature);
        B64.encode(&buf)
    }

    /// Deserialize from base64.
    pub fn deserialize(s: &str) -> Result<Self, MacaroonError> {
        let buf = B64
            .decode(s.as_bytes())
            .map_err(|_| MacaroonError::InvalidFormat)?;
        if buf.len() < 16 + 2 + 32 {
            return Err(MacaroonError::InvalidFormat);
        }
        let identifier = Uuid::from_slice(&buf[..16]).map_err(|_| MacaroonError::InvalidFormat)?;
        let num_caveats = u16::from_le_bytes([buf[16], buf[17]]) as usize;
        let mut pos = 18;
        let mut caveats = Vec::with_capacity(num_caveats);
        for _ in 0..num_caveats {
            if pos + 2 > buf.len() {
                return Err(MacaroonError::InvalidFormat);
            }
            let len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            if pos + len > buf.len() {
                return Err(MacaroonError::InvalidFormat);
            }
            let s = std::str::from_utf8(&buf[pos..pos + len])
                .map_err(|_| MacaroonError::InvalidFormat)?;
            caveats.push(s.to_string());
            pos += len;
        }
        if pos + 32 != buf.len() {
            return Err(MacaroonError::InvalidFormat);
        }
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&buf[pos..pos + 32]);
        Ok(Self {
            identifier,
            caveats,
            signature,
        })
    }
}

impl Drop for Macaroon {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

/// A discharge macaroon that satisfies a third-party caveat.
///
/// The discharge is minted by the third-party service (identified by `location`
/// in the caveat). It binds to the primary macaroon via the condition:
///   discharge_sig = HMAC(discharge_key, condition)
///   binding       = HMAC(primary_sig, discharge_sig)
///
/// At verification time, the verifier checks that each third-party caveat has
/// a matching discharge whose binding is valid.
#[derive(Debug, Clone)]
pub struct DischargeMacaroon {
    /// The location this discharge was minted for.
    pub location: String,
    /// The condition this discharge satisfies.
    pub condition: String,
    /// Optional expiry for the discharge itself.
    pub expires_at: Option<DateTime<Utc>>,
    /// HMAC(discharge_key, condition) - proves the third-party service
    /// validated the condition.
    pub discharge_signature: [u8; 32],
    /// HMAC(primary_sig, discharge_sig) - binds this discharge to one specific
    /// primary macaroon at the exact third-party caveat position.
    pub binding: [u8; 32],
}

impl DischargeMacaroon {
    /// Mint a discharge proving `condition` was satisfied and bind it to the
    /// provided primary macaroon signature.
    pub fn mint(
        location: &str,
        condition: &str,
        discharge_key: &[u8; 32],
        primary_signature: &[u8; 32],
    ) -> Self {
        Self::mint_with_expiry(location, condition, discharge_key, primary_signature, None)
    }

    pub fn mint_with_expiry(
        location: &str,
        condition: &str,
        discharge_key: &[u8; 32],
        primary_signature: &[u8; 32],
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let discharge_signature = hmac_compute(discharge_key, condition.as_bytes());
        let binding = hmac_compute(primary_signature, &discharge_signature);
        Self {
            location: location.to_string(),
            condition: condition.to_string(),
            expires_at,
            discharge_signature,
            binding,
        }
    }

    /// Compute the binding hash that ties this discharge to a primary macaroon.
    /// `primary_signature` is the current HMAC chain signature of the primary
    /// macaroon at the point where the third-party caveat was added.
    pub fn bind(&self, primary_signature: &[u8; 32]) -> [u8; 32] {
        hmac_compute(primary_signature, &self.discharge_signature)
    }

    /// Verify that this discharge was minted with the correct key for the
    /// given condition and is bound to the expected primary macaroon.
    pub fn verify(
        &self,
        condition: &str,
        discharge_key: &[u8; 32],
        primary_signature: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<(), MacaroonError> {
        if self.expires_at.is_some_and(|deadline| now > deadline) {
            return Err(MacaroonError::Expired);
        }
        let expected = hmac_compute(discharge_key, condition.as_bytes());
        if expected.ct_eq(&self.discharge_signature).unwrap_u8() == 0 {
            return Err(MacaroonError::CaveatFailed(
                "discharge signature invalid".into(),
            ));
        }
        let expected_binding = self.bind(primary_signature);
        if expected_binding.ct_eq(&self.binding).unwrap_u8() == 0 {
            return Err(MacaroonError::CaveatFailed(
                "discharge binding invalid".into(),
            ));
        }
        Ok(())
    }

    /// Serialize to compact binary, then base64.
    /// Wire format:
    ///   [u16 LE location_len][location bytes]
    ///   [u16 LE condition_len][condition bytes]
    ///   optional:
    ///     [i64 LE expiry_unix_seconds]
    ///   [32 bytes discharge_signature]
    ///   [32 bytes binding]
    pub fn serialize(&self) -> String {
        let mut buf = Vec::with_capacity(4 + self.location.len() + self.condition.len() + 8 + 64);
        let loc_len = self.location.len() as u16;
        buf.extend_from_slice(&loc_len.to_le_bytes());
        buf.extend_from_slice(self.location.as_bytes());
        let cond_len = self.condition.len() as u16;
        buf.extend_from_slice(&cond_len.to_le_bytes());
        buf.extend_from_slice(self.condition.as_bytes());
        if let Some(expires_at) = self.expires_at {
            buf.extend_from_slice(&expires_at.timestamp().to_le_bytes());
        }
        buf.extend_from_slice(&self.discharge_signature);
        buf.extend_from_slice(&self.binding);
        B64.encode(&buf)
    }

    /// Deserialize from base64.
    pub fn deserialize(s: &str) -> Result<Self, MacaroonError> {
        let buf = B64
            .decode(s.as_bytes())
            .map_err(|_| MacaroonError::InvalidFormat)?;
        if buf.len() < 4 + 64 {
            return Err(MacaroonError::InvalidFormat);
        }
        let loc_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let mut pos = 2;
        if pos + loc_len + 2 + 64 > buf.len() {
            return Err(MacaroonError::InvalidFormat);
        }
        let location = std::str::from_utf8(&buf[pos..pos + loc_len])
            .map_err(|_| MacaroonError::InvalidFormat)?
            .to_string();
        pos += loc_len;
        let cond_len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let remaining = buf.len().saturating_sub(pos + cond_len);
        if !matches!(remaining, 64 | 72) {
            return Err(MacaroonError::InvalidFormat);
        }
        let condition = std::str::from_utf8(&buf[pos..pos + cond_len])
            .map_err(|_| MacaroonError::InvalidFormat)?
            .to_string();
        pos += cond_len;
        let expires_at = if remaining == 72 {
            let mut expiry_bytes = [0u8; 8];
            expiry_bytes.copy_from_slice(&buf[pos..pos + 8]);
            pos += 8;
            DateTime::from_timestamp(i64::from_le_bytes(expiry_bytes), 0)
        } else {
            None
        };
        let mut discharge_signature = [0u8; 32];
        discharge_signature.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let mut binding = [0u8; 32];
        binding.copy_from_slice(&buf[pos..pos + 32]);
        Ok(Self {
            location,
            condition,
            expires_at,
            discharge_signature,
            binding,
        })
    }
}

impl Drop for DischargeMacaroon {
    fn drop(&mut self) {
        self.discharge_signature.zeroize();
        self.binding.zeroize();
    }
}

/// Context for verifying caveats against the current request.
pub struct CaveatVerifier {
    pub tenant_id: Option<String>,
    pub provider: Option<String>,
    pub circuit_id: Option<String>,
    pub node_id: Option<String>,
    pub action: Option<String>,
    pub use_count: u32,
    pub now: DateTime<Utc>,
    /// Discharge macaroons provided alongside the primary macaroon.
    /// Each entry satisfies one third-party caveat. Keyed by location.
    pub discharges: Vec<DischargeMacaroon>,
    /// Per-handle, per-caveat keys for verifying discharge macaroons.
    pub discharge_keys: Vec<DischargeKeyRef>,
}

#[derive(Debug, Clone)]
pub struct DischargeKeyRef {
    pub location: String,
    pub key_id: String,
    pub condition: String,
    pub key: [u8; 32],
}

impl CaveatVerifier {
    /// Create a verifier with only first-party context (no discharges).
    pub fn first_party_only(
        tenant_id: Option<String>,
        provider: Option<String>,
        circuit_id: Option<String>,
        node_id: Option<String>,
        action: Option<String>,
        use_count: u32,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id,
            provider,
            circuit_id,
            node_id,
            action,
            use_count,
            now,
            discharges: vec![],
            discharge_keys: vec![],
        }
    }

    pub fn check(
        &self,
        caveat: &Caveat,
        primary_signature: Option<&[u8; 32]>,
    ) -> Result<(), MacaroonError> {
        match caveat {
            Caveat::TenantId(expected) => match &self.tenant_id {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(MacaroonError::CaveatFailed(format!(
                    "tenant_id: expected {expected}, got {actual}"
                ))),
                None => Err(MacaroonError::CaveatFailed(
                    "tenant_id required but not provided".into(),
                )),
            },
            Caveat::Provider(expected) => match &self.provider {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(MacaroonError::CaveatFailed(format!(
                    "provider: expected {expected}, got {actual}"
                ))),
                None => Err(MacaroonError::CaveatFailed(
                    "provider required but not provided".into(),
                )),
            },
            Caveat::Expires(deadline) => {
                if self.now > *deadline {
                    Err(MacaroonError::Expired)
                } else {
                    Ok(())
                }
            }
            Caveat::CircuitId(expected) => match &self.circuit_id {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(MacaroonError::CaveatFailed(format!(
                    "circuit_id: expected {expected}, got {actual}"
                ))),
                None => Err(MacaroonError::CaveatFailed(
                    "circuit_id required but not provided".into(),
                )),
            },
            Caveat::NodeId(expected) => match &self.node_id {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(MacaroonError::CaveatFailed(format!(
                    "node_id: expected {expected}, got {actual}"
                ))),
                None => Err(MacaroonError::CaveatFailed(
                    "node_id required but not provided".into(),
                )),
            },
            Caveat::Action(expected) => match &self.action {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(MacaroonError::CaveatFailed(format!(
                    "action: expected {expected}, got {actual}"
                ))),
                None => Err(MacaroonError::CaveatFailed(
                    "action required but not provided".into(),
                )),
            },
            Caveat::MaxUses => {
                if self.use_count <= 1 {
                    Ok(())
                } else {
                    Err(MacaroonError::CaveatFailed(format!(
                        "max_uses: attempted use {} exceeds single-use limit",
                        self.use_count
                    )))
                }
            }
            Caveat::ThirdParty { location, key_id } => {
                let primary_signature = primary_signature.ok_or_else(|| {
                    MacaroonError::CaveatFailed(
                        "missing primary binding signature for third-party caveat".into(),
                    )
                })?;
                let key = self
                    .discharge_keys
                    .iter()
                    .find(|entry| entry.location == *location && entry.key_id == *key_id)
                    .ok_or_else(|| {
                        MacaroonError::CaveatFailed(format!(
                            "no discharge key configured for location {location}"
                        ))
                    })?;
                let expected_condition = key.condition.as_str();
                let mut saw_candidate = false;
                for discharge in self
                    .discharges
                    .iter()
                    .filter(|d| d.location == *location && d.condition == expected_condition)
                {
                    saw_candidate = true;
                    if discharge
                        .verify(expected_condition, &key.key, primary_signature, self.now)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                if !saw_candidate {
                    return Err(MacaroonError::CaveatFailed(format!(
                        "no discharge macaroon for third-party caveat at {location}"
                    )));
                }
                Err(MacaroonError::CaveatFailed(format!(
                    "no valid discharge macaroon for third-party caveat at {location}"
                )))
            }
        }
    }
}

fn hmac_compute(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length always valid");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn verifier(now: DateTime<Utc>) -> CaveatVerifier {
        CaveatVerifier::first_party_only(
            Some("tenant-a".into()),
            Some("provider-a".into()),
            None,
            None,
            Some("unwrap".into()),
            1,
            now,
        )
    }

    #[test]
    fn attenuation_is_monotonic() {
        let key = [7u8; 32];
        let id = Uuid::new_v4();
        let mut macaroon = Macaroon::mint(&key, id, vec![Caveat::TenantId("tenant-a".into())]);
        macaroon.add_caveat(Caveat::Action("unwrap".into()));
        assert!(macaroon.verify(&key, &verifier(Utc::now())).is_ok());

        let encoded = macaroon.serialize();
        let mut tampered = Macaroon::deserialize(&encoded).unwrap();
        tampered.caveats.pop();
        assert!(matches!(
            tampered.verify(&key, &verifier(Utc::now())),
            Err(MacaroonError::SignatureInvalid)
        ));
    }

    #[test]
    fn canonical_third_party_caveat_roundtrips_losslessly() {
        let caveat = Caveat::ThirdParty {
            location: "spiffe://trust.example/discharger".into(),
            key_id: "opaque:caveat:123".into(),
        };
        assert_eq!(Caveat::parse(&caveat.encode()).unwrap(), caveat);
    }

    #[test]
    fn noncanonical_third_party_wire_format_is_rejected() {
        assert!(matches!(
            Caveat::parse("3p = service:predicate"),
            Err(MacaroonError::InvalidFormat)
        ));
    }

    #[test]
    fn valid_discharge_satisfies_bound_third_party_caveat() {
        let root_key = [9u8; 32];
        let discharge_key = [8u8; 32];
        let location = "spiffe://trust.example/discharger";
        let key_id = "opaque-123";
        let condition = "attestation = valid";
        let macaroon = Macaroon::mint(
            &root_key,
            Uuid::new_v4(),
            vec![Caveat::ThirdParty {
                location: location.into(),
                key_id: key_id.into(),
            }],
        );
        let binding = macaroon
            .third_party_binding_info_by_key_id(&root_key, location, key_id)
            .unwrap();
        let discharge = DischargeMacaroon::mint_with_expiry(
            location,
            condition,
            &discharge_key,
            &binding,
            Some(Utc::now() + Duration::minutes(5)),
        );
        let verifier = CaveatVerifier {
            tenant_id: None,
            provider: None,
            circuit_id: None,
            node_id: None,
            action: None,
            use_count: 1,
            now: Utc::now(),
            discharges: vec![discharge],
            discharge_keys: vec![DischargeKeyRef {
                location: location.into(),
                key_id: key_id.into(),
                condition: condition.into(),
                key: discharge_key,
            }],
        };
        assert!(macaroon.verify(&root_key, &verifier).is_ok());
    }

    #[test]
    fn expired_discharge_is_rejected() {
        let discharge = DischargeMacaroon::mint_with_expiry(
            "service",
            "approved",
            &[3u8; 32],
            &[4u8; 32],
            Some(Utc::now() - Duration::seconds(1)),
        );
        assert!(matches!(
            discharge.verify("approved", &[3u8; 32], &[4u8; 32], Utc::now()),
            Err(MacaroonError::Expired)
        ));
    }
}
