use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{debug, error, info, warn};

use bn_manager::{
    BeaconError, BuilderConfig, BuilderEntry, BuilderPreferencesEntry, ProposerPreparation,
    SignedBuilderRequestAuth as WireSignedAuth, SignedValidatorRegistration,
    ValidatorRegistrationV1, FALLBACK_MAX_EXECUTION_PAYMENT, MAX_BUILDER_ENTRIES,
};
use eth_types::{
    BuilderRequestAuth, ForkName, ForkSchedule, ProposerPreferences, Root,
    SignedProposerPreferences, Slot, SLOTS_PER_EPOCH,
};
use signer::SignerError;
use validator_store::ValidatorStore;

use crate::traits::{BuilderBeaconClient, RegistrationSigner};

/// Fixed part of [`BuilderService::registration_step_timeout`].
const REGISTRATION_STEP_BASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether Gloas retired `prepare_beacon_proposer` / `register_validator`.
///
/// The only input is the resolved [`ForkName`]; BN status codes, features, and
/// env vars do not participate. Open-ended so a later fork keeps the retirement.
pub fn legacy_proposer_ops_retired(fork: ForkName) -> bool {
    fork >= ForkName::Gloas
}

/// One upcoming proposal slot to broadcast as [`ProposerPreferences`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpcomingProposal {
    pub pubkey: [u8; 48],
    pub validator_index: u64,
    pub proposal_slot: Slot,
    pub dependent_root: Root,
}

#[derive(Debug, Error)]
pub enum BuilderServiceError {
    #[error("beacon node error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("signer error: {0}")]
    SignerError(#[from] SignerError),

    #[error("{failed} of {total} builder registration batches failed")]
    RegistrationBatchesFailed { failed: usize, total: usize },

    #[error("{failed} of {total} builder registrations could not be signed")]
    RegistrationSigningFailed { failed: usize, total: usize },

    #[error("system clock is before the unix epoch")]
    ClockBeforeUnixEpoch,
}

/// A signed registration and the fee recipient and gas limit it was signed for.
///
/// Built only by [`Self::new`], so both fields equal `signed.message`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedRegistration {
    fee_recipient: [u8; 20],
    gas_limit: u64,
    signed: SignedValidatorRegistration,
}

impl CachedRegistration {
    fn new(signed: SignedValidatorRegistration) -> Self {
        Self {
            fee_recipient: signed.message.fee_recipient,
            gas_limit: signed.message.gas_limit,
            signed,
        }
    }

    fn signed_for(&self, fee_recipient: [u8; 20], gas_limit: u64) -> bool {
        self.fee_recipient == fee_recipient && self.gas_limit == gas_limit
    }
}

/// Failed and total batch counts of one [`BuilderService::send_batches`] call.
struct BatchReport {
    failed: usize,
    total: usize,
}

/// Last broadcast proposer preferences for a `(pubkey, slot)`.
///
/// Keyed without `dependent_root` so A→B→A misses on the stored root
/// instead of hitting a historical key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedPreference {
    fee_recipient: [u8; 20],
    gas_limit: u64,
    dependent_root: Root,
}

/// Signed per-builder auth reused at proposal time for byte-identical V4 `auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedBuilderPref {
    auth: WireSignedAuth,
    max_execution_payment: u64,
    /// A reorg must re-submit even when slot and URL are unchanged.
    dependent_root: Root,
}

type PreferenceCacheKey = ([u8; 48], Slot);
type BuilderPrefCacheKey = ([u8; 48], Slot, String);

pub struct BuilderService {
    signer: Arc<dyn RegistrationSigner>,
    bn: Arc<dyn BuilderBeaconClient>,
    validator_store: Arc<ValidatorStore>,
    genesis_fork_version: [u8; 4],
    fork_schedule: Arc<ForkSchedule>,
    cache: tokio::sync::RwLock<HashMap<[u8; 48], CachedRegistration>>,
    preference_cache: tokio::sync::RwLock<HashMap<PreferenceCacheKey, CachedPreference>>,
    builder_pref_cache: tokio::sync::RwLock<HashMap<BuilderPrefCacheKey, CachedBuilderPref>>,
    registration_batch_size: usize,
    registration_batch_delay_ms: u64,
}

impl BuilderService {
    pub fn new(
        signer: Arc<dyn RegistrationSigner>,
        bn: Arc<dyn BuilderBeaconClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
        fork_schedule: Arc<ForkSchedule>,
    ) -> Self {
        Self::with_batching(signer, bn, validator_store, genesis_fork_version, 0, 0, fork_schedule)
    }

    pub fn with_batching(
        signer: Arc<dyn RegistrationSigner>,
        bn: Arc<dyn BuilderBeaconClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
        registration_batch_size: usize,
        registration_batch_delay_ms: u64,
        fork_schedule: Arc<ForkSchedule>,
    ) -> Self {
        Self {
            signer,
            bn,
            validator_store,
            genesis_fork_version,
            fork_schedule,
            cache: tokio::sync::RwLock::new(HashMap::new()),
            preference_cache: tokio::sync::RwLock::new(HashMap::new()),
            builder_pref_cache: tokio::sync::RwLock::new(HashMap::new()),
            registration_batch_size,
            registration_batch_delay_ms,
        }
    }

    /// Duty fence for preferences and builder-request auth.
    ///
    /// Those messages carry `dependent_root` and `proposal_slot` from beacon
    /// duties. No admitted node skips the sign.
    fn preference_admission(&self) -> Option<signer::BeaconAdmission> {
        match self.bn.beacon_admission() {
            Ok(admission) if admission.holds() => Some(admission),
            _ => {
                warn!("skipping builder preference sign: beacon node admission revoked");
                None
            }
        }
    }

    /// Drop cached registrations so the next [`Self::register_validators`] re-submits.
    ///
    /// Preference caches are left intact. Used by boundary tests so a missing
    /// Gloas gate cannot hide behind `CachedRegistration`.
    pub async fn clear_cached_registrations(&self) {
        self.cache.write().await.clear();
    }

    /// Old path: signs and sends only new or changed keys; a cached key is never re-sent.
    ///
    /// Kept for the startup future and the slot-0 boundary until W4-E6a moves
    /// them to [`Self::submit_epoch_registrations`] and deletes this method.
    #[tracing::instrument(name = "builder.register", skip_all, fields(builder.batch_size, epoch = epoch))]
    pub async fn register_validators(&self, epoch: u64) -> Result<(), BuilderServiceError> {
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);
        if legacy_proposer_ops_retired(fork) {
            info!(epoch, fork = fork.as_ref(), "Skipping register_validators at Gloas");
            return Ok(());
        }
        let builder_pubkeys = self.builder_keys();

        if builder_pubkeys.is_empty() {
            debug!("no builder-enabled validators to register");
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        // Collect candidates that need (re-)registration by checking
        // the cache under a read lock, then release the lock before
        // performing any async signing.
        let candidates: Vec<([u8; 48], [u8; 20], u64)> = {
            let cache = self.cache.read().await;
            builder_pubkeys
                .iter()
                .filter_map(|pubkey| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pubkey);
                    let gas_limit = self.validator_store.effective_gas_limit(pubkey);
                    if cache.get(pubkey).is_some_and(|c| c.signed_for(fee_recipient, gas_limit)) {
                        None
                    } else {
                        Some((*pubkey, fee_recipient, gas_limit))
                    }
                })
                .collect()
        };

        let mut registrations = Vec::new();
        for &(pubkey, fee_recipient, gas_limit) in &candidates {
            let registration =
                ValidatorRegistrationV1 { fee_recipient, gas_limit, timestamp, pubkey };
            if let Some(signed) = self.sign_registration(registration).await {
                registrations.push(signed);
            }
        }

        if registrations.is_empty() {
            debug!("no new registrations to submit");
            return Ok(());
        }

        self.send_batches(&registrations).await;
        Ok(())
    }

    /// Re-send every builder key's registration; sign only keys that are new or changed.
    ///
    /// Entries for keys that left the builder set (enabled and
    /// `builder_proposals`) are evicted first. A key is signed when it has no
    /// entry or its fee recipient or gas limit changed, so a re-send keeps its
    /// signed timestamp. Each signature is cached before any send; a changed
    /// key whose re-sign fails loses its old entry. Every cached builder key is
    /// then sent in the configured batches, and every batch is tried. From
    /// Gloas on this is a no-op. W4-E6a's epoch-boundary step calls it.
    ///
    /// # Errors
    ///
    /// - [`BuilderServiceError::RegistrationBatchesFailed`] when any batch failed.
    /// - Otherwise [`BuilderServiceError::RegistrationSigningFailed`] when any
    ///   key was not signed; the signed keys are still sent.
    /// - [`BuilderServiceError::ClockBeforeUnixEpoch`] when a key needs signing
    ///   and the system clock reads before 1970.
    #[tracing::instrument(name = "builder.register", skip_all, fields(builder.batch_size, epoch = epoch))]
    pub async fn submit_epoch_registrations(&self, epoch: u64) -> Result<(), BuilderServiceError> {
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);
        if legacy_proposer_ops_retired(fork) {
            info!(epoch, fork = fork.as_ref(), "Skipping builder registrations at Gloas");
            return Ok(());
        }
        let builder_keys = self.builder_keys();

        let to_sign: Vec<([u8; 48], [u8; 20], u64)> = {
            let keep: HashSet<&[u8; 48]> = builder_keys.iter().collect();
            let mut cache = self.cache.write().await;
            cache.retain(|pubkey, _| keep.contains(pubkey));
            builder_keys
                .iter()
                .filter_map(|pubkey| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pubkey);
                    let gas_limit = self.validator_store.effective_gas_limit(pubkey);
                    let unchanged =
                        cache.get(pubkey).is_some_and(|c| c.signed_for(fee_recipient, gas_limit));
                    (!unchanged).then_some((*pubkey, fee_recipient, gas_limit))
                })
                .collect()
        };

        let mut signing_failures = 0;
        if !to_sign.is_empty() {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BuilderServiceError::ClockBeforeUnixEpoch)?
                .as_secs();
            for &(pubkey, fee_recipient, gas_limit) in &to_sign {
                let registration =
                    ValidatorRegistrationV1 { fee_recipient, gas_limit, timestamp, pubkey };
                let signed = self.sign_registration(registration).await;
                let mut cache = self.cache.write().await;
                match signed {
                    Some(signed) => {
                        cache.insert(pubkey, CachedRegistration::new(signed));
                    }
                    None => {
                        cache.remove(&pubkey);
                        signing_failures += 1;
                    }
                }
            }
        }

        let registrations: Vec<SignedValidatorRegistration> = {
            let cache = self.cache.read().await;
            builder_keys
                .iter()
                .filter_map(|pubkey| cache.get(pubkey))
                .map(|c| c.signed.clone())
                .collect()
        };
        let report = self.send_batches(&registrations).await;

        if report.failed > 0 {
            return Err(BuilderServiceError::RegistrationBatchesFailed {
                failed: report.failed,
                total: report.total,
            });
        }
        if signing_failures > 0 {
            return Err(BuilderServiceError::RegistrationSigningFailed {
                failed: signing_failures,
                total: to_sign.len(),
            });
        }
        Ok(())
    }

    /// Time budget for one [`Self::submit_epoch_registrations`] round.
    ///
    /// 10 s plus one batch delay for each batch after the first, where
    /// `batches = ceil(builder keys / batch size)`. A batch size of 0 and an
    /// empty builder set each count as one batch. Saturates instead of overflowing.
    pub fn registration_step_timeout(&self) -> Duration {
        let batches = match self.registration_batch_size {
            0 => 1,
            size => self.builder_keys().len().div_ceil(size).max(1),
        };
        let extra_delays = u64::try_from(batches - 1).unwrap_or(u64::MAX);
        REGISTRATION_STEP_BASE_TIMEOUT.saturating_add(Duration::from_millis(
            self.registration_batch_delay_ms.saturating_mul(extra_delays),
        ))
    }

    /// Enabled keys with `builder_proposals`.
    fn builder_keys(&self) -> Vec<[u8; 48]> {
        self.validator_store
            .list_enabled_pubkeys()
            .into_iter()
            .filter(|pk| self.validator_store.is_builder_enabled(pk))
            .collect()
    }

    /// Sign `registration`; `None` (an invalid pubkey or a signer error) is logged.
    async fn sign_registration(
        &self,
        registration: ValidatorRegistrationV1,
    ) -> Option<SignedValidatorRegistration> {
        let pubkey = registration.pubkey;
        let pk = match crypto::PublicKey::from_bytes(&pubkey) {
            Ok(pk) => pk,
            Err(e) => {
                warn!(pubkey = hex::encode(pubkey), error = %e, "skipping invalid pubkey");
                return None;
            }
        };

        // Fee recipient, gas limit, timestamp, and pubkey are local
        // config under the configured genesis fork version, not a
        // beacon-node body. The scope is `BeaconAdmission::unbound`.
        // A missing scope still fails closed.
        match signer::with_beacon_admission(
            signer::BeaconAdmission::unbound(),
            self.signer.sign_builder_registration(&registration, &pk, self.genesis_fork_version),
        )
        .await
        {
            // Wire boundary: eth_types::Signature is Vec<u8> for JSON serde.
            Ok(signature) => Some(SignedValidatorRegistration {
                message: registration,
                signature: signature.to_bytes().to_vec(),
            }),
            Err(e) => {
                error!(
                    pubkey = hex::encode(pubkey),
                    error = %e,
                    "failed to sign builder registration"
                );
                None
            }
        }
    }

    /// POST `registrations` in the configured batches, trying every batch.
    ///
    /// Each accepted batch is cached as soon as it lands, so a round cut by a
    /// caller's timeout keeps the batches it sent.
    async fn send_batches(&self, registrations: &[SignedValidatorRegistration]) -> BatchReport {
        if registrations.is_empty() {
            return BatchReport { failed: 0, total: 0 };
        }
        let total_count = registrations.len();
        tracing::Span::current().record("builder.batch_size", total_count);

        // Batch size 0 means send all at once (legacy behavior)
        let effective_batch_size = if self.registration_batch_size == 0 {
            total_count
        } else {
            self.registration_batch_size
        };

        let mut successful = 0;
        let mut batch_failures = 0;
        let chunks: Vec<&[SignedValidatorRegistration]> =
            registrations.chunks(effective_batch_size).collect();
        let num_batches = chunks.len();

        debug!(
            total_count = total_count,
            batch_size = effective_batch_size,
            num_batches = num_batches,
            "submitting builder registrations in batches"
        );

        for (i, chunk) in chunks.into_iter().enumerate() {
            if i > 0 && self.registration_batch_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.registration_batch_delay_ms)).await;
            }

            let start = Instant::now();
            match self.bn.register_validators(chunk).await {
                Ok(()) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    debug!(
                        batch = i + 1,
                        of = num_batches,
                        size = chunk.len(),
                        duration_ms = duration_ms,
                        "registration batch sent"
                    );
                    successful += chunk.len();
                    let mut cache = self.cache.write().await;
                    for reg in chunk {
                        cache.insert(reg.message.pubkey, CachedRegistration::new(reg.clone()));
                    }
                }
                Err(e) => {
                    batch_failures += 1;
                    warn!(
                        batch = i + 1,
                        of = num_batches,
                        size = chunk.len(),
                        error = %e,
                        "registration batch failed, continuing with remaining batches"
                    );
                    // Don't abort — continue with remaining batches
                }
            }
        }

        info!(
            total = total_count,
            successful = successful,
            batch_failures = batch_failures,
            "registration batching complete"
        );

        BatchReport { failed: batch_failures, total: num_batches }
    }

    #[tracing::instrument(name = "builder.prepare_proposers", skip_all, fields(epoch = epoch))]
    pub async fn prepare_proposers(
        &self,
        epoch: u64,
        validator_indices: &HashMap<[u8; 48], u64>,
    ) -> Result<(), BuilderServiceError> {
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);
        if legacy_proposer_ops_retired(fork) {
            info!(epoch, fork = fork.as_ref(), "Skipping prepare_beacon_proposer at Gloas");
            return Ok(());
        }

        let enabled_pubkeys = self.validator_store.list_enabled_pubkeys();

        let preparations: Vec<ProposerPreparation> = enabled_pubkeys
            .iter()
            .filter_map(|pk| {
                validator_indices.get(pk).map(|index| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pk);
                    ProposerPreparation {
                        validator_index: index.to_string(),
                        fee_recipient: format!("0x{}", hex::encode(fee_recipient)),
                    }
                })
            })
            .collect();

        if preparations.is_empty() {
            debug!("no proposer preparations to submit");
            return Ok(());
        }

        let count = preparations.len();
        debug!(count = count, "submitting proposer preparations");
        match self.bn.prepare_beacon_proposer(&preparations).await {
            Ok(()) => {
                info!(count = count, "proposer preparation sent");
            }
            Err(e) => {
                warn!(error = %e, "proposer preparation failure");
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// Sign and submit one [`SignedProposerPreferences`] per Gloas+ proposal
    /// slot. Gated on each slot's fork, so Gloas-1 can advertise Gloas slots.
    #[tracing::instrument(
        name = "builder.broadcast_proposer_preferences",
        skip_all,
        fields(epoch = epoch)
    )]
    pub async fn broadcast_proposer_preferences(
        &self,
        epoch: u64,
        proposals: &[UpcomingProposal],
        genesis_validators_root: &Root,
    ) -> Result<(), BuilderServiceError> {
        let candidates: Vec<UpcomingProposal> = {
            let cache = self.preference_cache.read().await;
            proposals
                .iter()
                .filter(|p| {
                    let slot_fork = ForkName::from_epoch(
                        p.proposal_slot / SLOTS_PER_EPOCH,
                        &self.fork_schedule,
                    );
                    legacy_proposer_ops_retired(slot_fork)
                })
                .filter(|p| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(&p.pubkey);
                    let gas_limit = self.validator_store.effective_gas_limit(&p.pubkey);
                    let cached = CachedPreference {
                        fee_recipient,
                        gas_limit,
                        dependent_root: p.dependent_root,
                    };
                    cache.get(&(p.pubkey, p.proposal_slot)) != Some(&cached)
                })
                .cloned()
                .collect()
        };

        if candidates.is_empty() {
            debug!(epoch, "no proposer preferences to broadcast");
            return Ok(());
        }

        let mut signed = Vec::new();
        let mut signed_keys = Vec::new();
        for proposal in &candidates {
            let Some(admission) = self.preference_admission() else {
                continue;
            };
            let fee_recipient = self.validator_store.effective_fee_recipient(&proposal.pubkey);
            let gas_limit = self.validator_store.effective_gas_limit(&proposal.pubkey);
            let prefs = ProposerPreferences {
                dependent_root: proposal.dependent_root,
                proposal_slot: proposal.proposal_slot,
                validator_index: proposal.validator_index,
                fee_recipient,
                target_gas_limit: gas_limit,
            };
            let pk = match crypto::PublicKey::from_bytes(&proposal.pubkey) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(
                        pubkey = hex::encode(proposal.pubkey),
                        error = %e,
                        "skipping invalid pubkey"
                    );
                    continue;
                }
            };
            match signer::with_beacon_admission(
                admission,
                self.signer.sign_proposer_preferences(
                    &prefs,
                    &pk,
                    &self.fork_schedule,
                    genesis_validators_root,
                ),
            )
            .await
            {
                Ok(signature) => {
                    signed.push(SignedProposerPreferences {
                        message: prefs,
                        signature: signature.to_bytes().to_vec(),
                    });
                    signed_keys.push((
                        proposal.pubkey,
                        proposal.proposal_slot,
                        CachedPreference {
                            fee_recipient,
                            gas_limit,
                            dependent_root: proposal.dependent_root,
                        },
                    ));
                }
                Err(e) => {
                    error!(
                        pubkey = hex::encode(proposal.pubkey),
                        error = %e,
                        "failed to sign proposer preferences"
                    );
                }
            }
        }

        if signed.is_empty() {
            debug!("no signed proposer preferences to submit");
            return Ok(());
        }

        let count = signed.len();
        match self.bn.submit_proposer_preferences(&signed).await {
            Ok(()) => {
                info!(count, epoch, "proposer preferences broadcast");
                let mut cache = self.preference_cache.write().await;
                for (pubkey, slot, cached) in signed_keys {
                    cache.insert((pubkey, slot), cached);
                }
                cache.retain(|(_, slot), _| *slot / SLOTS_PER_EPOCH >= epoch);
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "proposer preferences broadcast failure");
                Err(e.into())
            }
        }
    }

    /// Sign and submit one [`BuilderPreferencesEntry`] per (proposer, builder)
    /// for each Gloas+ proposal slot on the 6.10 schedule.
    ///
    /// Lookup is `(pubkey, slot, url)` so proposal-time `auth` reuse is unchanged.
    /// A `dependent_root`-only change re-submits the cached auth without
    /// re-signing: `BuilderRequestAuth` is `{data, slot}` and does not include
    /// the root. A slot or URL change is a cache miss and re-signs.
    #[tracing::instrument(
        name = "builder.broadcast_builder_preferences",
        skip_all,
        fields(epoch = epoch)
    )]
    pub async fn broadcast_builder_preferences(
        &self,
        epoch: u64,
        proposals: &[UpcomingProposal],
    ) -> Result<(), BuilderServiceError> {
        let gloas: Vec<&UpcomingProposal> = proposals
            .iter()
            .filter(|p| {
                let slot_fork =
                    ForkName::from_epoch(p.proposal_slot / SLOTS_PER_EPOCH, &self.fork_schedule);
                legacy_proposer_ops_retired(slot_fork)
            })
            .collect();

        if gloas.is_empty() {
            debug!(epoch, "no builder preferences to broadcast");
            return Ok(());
        }

        let mut entries = Vec::new();
        let mut signed_keys = Vec::new();
        let mut to_sign = Vec::new();
        {
            let cache = self.builder_pref_cache.read().await;
            for p in gloas {
                for url in capped_unique_builder_urls(self.validator_store.builders(&p.pubkey)) {
                    match cache.get(&(p.pubkey, p.proposal_slot, url.clone())) {
                        Some(cached) if cached.dependent_root == p.dependent_root => {}
                        Some(cached) => {
                            entries.push(BuilderPreferencesEntry {
                                proposer_pubkey: format!("0x{}", hex::encode(p.pubkey)),
                                url: url.clone(),
                                auth: cached.auth.clone(),
                                max_execution_payment: cached.max_execution_payment,
                            });
                            signed_keys.push((
                                p.pubkey,
                                p.proposal_slot,
                                url,
                                CachedBuilderPref {
                                    dependent_root: p.dependent_root,
                                    ..cached.clone()
                                },
                            ));
                        }
                        None => to_sign.push((p.clone(), url)),
                    }
                }
            }
        }

        for (proposal, url) in &to_sign {
            let Some(admission) = self.preference_admission() else {
                continue;
            };
            // No out-of-band override is configured; default to URL UTF-8 bytes.
            let auth =
                match BuilderRequestAuth::new(url.as_bytes().to_vec(), proposal.proposal_slot) {
                    Ok(auth) => auth,
                    Err(e) => {
                        warn!(
                            pubkey = hex::encode(proposal.pubkey),
                            url = %url,
                            error = %e,
                            "skipping invalid builder request auth data"
                        );
                        continue;
                    }
                };
            let pk = match crypto::PublicKey::from_bytes(&proposal.pubkey) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(
                        pubkey = hex::encode(proposal.pubkey),
                        error = %e,
                        "skipping invalid pubkey"
                    );
                    continue;
                }
            };
            match signer::with_beacon_admission(
                admission,
                self.signer.sign_builder_request_auth(&auth, &pk, self.genesis_fork_version),
            )
            .await
            {
                Ok(signature) => {
                    let signed = eth_types::SignedBuilderRequestAuth {
                        message: auth,
                        signature: signature.to_bytes().to_vec(),
                    };
                    let wire_auth = WireSignedAuth::from_signed(&signed);
                    entries.push(BuilderPreferencesEntry {
                        proposer_pubkey: format!("0x{}", hex::encode(proposal.pubkey)),
                        url: url.clone(),
                        auth: wire_auth.clone(),
                        max_execution_payment: FALLBACK_MAX_EXECUTION_PAYMENT,
                    });
                    signed_keys.push((
                        proposal.pubkey,
                        proposal.proposal_slot,
                        url.clone(),
                        CachedBuilderPref {
                            auth: wire_auth,
                            max_execution_payment: FALLBACK_MAX_EXECUTION_PAYMENT,
                            dependent_root: proposal.dependent_root,
                        },
                    ));
                }
                Err(e) => {
                    error!(
                        pubkey = hex::encode(proposal.pubkey),
                        url = %url,
                        error = %e,
                        "failed to sign builder request auth"
                    );
                }
            }
        }

        if entries.is_empty() {
            debug!("no signed builder preferences to submit");
            return Ok(());
        }

        let count = entries.len();
        match self.bn.submit_builder_preferences(&entries).await {
            Ok(result) => {
                let failed: HashSet<u32> = result.failures().iter().map(|f| f.index).collect();
                if !failed.is_empty() {
                    for f in result.failures() {
                        let url = entries
                            .get(f.index as usize)
                            .map(|e| e.url.as_str())
                            .unwrap_or("<missing>");
                        warn!(
                            index = f.index,
                            url,
                            message = %f.message,
                            "builder preference entry rejected"
                        );
                    }
                }
                let kept: Vec<_> = signed_keys
                    .into_iter()
                    .enumerate()
                    .filter_map(
                        |(i, key)| {
                            if failed.contains(&(i as u32)) {
                                None
                            } else {
                                Some(key)
                            }
                        },
                    )
                    .collect();
                info!(count, kept = kept.len(), epoch, "builder preferences broadcast");
                self.write_builder_pref_cache(epoch, kept).await;
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "builder preferences broadcast failure");
                Err(e.into())
            }
        }
    }

    async fn write_builder_pref_cache(
        &self,
        epoch: u64,
        keys: Vec<([u8; 48], Slot, String, CachedBuilderPref)>,
    ) {
        let mut cache = self.builder_pref_cache.write().await;
        for (pubkey, slot, url, cached) in keys {
            cache.insert((pubkey, slot, url), cached);
        }
        cache.retain(|(_, slot, _), _| *slot / SLOTS_PER_EPOCH >= epoch);
    }

    /// Cached signed auths for a proposer/slot so 6.5 can reuse byte-identical `auth`.
    pub async fn cached_builder_entries(&self, pubkey: &[u8; 48], slot: Slot) -> Vec<BuilderEntry> {
        let cache = self.builder_pref_cache.read().await;
        capped_unique_builder_urls(self.validator_store.builders(pubkey))
            .into_iter()
            .filter_map(|url| {
                let cached = cache.get(&(*pubkey, slot, url.clone()))?;
                Some(BuilderEntry {
                    url,
                    auth: cached.auth.clone(),
                    builder_pubkeys: Vec::new(),
                    max_execution_payment: cached.max_execution_payment,
                    min_bid: self.validator_store.min_bid(pubkey),
                    builder_boost_factor: self.validator_store.builder_boost_factor(pubkey),
                })
            })
            .collect()
    }

    /// V4 body for `pubkey` at `slot` using the same signed auths as preferences submit.
    pub async fn builder_config_for(&self, pubkey: &[u8; 48], slot: Slot) -> BuilderConfig {
        BuilderConfig {
            min_bid: self.validator_store.min_bid(pubkey),
            builder_boost_factor: self.validator_store.builder_boost_factor(pubkey),
            builders: self.cached_builder_entries(pubkey, slot).await,
        }
    }

    pub fn jitter_seconds() -> u64 {
        use rand::Rng;
        rand::thread_rng().gen_range(0..30)
    }
}

fn capped_unique_builder_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut dropped = 0usize;
    for url in urls {
        if !seen.insert(url.clone()) {
            continue;
        }
        if out.len() >= MAX_BUILDER_ENTRIES {
            dropped += 1;
            continue;
        }
        out.push(url);
    }
    if dropped > 0 {
        warn!(
            dropped,
            cap = MAX_BUILDER_ENTRIES,
            "capping builder URL list at MAX_BUILDER_ENTRIES"
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    use async_trait::async_trait;
    use crypto::PublicKey;
    use eth_types::{BuilderRequestAuth, ProposerPreferences, ValidatorRegistrationV1};
    use signer::ValidatorSigner;
    use validator_store::ValidatorConfig;

    use bn_manager::SubmitBuilderPreferencesResult;

    const PRE_GLOAS_EPOCH: u64 = 0;
    const GENESIS_FORK: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    const TEST_GVR: Root = [0xaau8; 32];

    fn unscheduled() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule::unscheduled_gloas())
    }

    fn gloas_at(epoch: u64) -> Arc<ForkSchedule> {
        let mut schedule = ForkSchedule::unscheduled_gloas();
        schedule.gloas_fork_epoch = epoch;
        Arc::new(schedule)
    }

    // --- Narrow mock BN ---

    struct MockBn {
        register_calls: Mutex<Vec<Vec<SignedValidatorRegistration>>>,
        prepare_calls: Mutex<Vec<Vec<ProposerPreparation>>>,
        preference_calls: Mutex<Vec<Vec<SignedProposerPreferences>>>,
        builder_pref_calls: Mutex<Vec<Vec<BuilderPreferencesEntry>>>,
        fail_register: bool,
        fail_prepare: bool,
        fail_preferences: bool,
        /// Fail only on these 0-based call indices (e.g. [1] fails the second call).
        fail_register_on_calls: Vec<usize>,
        indexed_fail_on: Option<Vec<bn_manager::IndexedFailure>>,
    }

    impl MockBn {
        fn new() -> Self {
            Self {
                register_calls: Mutex::new(Vec::new()),
                prepare_calls: Mutex::new(Vec::new()),
                preference_calls: Mutex::new(Vec::new()),
                builder_pref_calls: Mutex::new(Vec::new()),
                fail_register: false,
                fail_prepare: false,
                fail_preferences: false,
                fail_register_on_calls: Vec::new(),
                indexed_fail_on: None,
            }
        }

        fn with_register_error(mut self) -> Self {
            self.fail_register = true;
            self
        }

        fn with_prepare_error(mut self) -> Self {
            self.fail_prepare = true;
            self
        }

        fn with_register_error_on_calls(mut self, indices: Vec<usize>) -> Self {
            self.fail_register_on_calls = indices;
            self
        }

        fn with_indexed_failures(mut self, failures: Vec<bn_manager::IndexedFailure>) -> Self {
            self.indexed_fail_on = Some(failures);
            self
        }
    }

    #[async_trait]
    impl BuilderBeaconClient for MockBn {
        async fn prepare_beacon_proposer(
            &self,
            preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError> {
            self.prepare_calls.lock().push(preparations.to_vec());
            if self.fail_prepare {
                return Err(BeaconError::HttpError("mock prepare failure".into()));
            }
            Ok(())
        }

        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            let call_idx = self.register_calls.lock().len();
            if self.fail_register || self.fail_register_on_calls.contains(&call_idx) {
                // Still record the call so we can count it
                self.register_calls.lock().push(registrations.to_vec());
                return Err(BeaconError::HttpError("mock register failure".into()));
            }
            self.register_calls.lock().push(registrations.to_vec());
            Ok(())
        }

        async fn submit_proposer_preferences(
            &self,
            preferences: &[SignedProposerPreferences],
        ) -> Result<(), BeaconError> {
            if self.fail_preferences {
                self.preference_calls.lock().push(preferences.to_vec());
                return Err(BeaconError::HttpError("mock preferences failure".into()));
            }
            self.preference_calls.lock().push(preferences.to_vec());
            Ok(())
        }

        async fn submit_builder_preferences(
            &self,
            entries: &[BuilderPreferencesEntry],
        ) -> Result<SubmitBuilderPreferencesResult, BeaconError> {
            self.builder_pref_calls.lock().push(entries.to_vec());
            if let Some(failures) = &self.indexed_fail_on {
                return Ok(SubmitBuilderPreferencesResult::PartialFailure {
                    failures: failures.clone(),
                });
            }
            Ok(SubmitBuilderPreferencesResult::Success)
        }

        fn beacon_admission(&self) -> Result<signer::BeaconAdmission, BeaconError> {
            Ok(signer::BeaconAdmission::unbound())
        }
    }

    // --- Narrow mock signer ---

    struct MockSigner {
        fail_sign: bool,
        /// Builder registrations for these keys fail until [`Self::heal`].
        fail_for: Mutex<HashSet<[u8; 48]>>,
        sign_calls: Mutex<Vec<[u8; 48]>>,
        /// Fixed valid BLS signature for wire-boundary assertions.
        sig: crypto::Signature,
        auth_sk: Option<crypto::SecretKey>,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                fail_sign: false,
                fail_for: Mutex::new(HashSet::new()),
                sign_calls: Mutex::new(Vec::new()),
                sig: crypto::SecretKey::generate().sign(b"mock-builder-reg"),
                auth_sk: None,
            }
        }

        fn with_sign_error(mut self) -> Self {
            self.fail_sign = true;
            self
        }

        fn with_sign_error_for(self, pubkey: [u8; 48]) -> Self {
            self.fail_for.lock().insert(pubkey);
            self
        }

        fn heal(&self) {
            self.fail_for.lock().clear();
        }

        fn with_auth_key(mut self, sk: crypto::SecretKey) -> Self {
            self.auth_sk = Some(sk);
            self
        }

        fn signature_bytes(&self) -> Vec<u8> {
            self.sig.to_bytes().to_vec()
        }
    }

    #[async_trait]
    impl RegistrationSigner for MockSigner {
        async fn sign_builder_registration(
            &self,
            _registration: &ValidatorRegistrationV1,
            pubkey: &PublicKey,
            _fork_version: [u8; 4],
        ) -> Result<crypto::Signature, SignerError> {
            if self.fail_sign || self.fail_for.lock().contains(&pubkey.to_bytes()) {
                return Err(SignerError::KeyNotFound("mock sign failure".into()));
            }
            self.sign_calls.lock().push(pubkey.to_bytes());
            Ok(self.sig.clone())
        }

        async fn sign_proposer_preferences(
            &self,
            _prefs: &ProposerPreferences,
            pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<crypto::Signature, SignerError> {
            if self.fail_sign {
                return Err(SignerError::KeyNotFound("mock sign failure".into()));
            }
            self.sign_calls.lock().push(pubkey.to_bytes());
            Ok(self.sig.clone())
        }

        async fn sign_builder_request_auth(
            &self,
            auth: &BuilderRequestAuth,
            pubkey: &PublicKey,
            genesis_fork_version: [u8; 4],
        ) -> Result<crypto::Signature, SignerError> {
            if self.fail_sign {
                return Err(SignerError::KeyNotFound("mock sign failure".into()));
            }
            self.sign_calls.lock().push(pubkey.to_bytes());
            if let Some(sk) = &self.auth_sk {
                let root = crypto::signing_root_with_fork_version(
                    auth,
                    eth_types::DOMAIN_BUILDER_REQUEST_AUTH,
                    genesis_fork_version,
                    [0u8; 32],
                );
                return Ok(sk.sign(&root));
            }
            Ok(self.sig.clone())
        }
    }

    // --- Helpers ---

    fn gen_pubkey_bytes() -> [u8; 48] {
        let sk = crypto::SecretKey::generate();
        sk.public_key().to_bytes()
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    type ValidatorEntry = ([u8; 48], bool, Option<[u8; 20]>, Option<u64>);

    fn test_store_with_builder_validators(validators: &[ValidatorEntry]) -> ValidatorStore {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        for (pk, builder_enabled, fee_recipient, gas_limit) in validators {
            let mut config = ValidatorConfig::new(*pk);
            config.builder_proposals = *builder_enabled;
            config.fee_recipient = *fee_recipient;
            config.gas_limit = *gas_limit;
            store.add_validator(config).unwrap();
        }
        store
    }

    fn build_service(signer: MockSigner, bn: MockBn, store: ValidatorStore) -> BuilderService {
        BuilderService::new(
            Arc::new(signer),
            Arc::new(bn),
            Arc::new(store),
            GENESIS_FORK,
            unscheduled(),
        )
    }

    fn build_service_with_batching(
        signer: Arc<MockSigner>,
        bn: Arc<MockBn>,
        store: Arc<ValidatorStore>,
        batch_size: usize,
        batch_delay_ms: u64,
    ) -> BuilderService {
        BuilderService::with_batching(
            signer,
            bn,
            store,
            GENESIS_FORK,
            batch_size,
            batch_delay_ms,
            unscheduled(),
        )
    }

    /// RED→GREEN: BuilderService compiles against a four-method BN stub +
    /// three-method registration signer (no BeaconNodeClient / ValidatorSigner).
    #[tokio::test]
    async fn test_builder_service_compiles_against_two_method_stub() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        let mut indices = HashMap::new();
        indices.insert(pk, 1u64);
        service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await.unwrap();
        assert_eq!(bn.prepare_calls.lock().len(), 1);
    }

    // --- register_validators tests ---

    #[tokio::test]
    async fn test_register_validators_no_builder_enabled() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);
        let bn = Arc::new(MockBn::new());
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            unscheduled(),
        );

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_empty_store() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = build_service(MockSigner::new(), MockBn::new(), store);

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_validators_submits_for_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(fr), Some(35_000_000)),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            unscheduled(),
        );

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].message.pubkey, pk1);
        assert_eq!(calls[0][0].message.fee_recipient, fr);
        assert_eq!(calls[0][0].message.gas_limit, 35_000_000);
        assert_eq!(calls[0][0].signature, signer.signature_bytes());

        let sign_calls = signer.sign_calls.lock();
        assert_eq!(sign_calls.len(), 1);
    }

    #[tokio::test]
    async fn test_register_validators_uses_default_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 25_000_000);
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls[0][0].message.fee_recipient, default_fr);
        assert_eq!(calls[0][0].message.gas_limit, 25_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_multiple_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let pk3 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(test_fee_recipient(1)), Some(30_000_000)),
            (pk2, true, Some(test_fee_recipient(2)), Some(31_000_000)),
            (pk3, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let pubkeys: Vec<[u8; 48]> = calls[0].iter().map(|r| r.message.pubkey).collect();
        assert!(pubkeys.contains(&pk1));
        assert!(pubkeys.contains(&pk2));
        assert!(!pubkeys.contains(&pk3));
    }

    /// Old-path guard until W4-E6a: a failed batch still returns `Ok` and caches nothing.
    #[tokio::test]
    async fn test_register_validators_beacon_error_continues() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new().with_register_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), GENESIS_FORK, unscheduled());

        // With batching, failed batches are logged but don't abort — returns Ok
        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        // Cache should not be updated for failed registrations
        let cache = service.cache.read().await;
        assert!(cache.is_empty());
    }

    /// Old-path guard until W4-E6a: every signature failing still returns `Ok`, no POST.
    #[tokio::test]
    async fn test_register_validators_sign_error_skips_validator() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store =
            test_store_with_builder_validators(&[(pk1, true, None, None), (pk2, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new().with_sign_error());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        // No registrations submitted since signing failed
        let calls = bn.register_calls.lock();
        assert!(calls.is_empty());
    }

    /// Old-path guard until W4-E6a: an unchanged cached key is not re-sent.
    #[tokio::test]
    async fn test_register_validators_caches_and_skips_unchanged() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[(pk, true, Some(fr), Some(35_000_000))]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        // First call should register
        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Second call should skip (cached)
        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1); // Still 1, no new call
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_fee_recipient_change() {
        let pk = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0xab);
        let fr2 = test_fee_recipient(0xcd);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr1);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), GENESIS_FORK, unscheduled());

        // First registration
        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change fee_recipient
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    fee_recipient: Some(Some(fr2)),
                    ..Default::default()
                },
            )
            .unwrap();

        // Should re-register
        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.fee_recipient, fr2);
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_gas_limit_change() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), GENESIS_FORK, unscheduled());

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change gas_limit
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    gas_limit: Some(Some(50_000_000)),
                    ..Default::default()
                },
            )
            .unwrap();

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.gas_limit, 50_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_timestamp_is_reasonable() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let calls = bn.register_calls.lock();
        let timestamp = calls[0][0].message.timestamp;
        assert!(timestamp >= before);
        assert!(timestamp <= after);
    }

    // --- prepare_proposers tests ---

    #[tokio::test]
    async fn test_prepare_proposers_submits_for_all_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0x01);
        let fr2 = test_fee_recipient(0x02);
        let store = test_store_with_builder_validators(&[
            (pk1, false, Some(fr1), None),
            (pk2, false, Some(fr2), None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);
        indices.insert(pk2, 200u64);

        let result = service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await;
        assert!(result.is_ok());

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let preps = &calls[0];
        let indices_submitted: Vec<&str> =
            preps.iter().map(|p| p.validator_index.as_str()).collect();
        assert!(indices_submitted.contains(&"100"));
        assert!(indices_submitted.contains(&"200"));
    }

    #[tokio::test]
    async fn test_prepare_proposers_uses_effective_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let mut indices = HashMap::new();
        indices.insert(pk, 42u64);

        service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        let expected_fr = format!("0x{}", hex::encode(default_fr));
        assert_eq!(calls[0][0].fee_recipient, expected_fr);
        assert_eq!(calls[0][0].validator_index, "42");
    }

    #[tokio::test]
    async fn test_prepare_proposers_skips_unknown_indices() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, false, None, None),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        // Only provide index for pk1
        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);

        service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].validator_index, "100");
    }

    #[tokio::test]
    async fn test_prepare_proposers_empty_indices() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());

        let indices = HashMap::new();
        service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_prepare_proposers_beacon_error_propagates() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new().with_prepare_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), GENESIS_FORK, unscheduled());

        let mut indices = HashMap::new();
        indices.insert(pk, 100u64);

        let result = service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("beacon node error"));
    }

    // --- jitter tests ---

    #[test]
    fn test_jitter_is_in_range() {
        for _ in 0..100 {
            let jitter = BuilderService::jitter_seconds();
            assert!(jitter < 30);
        }
    }

    // --- Error display tests ---

    #[test]
    fn test_builder_service_error_display_beacon() {
        let err = BuilderServiceError::BeaconError(BeaconError::HttpError("test".into()));
        assert!(err.to_string().contains("beacon node error"));
    }

    #[test]
    fn test_builder_service_error_display_signer() {
        let err = BuilderServiceError::SignerError(SignerError::KeyNotFound("test".into()));
        assert!(err.to_string().contains("signer error"));
    }

    // --- Construction test ---

    #[test]
    fn test_builder_service_new() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let _service = BuilderService::new(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
            unscheduled(),
        );
    }

    // --- Batching tests ---

    #[tokio::test]
    async fn test_batching_splits_into_correct_batch_count() {
        // 5 validators with batch_size=2 should produce 3 batches (2+2+1)
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 2, 0);

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].len(), 2);
        assert_eq!(calls[1].len(), 2);
        assert_eq!(calls[2].len(), 1);
    }

    #[tokio::test]
    async fn test_batching_zero_sends_all_at_once() {
        // batch_size=0 (legacy) should submit all in a single call
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 0, 0);

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 5);
    }

    /// Old-path guard until W4-E6a: a failed batch still returns `Ok`; only accepted batches are cached.
    #[tokio::test]
    async fn test_batching_partial_failure_continues_remaining() {
        // Fail batch index 1 (second batch). Batches 0 and 2 should succeed.
        let pks: Vec<[u8; 48]> = (0..5).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));

        let bn = Arc::new(MockBn::new().with_register_error_on_calls(vec![1]));
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 2, 0);

        let result = service.register_validators(PRE_GLOAS_EPOCH).await;
        assert!(result.is_ok());

        // All 3 batches should have been attempted
        {
            let calls = bn.register_calls.lock();
            assert_eq!(calls.len(), 3);
        }

        // Cache should only contain validators from successful batches (0 and 2)
        let cache = service.cache.read().await;
        assert_eq!(cache.len(), 3); // 2 from batch 0 + 1 from batch 2
    }

    #[tokio::test]
    async fn test_batching_with_batching_constructor() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = BuilderService::with_batching(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
            100,
            50,
            unscheduled(),
        );
        assert_eq!(service.registration_batch_size, 100);
        assert_eq!(service.registration_batch_delay_ms, 50);
    }

    #[tokio::test]
    async fn test_batching_delay_between_batches() {
        // Relocated from bin/rvc tier-4 registration_batching (unique timing cover).
        let pks: Vec<[u8; 48]> = (0..20).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> =
            pks.iter().map(|pk| (*pk, true, None, None)).collect();
        let store = Arc::new(test_store_with_builder_validators(&validators));
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer, bn.clone(), store, 10, 50);

        let start = std::time::Instant::now();
        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        let elapsed = start.elapsed();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2, "20 validators / 10 batch = 2 requests");
        assert!(
            elapsed >= std::time::Duration::from_millis(40),
            "should have delay between batches, elapsed: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_batching_new_defaults_to_zero() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
            unscheduled(),
        );
        assert_eq!(service.registration_batch_size, 0);
        assert_eq!(service.registration_batch_delay_ms, 0);
    }

    // --- submit_epoch_registrations (W4-E5) ---

    fn builder_keys_store(n: usize) -> (Vec<[u8; 48]>, Arc<ValidatorStore>) {
        let pks: Vec<[u8; 48]> = (0..n).map(|_| gen_pubkey_bytes()).collect();
        let validators: Vec<ValidatorEntry> = pks
            .iter()
            .map(|pk| (*pk, true, Some(test_fee_recipient(0xab)), Some(30_000_000)))
            .collect();
        (pks, Arc::new(test_store_with_builder_validators(&validators)))
    }

    fn by_key(
        call: &[SignedValidatorRegistration],
    ) -> HashMap<[u8; 48], SignedValidatorRegistration> {
        call.iter().map(|r| (r.message.pubkey, r.clone())).collect()
    }

    fn sent_keys(call: &[SignedValidatorRegistration]) -> HashSet<[u8; 48]> {
        call.iter().map(|r| r.message.pubkey).collect()
    }

    fn key_set(pks: &[[u8; 48]]) -> HashSet<[u8; 48]> {
        pks.iter().copied().collect()
    }

    fn signatures_for(signer: &MockSigner, pk: &[u8; 48]) -> usize {
        signer.sign_calls.lock().iter().filter(|signed| *signed == pk).count()
    }

    async fn cached_keys(service: &BuilderService) -> HashSet<[u8; 48]> {
        service.cache.read().await.keys().copied().collect()
    }

    fn update(
        store: &ValidatorStore,
        pk: &[u8; 48],
        update: validator_store::ValidatorConfigUpdate,
    ) {
        store.update_config(pk, update).unwrap();
    }

    fn builder_flag(on: bool) -> validator_store::ValidatorConfigUpdate {
        validator_store::ValidatorConfigUpdate { builder_proposals: Some(on), ..Default::default() }
    }

    /// 654-AC2: no re-sign on an unchanged key; a fee or gas change re-signs only that key.
    #[tokio::test]
    async fn test_register_validators_resends_cached_without_resigning() {
        let (pks, store) = builder_keys_store(3);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store.clone(), 0, 0);

        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        {
            let calls = bn.register_calls.lock();
            assert_eq!(calls.len(), 2, "one POST per call");
            assert_eq!(sent_keys(&calls[0]), key_set(&pks));
            assert_eq!(by_key(&calls[1]), by_key(&calls[0]), "the second POST re-sends the first");
        }
        for pk in &pks {
            assert_eq!(signatures_for(&signer, pk), 1, "exactly one signature per key");
        }

        let new_fee = test_fee_recipient(0xcd);
        update(
            &store,
            &pks[0],
            validator_store::ValidatorConfigUpdate {
                fee_recipient: Some(Some(new_fee)),
                ..Default::default()
            },
        );
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(
            pks.iter().map(|pk| signatures_for(&signer, pk)).collect::<Vec<_>>(),
            vec![2, 1, 1],
            "a fee change re-signs only that key"
        );
        {
            let calls = bn.register_calls.lock();
            assert_eq!(calls.len(), 3);
            let third = by_key(&calls[2]);
            assert_eq!(sent_keys(&calls[2]), key_set(&pks), "the third POST carries every key");
            assert_eq!(third[&pks[0]].message.fee_recipient, new_fee);
            assert_eq!(third[&pks[1]], by_key(&calls[0])[&pks[1]]);
        }

        update(
            &store,
            &pks[1],
            validator_store::ValidatorConfigUpdate {
                gas_limit: Some(Some(45_000_000)),
                ..Default::default()
            },
        );
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(
            pks.iter().map(|pk| signatures_for(&signer, pk)).collect::<Vec<_>>(),
            vec![2, 2, 1],
            "a gas change re-signs only that key"
        );
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 4);
        assert_eq!(sent_keys(&calls[3]), key_set(&pks));
        assert_eq!(by_key(&calls[3])[&pks[1]].message.gas_limit, 45_000_000);
    }

    /// 654-AC3 (unit): a failed batch is reported; the next call re-sends its cached signature.
    #[tokio::test]
    async fn test_registration_503_then_200_sends_at_next_call() {
        let (pks, store) = builder_keys_store(1);
        let bn = Arc::new(MockBn::new().with_register_error_on_calls(vec![0]));
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store, 0, 0);

        let first = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;
        assert!(
            matches!(
                first,
                Err(BuilderServiceError::RegistrationBatchesFailed { failed: 1, total: 1 })
            ),
            "{first:?}"
        );
        assert_eq!(cached_keys(&service).await, key_set(&pks), "the failed batch stays cached");

        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(signer.sign_calls.lock().len(), 1, "0 new signatures at the second call");
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1], calls[0], "the second POST carries the cached signature");
    }

    /// 654-AC9: every signature fails → `RegistrationSigningFailed`, no POST.
    #[tokio::test]
    async fn test_register_validators_errs_when_every_signature_fails() {
        let (_pks, store) = builder_keys_store(2);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new().with_sign_error());
        let service = build_service_with_batching(signer, bn.clone(), store, 0, 0);

        let result = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;

        assert!(
            matches!(
                result,
                Err(BuilderServiceError::RegistrationSigningFailed { failed: 2, total: 2 })
            ),
            "{result:?}"
        );
        assert!(bn.register_calls.lock().is_empty(), "nothing signed, nothing sent");
        assert!(cached_keys(&service).await.is_empty());
    }

    /// 682-4: every batch is tried, the failed one is reported, and every key stays cached.
    #[tokio::test]
    async fn test_register_validators_errs_when_a_batch_fails() {
        let (pks, store) = builder_keys_store(5);
        let bn = Arc::new(MockBn::new().with_register_error_on_calls(vec![1]));
        let service =
            build_service_with_batching(Arc::new(MockSigner::new()), bn.clone(), store, 2, 0);

        let result = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;

        assert!(
            matches!(
                result,
                Err(BuilderServiceError::RegistrationBatchesFailed { failed: 1, total: 3 })
            ),
            "{result:?}"
        );
        let sizes: Vec<usize> = bn.register_calls.lock().iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![2, 2, 1], "all 3 batches attempted");
        assert_eq!(cached_keys(&service).await, key_set(&pks), "all 5 keys cached");
    }

    /// 1 of 3 signatures fails: 2 sent, `RegistrationSigningFailed { 1, 3 }`; next call re-signs only that key.
    #[tokio::test]
    async fn test_partial_signing_failure_sends_the_rest_and_errs() {
        let (pks, store) = builder_keys_store(3);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new().with_sign_error_for(pks[1]));
        let service = build_service_with_batching(signer.clone(), bn.clone(), store, 0, 0);

        let result = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;
        assert!(
            matches!(
                result,
                Err(BuilderServiceError::RegistrationSigningFailed { failed: 1, total: 3 })
            ),
            "{result:?}"
        );
        assert_eq!(sent_keys(&bn.register_calls.lock()[0]), key_set(&[pks[0], pks[2]]));

        signer.heal();
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(
            pks.iter().map(|pk| signatures_for(&signer, pk)).collect::<Vec<_>>(),
            vec![1, 1, 1],
            "only the failed key is signed at the next call"
        );
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(sent_keys(&calls[1]), key_set(&pks));
    }

    /// 654-AC10 / 696-5: flag off → not in the next POST, not cached, not re-signed.
    #[tokio::test]
    async fn test_register_validators_evicts_key_whose_builder_flag_turned_off() {
        let (pks, store) = builder_keys_store(2);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store.clone(), 0, 0);
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        update(&store, &pks[0], builder_flag(false));
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        assert_eq!(sent_keys(&bn.register_calls.lock()[1]), key_set(&[pks[1]]));
        assert_eq!(cached_keys(&service).await, key_set(&[pks[1]]));
        assert_eq!(signer.sign_calls.lock().len(), 2, "no key re-signed");
    }

    /// 654-AC11 / 696-5: flag back on with the same fee and gas → 1 new signature, key sent.
    #[tokio::test]
    async fn test_register_validators_reregisters_when_flag_turned_back_on() {
        let (pks, store) = builder_keys_store(2);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store.clone(), 0, 0);
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        update(&store, &pks[0], builder_flag(false));
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        update(&store, &pks[0], builder_flag(true));
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        assert_eq!(signatures_for(&signer, &pks[0]), 2, "re-signed once after re-enable");
        assert_eq!(signatures_for(&signer, &pks[1]), 1);
        assert_eq!(cached_keys(&service).await, key_set(&pks));
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 3);
        assert_eq!(sent_keys(&calls[2]), key_set(&pks));
    }

    /// A key disabled or deleted (not in `list_enabled_pubkeys`) is evicted and not sent.
    #[tokio::test]
    async fn test_disabled_key_is_evicted() {
        let (pks, store) = builder_keys_store(3);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store.clone(), 0, 0);
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        store.set_enabled(&pks[0], false);
        store.remove_validator(&pks[1]);
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        assert_eq!(sent_keys(&bn.register_calls.lock()[1]), key_set(&[pks[2]]));
        assert_eq!(cached_keys(&service).await, key_set(&[pks[2]]));
        assert_eq!(signer.sign_calls.lock().len(), 3, "no key re-signed");
    }

    /// No builder keys → `Ok`, no POST, and the cache is emptied.
    #[tokio::test]
    async fn test_no_builder_keys_is_ok_and_empties_the_cache() {
        let bn = Arc::new(MockBn::new());
        let empty = build_service_with_batching(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000)),
            0,
            0,
        );
        empty.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert!(bn.register_calls.lock().is_empty());

        let (pks, store) = builder_keys_store(1);
        let bn = Arc::new(MockBn::new());
        let service = build_service_with_batching(
            Arc::new(MockSigner::new()),
            bn.clone(),
            store.clone(),
            0,
            0,
        );
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(cached_keys(&service).await, key_set(&pks));

        update(&store, &pks[0], builder_flag(false));
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        assert_eq!(bn.register_calls.lock().len(), 1, "no POST without builder keys");
        assert!(cached_keys(&service).await.is_empty());
    }

    /// Gloas: `Ok`, no sign, no POST, also for a key cached before Gloas.
    #[tokio::test]
    async fn test_submit_epoch_registrations_skipped_at_gloas() {
        let (_pks, store) = builder_keys_store(1);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::with_batching(
            signer.clone(),
            bn.clone(),
            store,
            GENESIS_FORK,
            0,
            0,
            gloas_at(gloas_epoch),
        );

        service.submit_epoch_registrations(gloas_epoch).await.unwrap();
        assert_eq!((signer.sign_calls.lock().len(), bn.register_calls.lock().len()), (0, 0));

        service.submit_epoch_registrations(gloas_epoch - 1).await.unwrap();
        assert_eq!((signer.sign_calls.lock().len(), bn.register_calls.lock().len()), (1, 1));

        service.submit_epoch_registrations(gloas_epoch + 1).await.unwrap();
        assert_eq!(
            (signer.sign_calls.lock().len(), bn.register_calls.lock().len()),
            (1, 1),
            "a key cached before Gloas is not re-sent"
        );
    }

    /// 654-AC5: 10 s plus one batch delay per batch after the first.
    #[test]
    fn test_registration_step_timeout_scales_with_batches() {
        fn timeout_for(builder_keys: usize, batch_size: usize, delay_ms: u64) -> Duration {
            let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
            // 400 enabled non-builder keys and 400 disabled builder keys are not counted.
            for i in 0..builder_keys + 800 {
                let mut pk = [0u8; 48];
                pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let mut config = ValidatorConfig::new(pk);
                config.builder_proposals = i < builder_keys || i >= builder_keys + 400;
                config.enabled = i < builder_keys + 400;
                store.add_validator(config).unwrap();
            }
            build_service_with_batching(
                Arc::new(MockSigner::new()),
                Arc::new(MockBn::new()),
                store,
                batch_size,
                delay_ms,
            )
            .registration_step_timeout()
        }

        assert_eq!(timeout_for(1_200, 500, 500), Duration::from_secs(11), "3 batches");
        assert_eq!(timeout_for(1_000, 500, 500), Duration::from_millis(10_500), "2 batches");
        assert_eq!(timeout_for(1_200, 0, 500), Duration::from_secs(10), "batch 0 is one batch");
        assert_eq!(timeout_for(0, 500, 500), Duration::from_secs(10), "zero keys is one batch");
        assert_eq!(
            timeout_for(1_200, 500, u64::MAX),
            Duration::from_secs(10) + Duration::from_millis(u64::MAX),
            "saturates"
        );
    }

    /// The second POST carries the first POST's signed timestamp; nothing is re-signed.
    #[tokio::test]
    async fn test_resend_keeps_the_original_signed_timestamp() {
        let (pks, store) = builder_keys_store(1);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store, 0, 0);

        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        let first = bn.register_calls.lock()[0][0].message.timestamp;
        assert_eq!(bn.register_calls.lock()[1][0].message.timestamp, first);

        // A re-sign inside the same wall-clock second repeats the timestamp, so age the
        // cached registration by one epoch: a re-sign now could not carry that value.
        let signed_earlier = first - 384;
        service.cache.write().await.get_mut(&pks[0]).unwrap().signed.message.timestamp =
            signed_earlier;
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        assert_eq!(bn.register_calls.lock()[2][0].message.timestamp, signed_earlier);
        assert_eq!(signer.sign_calls.lock().len(), 1, "signed once across three calls");
    }

    /// A failed batch is reported ahead of a failed signature.
    #[tokio::test]
    async fn test_batch_failure_wins_over_signing_failure() {
        let (pks, store) = builder_keys_store(2);
        let bn = Arc::new(MockBn::new().with_register_error());
        let signer = Arc::new(MockSigner::new().with_sign_error_for(pks[0]));
        let service = build_service_with_batching(signer, bn.clone(), store, 0, 0);

        let result = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;

        assert!(
            matches!(
                result,
                Err(BuilderServiceError::RegistrationBatchesFailed { failed: 1, total: 1 })
            ),
            "{result:?}"
        );
        assert_eq!(sent_keys(&bn.register_calls.lock()[0]), key_set(&[pks[1]]));
    }

    /// A changed key whose re-sign fails is not re-sent with its old fee recipient.
    #[tokio::test]
    async fn test_failed_resign_does_not_resend_the_stale_registration() {
        let (pks, store) = builder_keys_store(2);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = build_service_with_batching(signer.clone(), bn.clone(), store.clone(), 0, 0);
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();

        let new_fee = test_fee_recipient(0xcd);
        update(
            &store,
            &pks[0],
            validator_store::ValidatorConfigUpdate {
                fee_recipient: Some(Some(new_fee)),
                ..Default::default()
            },
        );
        signer.fail_for.lock().insert(pks[0]);
        let result = service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await;

        assert!(
            matches!(
                result,
                Err(BuilderServiceError::RegistrationSigningFailed { failed: 1, total: 1 })
            ),
            "{result:?}"
        );
        assert_eq!(sent_keys(&bn.register_calls.lock()[1]), key_set(&[pks[1]]));
        assert_eq!(cached_keys(&service).await, key_set(&[pks[1]]));

        signer.heal();
        service.submit_epoch_registrations(PRE_GLOAS_EPOCH).await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(by_key(&calls[2])[&pks[0]].message.fee_recipient, new_fee);
        assert_eq!(sent_keys(&calls[2]), key_set(&pks));
    }

    // --- Gloas retirement + preferences broadcast ---

    #[test]
    fn test_legacy_proposer_ops_retired_reads_only_fork_name() {
        for fork in ForkName::ALL {
            if fork < ForkName::Gloas {
                assert!(!legacy_proposer_ops_retired(fork), "{fork:?} is pre-Gloas");
            } else {
                assert!(legacy_proposer_ops_retired(fork), "{fork:?} inherits Gloas retirement");
            }
        }

        let mut schedule = ForkSchedule::unscheduled_gloas();
        schedule.gloas_fork_epoch = 42;
        assert!(!legacy_proposer_ops_retired(ForkName::from_epoch(41, &schedule)));
        assert!(legacy_proposer_ops_retired(ForkName::from_epoch(42, &schedule)));
        assert!(legacy_proposer_ops_retired(ForkName::from_epoch(43, &schedule)));
    }

    #[tokio::test]
    async fn test_register_and_prepare_skipped_at_gloas_epoch() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        service.register_validators(gloas_epoch).await.unwrap();
        let mut indices = HashMap::new();
        indices.insert(pk, 1u64);
        service.prepare_proposers(gloas_epoch, &indices).await.unwrap();

        assert!(bn.register_calls.lock().is_empty());
        assert!(bn.prepare_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn test_register_still_called_when_bn_returns_404() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new().with_register_error());
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            unscheduled(),
        );

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        service.register_validators(PRE_GLOAS_EPOCH).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 2);
    }

    #[tokio::test]
    async fn test_prepare_still_called_when_bn_returns_501() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);
        let bn = Arc::new(MockBn::new().with_prepare_error());
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            unscheduled(),
        );
        let mut indices = HashMap::new();
        indices.insert(pk, 7u64);

        let result = service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await;
        assert!(result.is_err());
        assert_eq!(bn.prepare_calls.lock().len(), 1);

        let result = service.prepare_proposers(PRE_GLOAS_EPOCH, &indices).await;
        assert!(result.is_err());
        assert_eq!(bn.prepare_calls.lock().len(), 2);
    }

    fn upcoming_for(pk: [u8; 48], current_epoch: u64, validator_index: u64) -> UpcomingProposal {
        UpcomingProposal {
            pubkey: pk,
            validator_index,
            proposal_slot: (current_epoch + 1) * SLOTS_PER_EPOCH,
            dependent_root: [0x33; 32],
        }
    }

    #[tokio::test]
    async fn test_broadcast_one_signed_preference_per_upcoming_slot() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0x11);
        let fr2 = test_fee_recipient(0x22);
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(fr1), Some(30_000_000)),
            (pk2, true, Some(fr2), Some(31_000_000)),
        ]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let proposals = vec![
            upcoming_for(pk1, gloas_epoch, 1),
            UpcomingProposal {
                pubkey: pk2,
                validator_index: 2,
                proposal_slot: (gloas_epoch + 1) * SLOTS_PER_EPOCH + 7,
                dependent_root: [0x44; 32],
            },
        ];
        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();

        let calls = bn.preference_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);
        assert_eq!(calls[0][0].message.proposal_slot, proposals[0].proposal_slot);
        assert_eq!(calls[0][0].message.validator_index, 1);
        assert_eq!(calls[0][0].message.fee_recipient, fr1);
        assert_eq!(calls[0][0].message.target_gas_limit, 30_000_000);
        assert_eq!(calls[0][0].message.dependent_root, [0x33; 32]);
        assert_eq!(calls[0][1].message.proposal_slot, proposals[1].proposal_slot);
        assert_eq!(calls[0][1].message.fee_recipient, fr2);
        assert_eq!(calls[0][1].message.target_gas_limit, 31_000_000);
        assert_eq!(calls[0][0].signature, signer.signature_bytes());
    }

    #[tokio::test]
    async fn test_broadcast_skips_unchanged_and_resubmits_on_fee_recipient_change() {
        let pk = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0xab);
        let fr2 = test_fee_recipient(0xcd);
        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr1);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            store.clone(),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposals = vec![upcoming_for(pk, gloas_epoch, 9)];

        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 1);

        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 1);

        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    fee_recipient: Some(Some(fr2)),
                    ..Default::default()
                },
            )
            .unwrap();

        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();
        let calls = bn.preference_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.fee_recipient, fr2);
    }

    #[tokio::test]
    async fn test_broadcast_reresubmits_on_gas_limit_change() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config).unwrap();

        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            store.clone(),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposals = vec![upcoming_for(pk, gloas_epoch, 9)];

        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 1);

        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    gas_limit: Some(Some(50_000_000)),
                    ..Default::default()
                },
            )
            .unwrap();

        service.broadcast_proposer_preferences(gloas_epoch, &proposals, &TEST_GVR).await.unwrap();
        let calls = bn.preference_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.target_gas_limit, 50_000_000);
    }

    #[tokio::test]
    async fn test_broadcast_rebroadcasts_on_dependent_root_change_only() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let root_a = [0x33; 32];
        let root_b = [0x44; 32];
        let slot_a = upcoming_for(pk, gloas_epoch, 1);
        let slot_b = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: slot_a.proposal_slot + 3,
            dependent_root: root_a,
        };
        let with_root = |root: Root| {
            vec![
                UpcomingProposal { dependent_root: root, ..slot_a.clone() },
                UpcomingProposal { dependent_root: root, ..slot_b.clone() },
            ]
        };

        service
            .broadcast_proposer_preferences(gloas_epoch, &with_root(root_a), &TEST_GVR)
            .await
            .unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 1);
        assert_eq!(bn.preference_calls.lock()[0].len(), 2);

        service
            .broadcast_proposer_preferences(gloas_epoch, &with_root(root_a), &TEST_GVR)
            .await
            .unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 1);

        service
            .broadcast_proposer_preferences(gloas_epoch, &with_root(root_b), &TEST_GVR)
            .await
            .unwrap();
        {
            let calls = bn.preference_calls.lock();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1].len(), 2);
            let slots: Vec<u64> = calls[1].iter().map(|p| p.message.proposal_slot).collect();
            assert!(slots.contains(&slot_a.proposal_slot));
            assert!(slots.contains(&slot_b.proposal_slot));
            for signed in &calls[1] {
                assert_eq!(signed.message.dependent_root, root_b);
            }
        }

        service
            .broadcast_proposer_preferences(gloas_epoch, &with_root(root_b), &TEST_GVR)
            .await
            .unwrap();
        assert_eq!(bn.preference_calls.lock().len(), 2);

        service
            .broadcast_proposer_preferences(gloas_epoch, &with_root(root_a), &TEST_GVR)
            .await
            .unwrap();
        {
            let calls = bn.preference_calls.lock();
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[2].len(), 2);
            for signed in &calls[2] {
                assert_eq!(signed.message.dependent_root, root_a);
            }
        }
    }

    #[tokio::test]
    async fn test_broadcast_at_gloas_minus_one_for_gloas_slots() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let pre_gloas_slot = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: (gloas_epoch - 1) * SLOTS_PER_EPOCH,
            dependent_root: [0x11; 32],
        };
        service
            .broadcast_proposer_preferences(gloas_epoch - 1, &[pre_gloas_slot], &TEST_GVR)
            .await
            .unwrap();
        assert!(bn.preference_calls.lock().is_empty());

        let gloas_slot = upcoming_for(pk, gloas_epoch - 1, 1);
        assert_eq!(gloas_slot.proposal_slot / SLOTS_PER_EPOCH, gloas_epoch);
        service
            .broadcast_proposer_preferences(
                gloas_epoch - 1,
                std::slice::from_ref(&gloas_slot),
                &TEST_GVR,
            )
            .await
            .unwrap();
        let calls = bn.preference_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0].message.proposal_slot, gloas_slot.proposal_slot);
    }

    #[tokio::test]
    async fn test_broadcast_includes_remaining_current_epoch_gloas_slots() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let current = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: gloas_epoch * SLOTS_PER_EPOCH + 3,
            dependent_root: [0x22; 32],
        };
        let next = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_proposer_preferences(
                gloas_epoch,
                &[current.clone(), next.clone()],
                &TEST_GVR,
            )
            .await
            .unwrap();
        let calls = bn.preference_calls.lock();
        assert_eq!(calls.len(), 1);
        let slots: Vec<u64> = calls[0].iter().map(|p| p.message.proposal_slot).collect();
        assert!(slots.contains(&current.proposal_slot));
        assert!(slots.contains(&next.proposal_slot));
    }

    #[tokio::test]
    async fn test_preference_cache_evicts_slots_before_current_epoch() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let old = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_proposer_preferences(gloas_epoch, std::slice::from_ref(&old), &TEST_GVR)
            .await
            .unwrap();
        assert_eq!(service.preference_cache.read().await.len(), 1);

        let later = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: (gloas_epoch + 2) * SLOTS_PER_EPOCH,
            dependent_root: [0x55; 32],
        };
        service
            .broadcast_proposer_preferences(
                gloas_epoch + 2,
                std::slice::from_ref(&later),
                &TEST_GVR,
            )
            .await
            .unwrap();
        let cache = service.preference_cache.read().await;
        assert!(!cache.contains_key(&(pk, old.proposal_slot)));
        assert!(cache.contains_key(&(pk, later.proposal_slot)));
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_sentinel_gloas_epoch_does_not_retire_or_broadcast() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let schedule = unscheduled();
        assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
        let epoch = 1_000_000;
        assert_ne!(ForkName::from_epoch(epoch, &schedule), ForkName::Gloas);

        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            schedule,
        );

        service.register_validators(epoch).await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        let proposals = vec![upcoming_for(pk, epoch, 1)];
        service.broadcast_proposer_preferences(epoch, &proposals, &TEST_GVR).await.unwrap();
        assert!(bn.preference_calls.lock().is_empty());
    }

    fn store_with_builders(pk: [u8; 48], urls: &[&str]) -> ValidatorStore {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.builders = Some(urls.iter().map(|u| (*u).to_string()).collect());
        store.add_validator(config).unwrap();
        store
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_one_entry_per_proposer_builder() {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let proposer_pk = sk.public_key();
        let urls = ["https://a.example", "https://b.example"];
        let store = store_with_builders(pk, &urls);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new().with_auth_key(sk)),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();

        let calls = bn.builder_pref_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);
        let mut seen_urls = calls[0].iter().map(|e| e.url.as_str()).collect::<Vec<_>>();
        seen_urls.sort();
        assert_eq!(seen_urls, vec!["https://a.example", "https://b.example"]);
        for entry in &calls[0] {
            assert_eq!(entry.auth.message.slot, proposal.proposal_slot);
            assert_eq!(entry.proposer_pubkey, format!("0x{}", hex::encode(pk)));
            let data = hex::decode(entry.auth.message.data.trim_start_matches("0x")).unwrap();
            let auth = BuilderRequestAuth::new(data, entry.auth.message.slot).expect("auth data");
            let sig = crypto::Signature::from_bytes(
                &hex::decode(entry.auth.signature.trim_start_matches("0x")).unwrap(),
            )
            .unwrap();
            let root = crypto::signing_root_with_fork_version(
                &auth,
                eth_types::DOMAIN_BUILDER_REQUEST_AUTH,
                GENESIS_FORK,
                [0u8; 32],
            );
            sig.verify(&proposer_pk, &root).expect("6.16 domain");
        }
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_skips_unchanged_set() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert_eq!(bn.builder_pref_calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_resubmits_on_dependent_root_change() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let mut proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert_eq!(bn.builder_pref_calls.lock().len(), 1);
        let first_auth = bn.builder_pref_calls.lock()[0][0].auth.clone();
        let signs_after_first = signer.sign_calls.lock().len();
        assert!(signs_after_first >= 1);

        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert_eq!(bn.builder_pref_calls.lock().len(), 1);
        assert_eq!(signer.sign_calls.lock().len(), signs_after_first);

        proposal.dependent_root = [0x44; 32];
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        {
            let calls = bn.builder_pref_calls.lock();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1].len(), 1);
            assert_eq!(calls[1][0].auth.message.slot, proposal.proposal_slot);
            assert_eq!(calls[1][0].auth, first_auth);
        }
        assert_eq!(signer.sign_calls.lock().len(), signs_after_first);

        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert_eq!(bn.builder_pref_calls.lock().len(), 2);
        assert_eq!(signer.sign_calls.lock().len(), signs_after_first);
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_empty_builders_does_not_sign() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        assert!(store.builders(&pk).is_empty());
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert!(bn.builder_pref_calls.lock().is_empty());
        assert!(signer.sign_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_at_gloas_minus_one_for_gloas_slots() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );

        let pre = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: (gloas_epoch - 1) * SLOTS_PER_EPOCH,
            dependent_root: [0x11; 32],
        };
        service.broadcast_builder_preferences(gloas_epoch - 1, &[pre]).await.unwrap();
        assert!(bn.builder_pref_calls.lock().is_empty());
        assert!(signer.sign_calls.lock().is_empty());

        let gloas_slot = upcoming_for(pk, gloas_epoch - 1, 1);
        assert_eq!(gloas_slot.proposal_slot / SLOTS_PER_EPOCH, gloas_epoch);
        service
            .broadcast_builder_preferences(gloas_epoch - 1, std::slice::from_ref(&gloas_slot))
            .await
            .unwrap();
        let calls = bn.builder_pref_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].auth.message.slot, gloas_slot.proposal_slot);
        assert_eq!(calls[0][0].url, "https://a.example");
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_pre_gloas_is_noop() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let pre = UpcomingProposal {
            pubkey: pk,
            validator_index: 1,
            proposal_slot: (gloas_epoch - 1) * SLOTS_PER_EPOCH,
            dependent_root: [0x11; 32],
        };
        service.broadcast_builder_preferences(gloas_epoch - 1, &[pre]).await.unwrap();
        assert!(bn.builder_pref_calls.lock().is_empty());
        assert!(signer.sign_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_400_keeps_accepted_entries() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example", "https://b.example"]);
        let bn = Arc::new(MockBn::new().with_indexed_failures(vec![bn_manager::IndexedFailure {
            index: 1,
            message: "builder rejected".into(),
        }]));
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        assert_eq!(bn.builder_pref_calls.lock().len(), 1);
        assert_eq!(bn.builder_pref_calls.lock()[0].len(), 2);

        let config = service.builder_config_for(&pk, proposal.proposal_slot).await;
        assert_eq!(config.builders.len(), 1);
        assert_eq!(config.builders[0].url, "https://a.example");
    }

    #[tokio::test]
    async fn test_builder_config_auth_is_byte_identical_to_preferences_submit() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        let submitted = bn.builder_pref_calls.lock()[0][0].auth.clone();
        let config = service.builder_config_for(&pk, proposal.proposal_slot).await;
        assert_eq!(config.builders.len(), 1);
        let submitted_bytes = serde_json::to_vec(&submitted).unwrap();
        let config_bytes = serde_json::to_vec(&config.builders[0].auth).unwrap();
        assert_eq!(submitted_bytes, config_bytes);
        assert_eq!(submitted, config.builders[0].auth);
    }

    #[tokio::test]
    async fn test_sentinel_gloas_epoch_does_not_submit_builder_preferences() {
        let pk = gen_pubkey_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let schedule = unscheduled();
        let epoch = 1_000_000;
        let service = BuilderService::new(
            Arc::new(MockSigner::new()),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            schedule,
        );
        let proposals = vec![upcoming_for(pk, epoch, 1)];
        service.broadcast_builder_preferences(epoch, &proposals).await.unwrap();
        assert!(bn.builder_pref_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn test_broadcast_builder_preferences_dedupes_and_caps_urls() {
        let pk = gen_pubkey_bytes();
        let mut urls: Vec<String> = vec!["https://a.example".into(), "https://a.example".into()];
        urls.extend((0..MAX_BUILDER_ENTRIES).map(|i| format!("https://b{i}.example")));
        assert_eq!(urls.len(), 2 + MAX_BUILDER_ENTRIES);
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.builders = Some(urls);
        store.add_validator(config).unwrap();
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let gloas_epoch = 10;
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        service
            .broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal))
            .await
            .unwrap();
        let calls = bn.builder_pref_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), MAX_BUILDER_ENTRIES);
        assert_eq!(calls[0][0].url, "https://a.example");
        assert_eq!(signer.sign_calls.lock().len(), MAX_BUILDER_ENTRIES);
    }

    #[test]
    fn test_capped_unique_builder_urls_dedupes() {
        let urls = vec![
            "https://a.example".into(),
            "https://a.example".into(),
            "https://b.example".into(),
        ];
        assert_eq!(
            capped_unique_builder_urls(urls),
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
    }

    fn production_signer() -> (Arc<signer::SignerService>, PublicKey, Arc<dyn RegistrationSigner>) {
        let secret = crypto::SecretKey::generate();
        let pubkey = secret.public_key();
        let mut keys = crypto::KeyManager::new();
        keys.insert(secret);
        let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(keys)));
        let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("memory slashing db"));
        let service = Arc::new(
            signer::SignerService::new(composite, db).with_enablement(signer::always_enabled()),
        );
        let validator: Arc<dyn signer::ValidatorSigner> = service.clone();
        (service, pubkey, Arc::new(validator))
    }

    /// Registration installs `BeaconAdmission::unbound`. Removing that scope
    /// makes the submit empty, because `require_beacon_admission_scope` runs
    /// the production missing-scope branch.
    #[tokio::test]
    async fn registration_signs_under_unbound_scope_and_is_refused_without_one() {
        let (service, pubkey, signer) = production_signer();
        let pk = pubkey.to_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let builder =
            BuilderService::new(signer, bn.clone(), Arc::new(store), GENESIS_FORK, unscheduled());
        signer::require_beacon_admission_scope(builder.register_validators(PRE_GLOAS_EPOCH))
            .await
            .unwrap();
        {
            let calls = bn.register_calls.lock();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].len(), 1);
            assert_eq!(calls[0][0].signature.len(), 96);
        }

        let registration = ValidatorRegistrationV1 {
            fee_recipient: [0; 20],
            gas_limit: 1,
            timestamp: 1,
            pubkey: pk,
        };
        let err = signer::require_beacon_admission_scope(service.sign_builder_registration(
            &registration,
            &pubkey,
            GENESIS_FORK,
        ))
        .await
        .expect_err("missing admission scope");
        assert!(matches!(err, SignerError::BeaconAdmissionRevoked));
    }

    /// The preferences gate installs the beacon scope before the sign.
    /// Removing `preference_admission` leaves the production branch with no
    /// scope, so nothing is submitted.
    #[tokio::test]
    async fn proposer_preferences_sign_under_the_gate_and_are_refused_without_a_scope() {
        let (service, pubkey, signer) = production_signer();
        let pk = pubkey.to_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let builder = BuilderService::new(
            signer,
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        signer::require_beacon_admission_scope(builder.broadcast_proposer_preferences(
            gloas_epoch,
            std::slice::from_ref(&proposal),
            &TEST_GVR,
        ))
        .await
        .unwrap();
        {
            let calls = bn.preference_calls.lock();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].len(), 1);
            assert_eq!(calls[0][0].signature.len(), 96);
        }

        let prefs = ProposerPreferences {
            dependent_root: proposal.dependent_root,
            proposal_slot: proposal.proposal_slot,
            validator_index: proposal.validator_index,
            fee_recipient: [0; 20],
            target_gas_limit: 1,
        };
        let err = signer::require_beacon_admission_scope(service.sign_proposer_preferences(
            &prefs,
            &pubkey,
            &gloas_at(gloas_epoch),
            &TEST_GVR,
        ))
        .await
        .expect_err("missing admission scope");
        assert!(matches!(err, SignerError::BeaconAdmissionRevoked));
    }

    /// Builder-request auth uses the same gate. A missing scope is refused.
    #[tokio::test]
    async fn builder_request_auth_signs_under_the_gate_and_is_refused_without_a_scope() {
        let (service, pubkey, signer) = production_signer();
        let pk = pubkey.to_bytes();
        let store = store_with_builders(pk, &["https://a.example"]);
        let bn = Arc::new(MockBn::new());
        let gloas_epoch = 10;
        let builder = BuilderService::new(
            signer,
            bn.clone(),
            Arc::new(store),
            GENESIS_FORK,
            gloas_at(gloas_epoch),
        );
        let proposal = upcoming_for(pk, gloas_epoch, 1);
        signer::require_beacon_admission_scope(
            builder.broadcast_builder_preferences(gloas_epoch, std::slice::from_ref(&proposal)),
        )
        .await
        .unwrap();
        {
            let calls = bn.builder_pref_calls.lock();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].len(), 1);
        }

        let auth = BuilderRequestAuth::new(b"https://a.example".to_vec(), proposal.proposal_slot)
            .expect("auth");
        let err = signer::require_beacon_admission_scope(service.sign_builder_request_auth(
            &auth,
            &pubkey,
            GENESIS_FORK,
        ))
        .await
        .expect_err("missing admission scope");
        assert!(matches!(err, SignerError::BeaconAdmissionRevoked));
    }
}
