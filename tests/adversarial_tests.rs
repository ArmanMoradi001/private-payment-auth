//! Adversarial tests: a malicious prover must never get a corrupted
//! artifact accepted. Corruptions are applied *before* re-commitment
//! where possible (so the commitment layer passes and the semantic
//! checks must catch the cheat), and directly otherwise.

use ark_ff::{One, Zero};
use circuit::{Circuit, CircuitBuilder};
use crypto_core::{Digest, SecretBytes};
use mpc::PublicValue;
use mpcith::{
    MpcithError, MpcithProof, MpcithProver, MpcithVerifier, OpenedView, PartyId, PartyView,
    RepetitionId, Statement, TripleShare, VerificationResult, ViewCommitment,
};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand_core::SeedableRng;

type Fr = mpcith::FieldElement;

/// Circuit: out = x0 * x1 (two secret inputs, one Beaver multiplication).
fn beaver_circuit() -> Circuit<Fr> {
    let mut b = CircuitBuilder::<Fr>::new();
    let x0 = b.secret_input();
    let x1 = b.secret_input();
    let m = b.mul(x0, x1).expect("valid");
    b.output(m).expect("valid");
    b.build().expect("valid")
}

fn statement_for(circuit: &Circuit<Fr>, expected: Fr) -> Statement {
    Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![],
        expected_outputs: vec![PublicValue::new(expected)],
    }
}

/// Hand-builds three honest party views for `x0 · x1`, exercising the
/// same algebra the prover uses, with the caller choosing the split.
#[allow(clippy::too_many_lines)]
fn honest_views(w0: Fr, w1: Fr, rng: &mut ChaCha20Rng) -> (Vec<PartyView>, Fr) {
    let mut views = Vec::new();
    let mut xs0 = Vec::new();
    let mut xs1 = Vec::new();

    // Random additive splits of both secrets.
    let mut acc0 = Fr::zero();
    let mut acc1 = Fr::zero();
    for _ in 0..3 {
        let s0 = Fr::from(rng.next_u64());
        let s1 = Fr::from(rng.next_u64());
        acc0 += s0;
        acc1 += s1;
        xs0.push(s0);
        xs1.push(s1);
    }
    // Fix party 2's share to complete the sums.
    let last0 = w0 - acc0 + xs0[2];
    let last1 = w1 - acc1 + xs1[2];
    xs0[2] = last0;
    xs1[2] = last1;

    // Fresh triple shares with c = a·b over the sums.
    let mut tri = Vec::new();
    for _ in 0..3 {
        tri.push((Fr::from(rng.next_u64()), Fr::from(rng.next_u64())));
    }
    let big_a: Fr = tri.iter().map(|(a, _)| *a).sum();
    let big_b: Fr = tri.iter().map(|(_, b)| *b).sum();
    let big_c = big_a * big_b;
    let c_partial: Fr = tri
        .iter()
        .map(|_| Fr::from(rng.next_u64()))
        .take(2)
        .product();
    let _ = c_partial;
    let c_rand1 = Fr::from(rng.next_u64());
    let c_rand2 = Fr::from(rng.next_u64());
    let cs = [big_c - c_rand1 - c_rand2, c_rand1, c_rand2];

    let d: Fr = (0..3).map(|i| xs0[i]).sum::<Fr>() - big_a;
    let e: Fr = (0..3).map(|i| xs1[i]).sum::<Fr>() - big_b;

    for i in 0..3usize {
        let dp = xs0[i] - tri[i].0;
        let ep = xs1[i] - tri[i].1;
        let mut z = cs[i] + d * tri[i].1 + e * tri[i].0;
        if i == 0 {
            z += d * e;
        }
        views.push(PartyView {
            repetition_id: RepetitionId::new(0),
            party_id: PartyId::new(i as u8).unwrap(),
            input_shares: vec![xs0[i], xs1[i]],
            local_operations: vec![mpcith::LocalOperation::BeaverMul {
                output: circuit::NodeId::new(2),
                triple_index: 0,
                d,
                e,
                share: z,
            }],
            triple_shares: vec![TripleShare {
                a: tri[i].0,
                b: tri[i].1,
                c: cs[i],
            }],
            opened_values: vec![dp, ep],
        });
    }

    let product = w0 * w1;
    (views, product)
}

/// Commits three views into a single-repetition proof with the given
/// hidden party and hidden output share.
fn forge_proof(views: &[PartyView], hidden: u8, hidden_output_share: Fr) -> MpcithProof {
    let mut commitments = Vec::new();
    let mut opened = Vec::new();
    for v in views {
        let r = SecretBytes::new(vec![7u8; 32]);
        commitments.push(mpcith::commit_view(v, &r).expect("valid"));
        if v.party_id.get() != hidden {
            opened.push(OpenedView {
                view: v.clone(),
                randomness: r,
            });
        }
    }
    opened.sort_by_key(|ov| ov.view.party_id.get());
    MpcithProof {
        repetitions: vec![mpcith::Repetition {
            id: RepetitionId::new(0),
            commitments,
            challenge: mpcith::Challenge {
                hidden_party: PartyId::new(hidden).unwrap(),
            },
            opened_views: opened,
            hidden_output_shares: vec![hidden_output_share],
            hidden_broadcasts: views[hidden as usize].opened_values.clone(),
        }],
    }
}

fn accepts(circuit: &Circuit<Fr>, st: &Statement, proof: &MpcithProof) -> bool {
    matches!(
        MpcithVerifier::new().verify(st, proof, circuit),
        Ok(VerificationResult::Valid)
    )
}

/// The hidden party's output contribution: its recorded result share
/// of the single Mul gate (node 2).
fn hidden_output_of(views: &[PartyView], hidden: u8) -> Fr {
    let idx = hidden as usize;
    match &views[idx].local_operations[0] {
        mpcith::LocalOperation::BeaverMul { share, .. } => *share,
        _ => panic!("expected beaver mul"),
    }
}

fn baseline() -> (Circuit<Fr>, Statement, MpcithProof, Fr) {
    let circuit = beaver_circuit();
    let mut rng = ChaCha20Rng::seed_from_u64(2024);
    let (views, product) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    let st = statement_for(&circuit, product);
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    assert!(
        accepts(&circuit, &st, &proof),
        "hand-built honest proof must verify"
    );
    (circuit, st, proof, product)
}

#[test]
fn tampered_opened_operation_is_caught_by_replay() {
    let (circuit, st, _, _) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let (mut views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // Corrupt party 1's claimed result share, then commit normally:
    // commitments pass, replay must catch it.
    if let mpcith::LocalOperation::BeaverMul { share, .. } = &mut views[1].local_operations[0] {
        *share += Fr::one();
    }
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    assert!(!accepts(&circuit, &st, &proof));
}

#[test]
fn tampered_opened_mask_is_caught_as_invalid_opening() {
    let (circuit, st, _, _) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    let (mut views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // Claim a wrong d without touching the triple share.
    views[0].opened_values[0] += Fr::one();
    if let mpcith::LocalOperation::BeaverMul { d, .. } = &mut views[0].local_operations[0] {
        *d += Fr::one();
    }
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    assert!(matches!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::InvalidOpening) | Ok(VerificationResult::Invalid)
    ));
}

#[test]
fn tampered_triple_share_breaks_beaver_algebra() {
    let (circuit, st, _, _) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let (mut views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // Change an opened party's c share: z check must fail.
    views[1].triple_shares[0].c += Fr::one();
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    assert!(matches!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::InconsistentView | MpcithError::InvalidOpening)
            | Ok(VerificationResult::Invalid)
    ));
}

#[test]
fn altered_input_share_breaks_downstream_checks() {
    let (circuit, st, _, _) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(34);
    let (mut views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // Shift an opened party's input share without fixing its masks.
    views[1].input_shares[0] += Fr::one();
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    assert!(!accepts(&circuit, &st, &proof));
}

#[test]
fn inconsistent_broadcast_contributions_reject() {
    let (circuit, st, _, _) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(35);
    let (mut views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // An opened party broadcasts a d contribution inconsistent with
    // its own input share and triple.
    views[1].opened_values[0] += Fr::one();
    let proof = forge_proof(&views, 2, hidden_output_of(&views, 2));
    // The tampered contribution shifts the global mask, which trips
    // the recorded-operation check of the other opened party.
    assert_eq!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::InconsistentView)
    );
}

#[test]
fn altered_output_share_invalidates() {
    let (circuit, st, _, product) = baseline();
    let mut rng = ChaCha20Rng::seed_from_u64(36);
    let (views, _) = honest_views(Fr::from(6u64), Fr::from(9u64), &mut rng);
    // Hidden party claims a shifted output contribution.
    let proof = forge_proof(&views, 2, product - Fr::one());
    assert!(!accepts(&circuit, &st, &proof));
}

#[test]
fn modified_opened_commitment_rejects() {
    let (circuit, st, mut proof, _) = baseline();
    // Commitments of *opened* views are checked against the revealed
    // randomness. (Modifying the *hidden* party's commitment is
    // undetectable by design — it binds nothing the verifier sees.)
    proof.repetitions[0].commitments[1] = ViewCommitment::from_digest(Digest::new([0xEE; 32]));
    assert_eq!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::CommitmentMismatch)
    );
}

#[test]
fn opening_with_different_randomness_rejects() {
    let (circuit, st, mut proof, _) = baseline();
    proof.repetitions[0].opened_views[0].randomness = SecretBytes::new(vec![3u8; 32]);
    assert_eq!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::CommitmentMismatch)
    );
}

#[test]
fn different_circuit_rejects() {
    let (_, st, proof, _) = baseline();
    // Genuinely different circuit (extra constant) → different id.
    let mut b = CircuitBuilder::<Fr>::new();
    let x1 = b.secret_input();
    let x0 = b.secret_input();
    let m = b.mul(x1, x0).expect("valid");
    let c = b.constant(Fr::one()); // changes semantics and encoding
    let s = b.add(m, c).expect("valid");
    b.output(s).expect("valid");
    let other = b.build().expect("valid");
    assert_eq!(
        MpcithVerifier::new().verify(&st, &proof, &other),
        Err(MpcithError::InvalidCircuit)
    );
}

#[test]
fn mixed_and_misidentified_repetitions_reject() {
    let (circuit, st, mut proof, _) = baseline();
    // Repetition id no longer equals its position.
    proof.repetitions[0].id = RepetitionId::new(5);
    assert_eq!(
        MpcithVerifier::new().verify(&st, &proof, &circuit),
        Err(MpcithError::InconsistentView)
    );

    // Reusing a view across repetitions fails: every view carries its
    // repetition id, so a duplicated view no longer matches the second
    // repetition's identity.
    let (circuit, st, good, _) = baseline();
    let mut doubled = MpcithProof {
        repetitions: vec![good.repetitions[0].clone(), good.repetitions[0].clone()],
    };
    doubled.repetitions[1].id = RepetitionId::new(1);
    assert_eq!(
        MpcithVerifier::new().verify(&st, &doubled, &circuit),
        Err(MpcithError::InconsistentView)
    );

    // Misordered id must reject.
    doubled.repetitions[1].id = RepetitionId::new(0);
    assert_eq!(
        MpcithVerifier::new().verify(&st, &doubled, &circuit),
        Err(MpcithError::InconsistentView)
    );
}

#[test]
fn malformed_encodings_reject() {
    let (_, _, proof, _) = baseline();
    let bytes = mpcith::serialize_proof(&proof);

    // Truncation.
    assert!(matches!(
        mpcith::decode_proof(&bytes[..bytes.len() - 4]),
        Err(MpcithError::MalformedEncoding)
    ));
    // Trailing bytes.
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(matches!(
        mpcith::decode_proof(&extended),
        Err(MpcithError::MalformedEncoding)
    ));
    // Invalid hidden-party byte inside an encoded challenge position:
    // flip the version byte instead — unsupported versions are rejected.
    let mut bad_version = bytes.clone();
    bad_version[0] = 0xFF;
    assert!(matches!(
        mpcith::decode_proof(&bad_version),
        Err(MpcithError::MalformedEncoding)
    ));
}

#[test]
fn exhausted_challenge_source_cannot_prove() {
    let circuit = beaver_circuit();
    let st = statement_for(&circuit, Fr::from(54u64));
    let mut prover = MpcithProver::new(
        &circuit,
        &st,
        vec![Fr::from(6u64), Fr::from(9u64)],
        Box::new(mpcith::DeterministicChallengeSource::repeating(
            PartyId::new(0).unwrap(),
            1,
        )),
        ChaCha20Rng::seed_from_u64(40),
    )
    .expect("valid");
    // Asking for more repetitions than the source supports must fail.
    assert_eq!(
        prover.prove(2).map(|_| ()).unwrap_err(),
        MpcithError::InvalidProtocolState
    );
}
