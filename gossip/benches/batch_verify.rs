#![feature(test)]

extern crate test;

use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature, Verifier};
use rand::thread_rng;
use test::Bencher;
use {
    solana_gossip::crds_value::CrdsValue,
    solana_sdk::signature::Signable,
};

/// Generate CrdsValues for verification
fn generate_test_data(num_signatures: usize) -> (Vec<DalekPublicKey>, Vec<Vec<u8>>, Vec<DalekSignature>) {
    let mut rng = thread_rng();

    let mut public_keys = Vec::with_capacity(num_signatures);
    let mut messages = Vec::with_capacity(num_signatures);
    let mut signatures = Vec::with_capacity(num_signatures);

    for _ in 0..num_signatures {
        let crds_value = CrdsValue::new_rand(&mut rng, None);
        let crds_pk = crds_value.pubkey();
        let pubkey_bytes = crds_pk.as_ref();
        let pk = DalekPublicKey::from_bytes(pubkey_bytes).unwrap();
        let sig = DalekSignature::try_from(crds_value.signature().as_ref()).unwrap();
        let message = crds_value.signable_data().into_owned();

        public_keys.push(pk);
        messages.push(message);
        signatures.push(sig);
    }

    (public_keys, messages, signatures)
}

/// Benchmark iterative verification
#[bench]
fn bench_single_verify(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    bencher.iter(|| {
        for ((pk, msg), sig) in public_keys.iter().zip(&messages).zip(&signatures) {
            pk.verify(msg, sig).expect("Single verify failed");
        }
    });
}

/// Benchmark batch verification
#[bench]
fn bench_batch_verify_1000(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    let batch_size = 1000;
    let total = public_keys.len();

    bencher.iter(|| {
        let mut start_idx = 0;

        while start_idx < total {
            let end_idx = (start_idx + batch_size).min(total);

            let msg_slices: Vec<&[u8]> = messages[start_idx..end_idx]
                .iter()
                .map(|m| m.as_slice())
                .collect();
            let sigs = &signatures[start_idx..end_idx];
            let pks = &public_keys[start_idx..end_idx];

            ed25519_dalek::verify_batch(&msg_slices, sigs, pks)
                .expect("Batch verify failed");

            start_idx = end_idx;
        }
    });
}

#[bench]
fn bench_batch_verify_500(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    let batch_size = 500;
    let total = public_keys.len();

    bencher.iter(|| {
        let mut start_idx = 0;

        while start_idx < total {
            let end_idx = (start_idx + batch_size).min(total);

            let msg_slices: Vec<&[u8]> = messages[start_idx..end_idx]
                .iter()
                .map(|m| m.as_slice())
                .collect();
            let sigs = &signatures[start_idx..end_idx];
            let pks = &public_keys[start_idx..end_idx];

            ed25519_dalek::verify_batch(&msg_slices, sigs, pks)
                .expect("Batch verify failed");

            start_idx = end_idx;
        }
    });
}

#[bench]
fn bench_batch_verify_100(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    let batch_size = 100;
    let total = public_keys.len();

    bencher.iter(|| {
        let mut start_idx = 0;

        while start_idx < total {
            let end_idx = (start_idx + batch_size).min(total);

            let msg_slices: Vec<&[u8]> = messages[start_idx..end_idx]
                .iter()
                .map(|m| m.as_slice())
                .collect();
            let sigs = &signatures[start_idx..end_idx];
            let pks = &public_keys[start_idx..end_idx];

            ed25519_dalek::verify_batch(&msg_slices, sigs, pks)
                .expect("Batch verify failed");

            start_idx = end_idx;
        }
    });
}

#[bench]
fn bench_batch_verify_20(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    let batch_size = 100;
    let total = public_keys.len();

    bencher.iter(|| {
        let mut start_idx = 0;

        while start_idx < total {
            let end_idx = (start_idx + batch_size).min(total);

            let msg_slices: Vec<&[u8]> = messages[start_idx..end_idx]
                .iter()
                .map(|m| m.as_slice())
                .collect();
            let sigs = &signatures[start_idx..end_idx];
            let pks = &public_keys[start_idx..end_idx];

            ed25519_dalek::verify_batch(&msg_slices, sigs, pks)
                .expect("Batch verify failed");

            start_idx = end_idx;
        }
    });
}


#[bench]
fn bench_batch_verify_10(bencher: &mut Bencher) {
    let (public_keys, messages, signatures) = generate_test_data(5000);

    let batch_size = 100; // Smaller batch size
    let total = public_keys.len();

    bencher.iter(|| {
        let mut start_idx = 0;

        while start_idx < total {
            let end_idx = (start_idx + batch_size).min(total);

            // Create slices for this sub-batch
            let msg_slices: Vec<&[u8]> = messages[start_idx..end_idx]
                .iter()
                .map(|m| m.as_slice())
                .collect();
            let sigs = &signatures[start_idx..end_idx];
            let pks = &public_keys[start_idx..end_idx];

            // Perform batch verify on this sub-batch
            ed25519_dalek::verify_batch(&msg_slices, sigs, pks)
                .expect("Batch verify failed");

            start_idx = end_idx;
        }
    });
}
