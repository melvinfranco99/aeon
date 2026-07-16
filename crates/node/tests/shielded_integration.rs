//! End-to-end test of Aeon's optional shielded pool (see `docs/PRIVACY.md`):
//! two nodes on loopback P2P, one mines a block paying a transparent
//! address, that wallet shields the funds into its own shielded address,
//! sends part of it *privately* to a second shielded address, and that
//! recipient deshields back to a transparent address — all real zk-SNARK
//! proofs, no shortcuts. Every step is confirmed on node A and checked to
//! have propagated to node B, exactly like the transparent flow in
//! `two_node_integration.rs`.
//!
//! This test builds several real Halo2 proofs, so it takes real wall-clock
//! time (well over a minute) — that's expected, not a bug.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aeon_core::{
    bits_to_target, hash_meets_target, Block, GhostdagParams, OutPoint, Transaction, TxInput,
};
use aeon_crypto::{Address, Hash, KeyPair};
use aeon_network::Network;
use aeon_node::{genesis_block, spawn_node, NodeHandle};
use aeon_rpc::RpcBackend;
use aeon_shielded::orchard::keys::SpendAuthorizingKey;
use aeon_shielded::orchard::note::Note;
use aeon_storage::Store;

async fn start_node(node_id: [u8; 16]) -> (NodeHandle, Arc<Network>, SocketAddr) {
    let store = Store::open_temporary().expect("open temp store");
    store
        .insert_genesis(genesis_block())
        .expect("insert genesis");
    let tip = store.tip().unwrap();
    let tip_data = store.get_ghostdag(&tip).unwrap();

    let network = Arc::new(Network::new(node_id, tip, tip_data.blue_work));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    network.listen(addr).await.expect("listen");

    let params = GhostdagParams::default();
    let running = spawn_node(store, params, network.clone());
    (running.handle, network, addr)
}

async fn mine_one_block(handle: &NodeHandle, miner_address: &str) -> Block {
    let template = handle
        .block_template(miner_address)
        .await
        .expect("block template")
        .block;
    let target = bits_to_target(template.header.bits);
    let mut header = template.header.clone();
    loop {
        header.nonce = header.nonce.wrapping_add(1);
        if hash_meets_target(&header.hash(), target) {
            break;
        }
    }
    let block = Block {
        header,
        transactions: template.transactions,
    };
    let result = handle.submit_block(block.clone()).await;
    assert!(
        result.accepted,
        "mined block should be accepted: {:?}",
        result.reason
    );
    block
}

async fn wait_for_tip(handle: &NodeHandle, expected_tip: Hash, timeout: Duration) {
    let start = tokio::time::Instant::now();
    loop {
        if handle.tip_info().await.tip == expected_tip {
            return;
        }
        if start.elapsed() > timeout {
            panic!("tip did not converge to {expected_tip} within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Scans every confirmed shielded bundle `handle` knows about, decrypting
/// with `ivk`. Returns (every commitment in canonical order, our own
/// unspent notes as (global position, note, value)) — the same logic
/// `aeon-wallet` uses, reimplemented here directly against `NodeHandle` to
/// keep this test self-contained.
async fn scan_shielded(
    handle: &NodeHandle,
    fvk: &aeon_shielded::orchard::keys::FullViewingKey,
) -> (Vec<[u8; 32]>, Vec<(u64, Note, u64)>) {
    let ivk = aeon_shielded::incoming_viewing_key(fvk);
    let bundles = handle.shielded_actions_since(0).await;

    let mut all_commitments = Vec::new();
    let mut all_nullifiers_seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();

    for info in &bundles {
        let base_position = all_commitments.len() as u64;
        for nf in info.bundle.nullifier_bytes() {
            all_nullifiers_seen.insert(nf);
        }
        for (action_index, note, _addr, _memo) in info.bundle.scan_for_incoming_notes(&ivk) {
            candidates.push((base_position + action_index as u64, note));
        }
        all_commitments.extend(info.bundle.note_commitment_bytes());
    }

    let unspent = candidates
        .into_iter()
        .filter(|(_, note)| !all_nullifiers_seen.contains(&note.nullifier(fvk).to_bytes()))
        .map(|(position, note)| (position, note, note.value().inner()))
        .collect();

    (all_commitments, unspent)
}

#[tokio::test]
async fn shield_private_send_and_deshield_propagate_between_two_nodes() {
    let (node_a, _network_a, addr_a) = start_node([11u8; 16]).await;
    let (node_b, _network_b, _addr_b) = start_node([12u8; 16]).await;
    _network_b
        .connect(addr_a)
        .await
        .expect("node B connects to node A");

    // Alice: transparent + shielded identity, both derived here directly
    // (rather than via aeon-wallet) to keep the test self-contained.
    let alice_transparent = KeyPair::generate();
    let alice_transparent_address = Address::from_pubkey(&alice_transparent.public_key());
    let alice_orchard_sk =
        aeon_shielded::orchard::keys::SpendingKey::from_bytes([7u8; 32]).unwrap();
    let alice_fvk = aeon_shielded::full_viewing_key(&alice_orchard_sk);
    let alice_shielded_address = aeon_shielded::default_address(&alice_orchard_sk);

    // Bob: shielded + transparent identity (receives the private send,
    // then deshields to his transparent address).
    let bob_orchard_sk = aeon_shielded::orchard::keys::SpendingKey::from_bytes([9u8; 32]).unwrap();
    let bob_fvk = aeon_shielded::full_viewing_key(&bob_orchard_sk);
    let bob_shielded_address = aeon_shielded::default_address(&bob_orchard_sk);
    let bob_transparent = KeyPair::generate();
    let bob_transparent_address = Address::from_pubkey(&bob_transparent.public_key());

    // A throwaway address for every *confirming* block after the first —
    // keeps its coinbase reward from masking whether Alice's/Bob's own
    // transparent balances actually changed the way each step intends.
    let confirmer = KeyPair::generate();
    let confirmer_address = Address::from_pubkey(&confirmer.public_key()).to_string();

    // 1. Mine a block paying Alice's transparent address.
    mine_one_block(&node_a, &alice_transparent_address.to_string()).await;
    let alice_balance = node_a
        .balance(&alice_transparent_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert!(alice_balance > 0);
    wait_for_tip(
        &node_b,
        node_a.tip_info().await.tip,
        Duration::from_secs(10),
    )
    .await;

    // 2. Shield: Alice moves her whole transparent balance into her own
    // shielded address.
    let shield_amount = alice_balance;
    let utxos = node_a
        .utxos(&alice_transparent_address.to_string())
        .await
        .unwrap();
    let inputs: Vec<TxInput> = utxos
        .iter()
        .map(|u| TxInput {
            prev_out: OutPoint {
                txid: u.txid,
                index: u.index,
            },
            pubkey: alice_transparent.public_key(),
            signature: alice_transparent.sign(b""),
        })
        .collect();

    println!("Building shielding proof...");
    let shielding_bundle =
        aeon_shielded::build_shielding_bundle(alice_shielded_address, shield_amount).unwrap();
    let mut shield_tx = Transaction {
        inputs,
        outputs: vec![],
        lock_time: 0,
        shielded: Some(shielding_bundle),
    };
    let sig = aeon_core::sign_input(&shield_tx, &alice_transparent);
    for input in &mut shield_tx.inputs {
        input.signature = sig.clone();
    }
    let result = node_a.submit_transaction(shield_tx).await;
    assert!(
        result.accepted,
        "shielding tx should be accepted: {:?}",
        result.reason
    );

    mine_one_block(&node_a, &confirmer_address).await;
    wait_for_tip(
        &node_b,
        node_a.tip_info().await.tip,
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(
        node_a
            .balance(&alice_transparent_address.to_string())
            .await
            .unwrap()
            .balance_quarks,
        0,
        "Alice's transparent balance should be fully shielded away"
    );

    let (commitments_after_shield, alice_notes) = scan_shielded(&node_a, &alice_fvk).await;
    assert_eq!(
        alice_notes.len(),
        1,
        "Alice should have exactly one shielded note now"
    );
    let (alice_note_position, alice_note, alice_note_value) = alice_notes[0];
    assert_eq!(alice_note_value, shield_amount);

    // 3. Private send: Alice sends half of it to Bob's shielded address,
    // with shielded change back to herself. Neither the amount nor either
    // address is visible on-chain.
    let send_amount = shield_amount / 2;
    let change_amount = alice_note_value - send_amount;

    let (anchor_bytes, merkle_path) =
        aeon_shielded::witness_for_position(&commitments_after_shield, alice_note_position)
            .unwrap();
    let anchor = Option::<aeon_shielded::orchard::Anchor>::from(
        aeon_shielded::orchard::Anchor::from_bytes(anchor_bytes),
    )
    .unwrap();

    println!("Building private-send proof...");
    let alice_spend_auth_key = SpendAuthorizingKey::from(&alice_orchard_sk);
    let send_bundle = aeon_shielded::build_spend_bundle(
        alice_fvk.clone(),
        &alice_spend_auth_key,
        alice_note,
        merkle_path,
        anchor,
        &[
            (bob_shielded_address, send_amount),
            (alice_shielded_address, change_amount),
        ],
    )
    .unwrap();

    let send_tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        shielded: Some(send_bundle),
    };
    let result = node_a.submit_transaction(send_tx).await;
    assert!(
        result.accepted,
        "private send should be accepted: {:?}",
        result.reason
    );

    mine_one_block(&node_a, &confirmer_address).await;
    wait_for_tip(
        &node_b,
        node_a.tip_info().await.tip,
        Duration::from_secs(10),
    )
    .await;

    let (commitments_after_send, bob_notes) = scan_shielded(&node_a, &bob_fvk).await;
    assert_eq!(
        bob_notes.len(),
        1,
        "Bob should have received exactly one private note"
    );
    let (bob_note_position, bob_note, bob_note_value) = bob_notes[0];
    assert_eq!(bob_note_value, send_amount);

    let (_, alice_notes_after_send) = scan_shielded(&node_a, &alice_fvk).await;
    assert_eq!(
        alice_notes_after_send.len(),
        1,
        "Alice's original note is spent; only her change note remains"
    );
    assert_eq!(alice_notes_after_send[0].2, change_amount);

    // Node B independently scanning the same (propagated) chain state
    // should reach identical conclusions.
    let (_, bob_notes_on_b) = scan_shielded(&node_b, &bob_fvk).await;
    assert_eq!(bob_notes_on_b.len(), 1);
    assert_eq!(bob_notes_on_b[0].2, send_amount);

    // 4. Deshield: Bob moves his private note back to a transparent
    // address of his own.
    let (anchor_bytes2, merkle_path2) =
        aeon_shielded::witness_for_position(&commitments_after_send, bob_note_position).unwrap();
    let anchor2 = Option::<aeon_shielded::orchard::Anchor>::from(
        aeon_shielded::orchard::Anchor::from_bytes(anchor_bytes2),
    )
    .unwrap();

    println!("Building deshielding proof...");
    let bob_spend_auth_key = SpendAuthorizingKey::from(&bob_orchard_sk);
    let deshield_bundle = aeon_shielded::build_spend_bundle(
        bob_fvk,
        &bob_spend_auth_key,
        bob_note,
        merkle_path2,
        anchor2,
        &[],
    )
    .unwrap();

    let deshield_tx = Transaction {
        inputs: vec![],
        outputs: vec![aeon_core::TxOutput {
            amount: bob_note_value,
            pubkey_hash: bob_transparent.public_key().pubkey_hash(),
        }],
        lock_time: 0,
        shielded: Some(deshield_bundle),
    };
    let result = node_a.submit_transaction(deshield_tx).await;
    assert!(
        result.accepted,
        "deshielding tx should be accepted: {:?}",
        result.reason
    );

    mine_one_block(&node_a, &confirmer_address).await;
    wait_for_tip(
        &node_b,
        node_a.tip_info().await.tip,
        Duration::from_secs(10),
    )
    .await;

    let bob_transparent_balance_a = node_a
        .balance(&bob_transparent_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    let bob_transparent_balance_b = node_b
        .balance(&bob_transparent_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert_eq!(bob_transparent_balance_a, send_amount);
    assert_eq!(bob_transparent_balance_b, send_amount);
}
