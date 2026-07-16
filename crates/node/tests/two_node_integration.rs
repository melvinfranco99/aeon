//! End-to-end test: two nodes on loopback TCP, connected over Aeon's P2P
//! protocol. One mines blocks (funding a wallet), sends AEON to a second
//! wallet, mines a confirming block, and both nodes' views of the ledger
//! are checked to agree. This rehearses, in automated form, exactly the
//! manual workflow described in `docs/GETTING_STARTED.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aeon_core::{
    bits_to_target, hash_meets_target, sign_input, Block, GhostdagParams, OutPoint, Transaction,
    TxInput, TxOutput,
};
use aeon_crypto::{Address, Hash, KeyPair};
use aeon_network::Network;
use aeon_node::{genesis_block, spawn_node, NodeHandle};
use aeon_rpc::RpcBackend;
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

/// Mines a single block on `handle` by fetching a template and brute-forcing
/// a nonce against its (very easy, testnet-level) target.
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

/// Polls `handle`'s tip until it matches `expected_tip` (i.e. until a block
/// mined elsewhere has propagated over P2P and been accepted here), or
/// panics after `timeout`.
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

#[tokio::test]
async fn mining_and_a_transaction_propagate_between_two_nodes() {
    let (node_a, _network_a, addr_a) = start_node([1u8; 16]).await;
    let (node_b, _network_b, _addr_b) = start_node([2u8; 16]).await;
    _network_b
        .connect(addr_a)
        .await
        .expect("node B connects to node A");

    let alice = KeyPair::generate();
    let alice_address = Address::from_pubkey(&alice.public_key());
    let bob = KeyPair::generate();
    let bob_address = Address::from_pubkey(&bob.public_key());

    // Mine a block on node A, paying Alice the block reward.
    mine_one_block(&node_a, &alice_address.to_string()).await;

    let alice_balance = node_a
        .balance(&alice_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert!(
        alice_balance > 0,
        "Alice should have been paid a block reward"
    );

    // Node B should learn about the new tip via P2P without any manual
    // intervention.
    let tip_a = node_a.tip_info().await.tip;
    wait_for_tip(&node_b, tip_a, Duration::from_secs(10)).await;

    let bob_balance_before = node_b
        .balance(&bob_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert_eq!(bob_balance_before, 0);

    // Alice sends half her balance to Bob. Built by hand here (rather than
    // via `aeon-wallet`) to keep the test self-contained, but this is
    // exactly what the wallet's `send` command does internally.
    let utxos = node_a.utxos(&alice_address.to_string()).await.unwrap();
    let send_amount = alice_balance / 2;
    let mut inputs = Vec::new();
    let mut total_in = 0u64;
    for utxo in utxos {
        inputs.push(TxInput {
            prev_out: OutPoint {
                txid: utxo.txid,
                index: utxo.index,
            },
            pubkey: alice.public_key(),
            signature: alice.sign(b""),
        });
        total_in += utxo.amount_quarks;
    }
    let change = total_in - send_amount;
    let mut tx = Transaction {
        inputs,
        outputs: vec![
            TxOutput {
                amount: send_amount,
                pubkey_hash: bob.public_key().pubkey_hash(),
            },
            TxOutput {
                amount: change,
                pubkey_hash: alice.public_key().pubkey_hash(),
            },
        ],
        lock_time: 0,
        shielded: None,
    };
    let signature = sign_input(&tx, &alice);
    for input in &mut tx.inputs {
        input.signature = signature.clone();
    }

    let submit_result = node_a.submit_transaction(tx).await;
    assert!(
        submit_result.accepted,
        "transaction should be accepted: {:?}",
        submit_result.reason
    );

    // The transaction only takes effect once it's mined into a block.
    let miner2 = KeyPair::generate();
    let miner2_address = Address::from_pubkey(&miner2.public_key());
    mine_one_block(&node_a, &miner2_address.to_string()).await;

    let tip_a2 = node_a.tip_info().await.tip;
    wait_for_tip(&node_b, tip_a2, Duration::from_secs(10)).await;

    // Both nodes should now agree that Bob has funds and Alice's spent
    // output is gone.
    let bob_balance_a = node_a
        .balance(&bob_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    let bob_balance_b = node_b
        .balance(&bob_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert_eq!(bob_balance_a, send_amount);
    assert_eq!(bob_balance_b, send_amount);

    let alice_balance_after_a = node_a
        .balance(&alice_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    let alice_balance_after_b = node_b
        .balance(&alice_address.to_string())
        .await
        .unwrap()
        .balance_quarks;
    assert_eq!(alice_balance_after_a, change);
    assert_eq!(alice_balance_after_b, change);
}
