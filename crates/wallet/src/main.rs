use std::collections::HashSet;
use std::path::Path;

use aeon_core::{sign_input, OutPoint, Transaction, TxInput, TxOutput};
use aeon_crypto::{Address, KeyPair, Keystore};
use aeon_rpc::RpcClient;
use aeon_shielded::orchard::keys::FullViewingKey;
use aeon_shielded::orchard::note::Note;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Aeon CLI wallet.
#[derive(Parser, Debug)]
#[command(name = "aeon-wallet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new wallet: a fresh 12-word BIP39 mnemonic, encrypted
    /// with a password you choose. Derives both a transparent (`aeon1...`)
    /// and a shielded (`aeonz1...`) address from the same mnemonic.
    Create {
        /// Path to write the new wallet file to.
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
    },
    /// Print the wallet's transparent and shielded addresses (does not
    /// require the password).
    Address {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
    },
    /// Query the wallet's transparent balance from a node.
    Balance {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
    },
    /// Build, sign and broadcast a transparent transaction sending AEON to
    /// another address.
    Send {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
        /// Recipient's transparent Aeon address (aeon1...).
        #[arg(long)]
        to: String,
        /// Amount in AEON, e.g. "12.5".
        #[arg(long)]
        amount: String,
    },
    /// Move AEON from this wallet's transparent balance into its own
    /// shielded balance. Building the zk-SNARK proof takes real time
    /// (seconds, not milliseconds) — see docs/PRIVACY.md.
    Shield {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
        #[arg(long)]
        amount: String,
    },
    /// Query the wallet's shielded balance by scanning the chain locally
    /// with its own viewing key (see docs/PRIVACY.md — the node never sees
    /// this key). Slower than `balance`: it rescans every confirmed
    /// shielded action from genesis each time.
    ShieldedBalance {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
    },
    /// Send AEON privately from this wallet's shielded balance to another
    /// shielded address. Both the amount and both addresses stay hidden
    /// on-chain. Builds a real zk-SNARK proof (seconds, not milliseconds).
    SendShielded {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
        /// Recipient's shielded Aeon address (aeonz1...).
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    /// Move AEON from this wallet's shielded balance back into a
    /// transparent address (its own, by default).
    Deshield {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
        /// Transparent recipient; defaults to this wallet's own transparent
        /// address if omitted.
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        amount: String,
    },
}

#[derive(Serialize, Deserialize)]
struct WalletFile {
    address: String,
    shielded_address: String,
    keystore: Keystore,
}

/// This wallet's unlocked keys: the transparent keypair and the Orchard
/// spending key, both derived from the same 64-byte seed.
struct Unlocked {
    transparent: KeyPair,
    orchard_sk: aeon_shielded::orchard::keys::SpendingKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Create { wallet } => cmd_create(&wallet),
        Commands::Address { wallet } => cmd_address(&wallet),
        Commands::Balance { wallet, node } => cmd_balance(&wallet, &node).await,
        Commands::Send {
            wallet,
            node,
            to,
            amount,
        } => cmd_send(&wallet, &node, &to, &amount).await,
        Commands::Shield {
            wallet,
            node,
            amount,
        } => cmd_shield(&wallet, &node, &amount).await,
        Commands::ShieldedBalance { wallet, node } => cmd_shielded_balance(&wallet, &node).await,
        Commands::SendShielded {
            wallet,
            node,
            to,
            amount,
        } => cmd_send_shielded(&wallet, &node, &to, &amount).await,
        Commands::Deshield {
            wallet,
            node,
            to,
            amount,
        } => cmd_deshield(&wallet, &node, to, &amount).await,
    }
}

fn cmd_create(wallet_path: &str) -> anyhow::Result<()> {
    if Path::new(wallet_path).exists() {
        anyhow::bail!("'{wallet_path}' already exists; refusing to overwrite an existing wallet");
    }

    let mnemonic = aeon_crypto::generate_mnemonic();
    println!("Your 12-word recovery phrase (write it down and keep it secret and safe):\n");
    println!("    {mnemonic}\n");
    println!(
        "Anyone who has these words can spend your AEON. Aeon cannot recover a lost phrase.\n"
    );

    let password = prompt_new_password()?;
    let seed64 = mnemonic.to_seed("");

    let transparent_kp = KeyPair::from_seed_bytes(&aeon_crypto::seed64_to_key_material(&seed64))?;
    let address = Address::from_pubkey(&transparent_kp.public_key());

    let orchard_sk = aeon_shielded::derive_spending_key_from_seed(&seed64);
    let shielded_address =
        aeon_shielded::encode_address(&aeon_shielded::default_address(&orchard_sk));

    let keystore = Keystore::encrypt(&seed64, &password);

    let file = WalletFile {
        address: address.to_string(),
        shielded_address: shielded_address.clone(),
        keystore,
    };
    std::fs::write(wallet_path, serde_json::to_string_pretty(&file)?)?;

    println!("Wallet written to '{wallet_path}'.");
    println!("Transparent address: {address}");
    println!("Shielded address:    {shielded_address}");
    Ok(())
}

fn cmd_address(wallet_path: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    println!("Transparent address: {}", file.address);
    println!("Shielded address:    {}", file.shielded_address);
    Ok(())
}

async fn cmd_balance(wallet_path: &str, node: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let client = RpcClient::new(node.to_string());
    let info = client.balance(&file.address).await?;
    println!("{} AEON (transparent)", format_quarks(info.balance_quarks));
    Ok(())
}

async fn cmd_send(wallet_path: &str, node: &str, to: &str, amount: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let unlocked = unlock(&file)?;
    let keypair = unlocked.transparent;

    let amount_quarks = parse_aeon_amount(amount)?;
    let recipient_pubkey_hash =
        Address::decode(to).map_err(|e| anyhow::anyhow!("invalid recipient address: {e}"))?;

    let client = RpcClient::new(node.to_string());
    let (inputs, change) =
        select_transparent_inputs(&client, &file.address, &keypair, amount_quarks).await?;

    let mut outputs = vec![TxOutput {
        amount: amount_quarks,
        pubkey_hash: recipient_pubkey_hash,
    }];
    if change > 0 {
        outputs.push(TxOutput {
            amount: change,
            pubkey_hash: keypair.public_key().pubkey_hash(),
        });
    }

    let mut tx = Transaction {
        inputs,
        outputs,
        lock_time: 0,
        shielded: None,
    };
    sign_transparent_inputs(&mut tx, &keypair);

    submit_and_report(
        &client,
        tx,
        &format!("Sent {} AEON to {to}", format_quarks(amount_quarks)),
    )
    .await
}

async fn cmd_shield(wallet_path: &str, node: &str, amount: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let unlocked = unlock(&file)?;
    let keypair = unlocked.transparent;

    let amount_quarks = parse_aeon_amount(amount)?;
    let own_shielded_address = aeon_shielded::decode_address(&file.shielded_address)
        .map_err(|e| anyhow::anyhow!("corrupt wallet: {e}"))?;

    let client = RpcClient::new(node.to_string());
    let (inputs, change) =
        select_transparent_inputs(&client, &file.address, &keypair, amount_quarks).await?;

    let mut outputs = Vec::new();
    if change > 0 {
        outputs.push(TxOutput {
            amount: change,
            pubkey_hash: keypair.public_key().pubkey_hash(),
        });
    }

    println!("Building the shielding proof (this takes real time, typically several seconds)...");
    let bundle = aeon_shielded::build_shielding_bundle(own_shielded_address, amount_quarks)
        .map_err(|e| anyhow::anyhow!("failed to build shielded bundle: {e}"))?;

    let mut tx = Transaction {
        inputs,
        outputs,
        lock_time: 0,
        shielded: Some(bundle),
    };
    sign_transparent_inputs(&mut tx, &keypair);

    submit_and_report(
        &client,
        tx,
        &format!(
            "Shielded {} AEON into your own shielded balance",
            format_quarks(amount_quarks)
        ),
    )
    .await
}

async fn cmd_shielded_balance(wallet_path: &str, node: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let unlocked = unlock(&file)?;
    let fvk = aeon_shielded::full_viewing_key(&unlocked.orchard_sk);

    let client = RpcClient::new(node.to_string());
    println!("Scanning the shielded pool locally (no key ever leaves this machine)...");
    let scan = scan_shielded_notes(&client, &fvk).await?;

    let total: u64 = scan.spendable.iter().map(|n| n.value_quarks).sum();
    println!(
        "{} AEON (shielded, {} spendable note(s))",
        format_quarks(total),
        scan.spendable.len()
    );
    Ok(())
}

async fn cmd_send_shielded(
    wallet_path: &str,
    node: &str,
    to: &str,
    amount: &str,
) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let unlocked = unlock(&file)?;
    let amount_quarks = parse_aeon_amount(amount)?;
    let recipient = aeon_shielded::decode_address(to)
        .map_err(|e| anyhow::anyhow!("invalid shielded recipient address: {e}"))?;
    let own_shielded_address = aeon_shielded::decode_address(&file.shielded_address)
        .map_err(|e| anyhow::anyhow!("corrupt wallet: {e}"))?;

    let client = RpcClient::new(node.to_string());
    let fvk = aeon_shielded::full_viewing_key(&unlocked.orchard_sk);
    println!("Scanning the shielded pool locally for a spendable note...");
    let scan = scan_shielded_notes(&client, &fvk).await?;

    let chosen = scan
        .spendable
        .into_iter()
        .filter(|n| n.value_quarks >= amount_quarks)
        .min_by_key(|n| n.value_quarks)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no single shielded note covers {} AEON (this simplified wallet doesn't combine multiple notes yet)",
                format_quarks(amount_quarks)
            )
        })?;

    let (anchor_bytes, merkle_path) =
        aeon_shielded::witness_for_position(&scan.all_commitments, chosen.position)
            .map_err(|e| anyhow::anyhow!("failed to build a spend witness: {e}"))?;
    let anchor = Option::<aeon_shielded::orchard::Anchor>::from(
        aeon_shielded::orchard::Anchor::from_bytes(anchor_bytes),
    )
    .ok_or_else(|| anyhow::anyhow!("invalid anchor"))?;

    let change = chosen.value_quarks - amount_quarks;
    let mut outputs = vec![(recipient, amount_quarks)];
    if change > 0 {
        outputs.push((own_shielded_address, change));
    }

    println!(
        "Building the private-send proof (this takes real time, typically several seconds)..."
    );
    let spend_auth_key =
        aeon_shielded::orchard::keys::SpendAuthorizingKey::from(&unlocked.orchard_sk);
    let bundle = aeon_shielded::build_spend_bundle(
        aeon_shielded::full_viewing_key(&unlocked.orchard_sk),
        &spend_auth_key,
        chosen.note,
        merkle_path,
        anchor,
        &outputs,
    )
    .map_err(|e| anyhow::anyhow!("failed to build shielded spend: {e}"))?;

    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        shielded: Some(bundle),
    };
    submit_and_report(
        &client,
        tx,
        &format!(
            "Sent {} AEON privately to {to}",
            format_quarks(amount_quarks)
        ),
    )
    .await
}

async fn cmd_deshield(
    wallet_path: &str,
    node: &str,
    to: Option<String>,
    amount: &str,
) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let unlocked = unlock(&file)?;
    let amount_quarks = parse_aeon_amount(amount)?;
    let to = to.unwrap_or_else(|| file.address.clone());
    let recipient_pubkey_hash = Address::decode(&to)
        .map_err(|e| anyhow::anyhow!("invalid transparent recipient address: {e}"))?;
    let own_shielded_address = aeon_shielded::decode_address(&file.shielded_address)
        .map_err(|e| anyhow::anyhow!("corrupt wallet: {e}"))?;

    let client = RpcClient::new(node.to_string());
    let fvk = aeon_shielded::full_viewing_key(&unlocked.orchard_sk);
    println!("Scanning the shielded pool locally for a spendable note...");
    let scan = scan_shielded_notes(&client, &fvk).await?;

    let chosen = scan
        .spendable
        .into_iter()
        .filter(|n| n.value_quarks >= amount_quarks)
        .min_by_key(|n| n.value_quarks)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no single shielded note covers {} AEON (this simplified wallet doesn't combine multiple notes yet)",
                format_quarks(amount_quarks)
            )
        })?;

    let (anchor_bytes, merkle_path) =
        aeon_shielded::witness_for_position(&scan.all_commitments, chosen.position)
            .map_err(|e| anyhow::anyhow!("failed to build a spend witness: {e}"))?;
    let anchor = Option::<aeon_shielded::orchard::Anchor>::from(
        aeon_shielded::orchard::Anchor::from_bytes(anchor_bytes),
    )
    .ok_or_else(|| anyhow::anyhow!("invalid anchor"))?;

    let change = chosen.value_quarks - amount_quarks;
    let mut outputs = Vec::new();
    if change > 0 {
        outputs.push((own_shielded_address, change));
    }

    println!("Building the deshielding proof (this takes real time, typically several seconds)...");
    let spend_auth_key =
        aeon_shielded::orchard::keys::SpendAuthorizingKey::from(&unlocked.orchard_sk);
    let bundle = aeon_shielded::build_spend_bundle(
        aeon_shielded::full_viewing_key(&unlocked.orchard_sk),
        &spend_auth_key,
        chosen.note,
        merkle_path,
        anchor,
        &outputs,
    )
    .map_err(|e| anyhow::anyhow!("failed to build shielded spend: {e}"))?;

    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TxOutput {
            amount: amount_quarks,
            pubkey_hash: recipient_pubkey_hash,
        }],
        lock_time: 0,
        shielded: Some(bundle),
    };
    submit_and_report(
        &client,
        tx,
        &format!("Deshielded {} AEON to {to}", format_quarks(amount_quarks)),
    )
    .await
}

// ---- shared helpers -----------------------------------------------------

fn unlock(file: &WalletFile) -> anyhow::Result<Unlocked> {
    let password = rpassword::prompt_password("Wallet password: ")?;
    let seed64_vec = file
        .keystore
        .decrypt(&password)
        .map_err(|_| anyhow::anyhow!("wrong password, or the wallet file is corrupted"))?;
    let seed64: [u8; 64] = seed64_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("wallet file is corrupted (unexpected seed length)"))?;

    let transparent = KeyPair::from_seed_bytes(&aeon_crypto::seed64_to_key_material(&seed64))?;
    let derived_address = Address::from_pubkey(&transparent.public_key());
    if derived_address.to_string() != file.address {
        anyhow::bail!(
            "wallet file is corrupted: stored transparent address does not match the decrypted key"
        );
    }

    let orchard_sk = aeon_shielded::derive_spending_key_from_seed(&seed64);
    let derived_shielded =
        aeon_shielded::encode_address(&aeon_shielded::default_address(&orchard_sk));
    if derived_shielded != file.shielded_address {
        anyhow::bail!(
            "wallet file is corrupted: stored shielded address does not match the decrypted key"
        );
    }

    Ok(Unlocked {
        transparent,
        orchard_sk,
    })
}

/// Selects enough of this address's transparent UTXOs to cover
/// `amount_quarks`, returning the signed-ready (placeholder-signature)
/// inputs and the leftover change.
async fn select_transparent_inputs(
    client: &RpcClient,
    address: &str,
    keypair: &KeyPair,
    amount_quarks: u64,
) -> anyhow::Result<(Vec<TxInput>, u64)> {
    let utxos = client.utxos(address).await?;
    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for utxo in utxos {
        if total >= amount_quarks {
            break;
        }
        total = total.saturating_add(utxo.amount_quarks);
        selected.push(utxo);
    }
    if total < amount_quarks {
        anyhow::bail!(
            "insufficient transparent balance: have {} AEON, need {} AEON",
            format_quarks(total),
            format_quarks(amount_quarks)
        );
    }
    let change = total - amount_quarks;

    let inputs = selected
        .iter()
        .map(|utxo| TxInput {
            prev_out: OutPoint {
                txid: utxo.txid,
                index: utxo.index,
            },
            pubkey: keypair.public_key(),
            // Placeholder; every input shares the same whole-transaction
            // signature, filled in by `sign_transparent_inputs` once the
            // transaction's outputs/shielded bundle are finalized.
            signature: keypair.sign(b""),
        })
        .collect();
    Ok((inputs, change))
}

fn sign_transparent_inputs(tx: &mut Transaction, keypair: &KeyPair) {
    if tx.inputs.is_empty() {
        return;
    }
    let signature = sign_input(tx, keypair);
    for input in &mut tx.inputs {
        input.signature = signature.clone();
    }
}

async fn submit_and_report(
    client: &RpcClient,
    tx: Transaction,
    success_message: &str,
) -> anyhow::Result<()> {
    let txid = tx.txid();
    let result = client.submit_transaction(tx).await?;
    if result.accepted {
        println!("{success_message}");
        println!("txid: {txid}");
        Ok(())
    } else {
        anyhow::bail!(
            "node rejected the transaction: {}",
            result.reason.unwrap_or_default()
        )
    }
}

struct SpendableNote {
    position: u64,
    note: Note,
    value_quarks: u64,
}

struct ShieldedScan {
    /// Every note commitment ever confirmed, in canonical order — needed to
    /// rebuild a Merkle witness for spending one of our own notes.
    all_commitments: Vec<[u8; 32]>,
    /// Our own notes that haven't been spent yet.
    spendable: Vec<SpendableNote>,
}

/// Scans every confirmed shielded bundle from genesis: decrypts each
/// action with `fvk`'s incoming viewing key to find notes addressed to us,
/// and separately tracks every nullifier ever seen so we can tell which of
/// our own notes are still unspent. See `docs/PRIVACY.md` for why this is
/// a full local rescan rather than an incremental/cached one.
async fn scan_shielded_notes(
    client: &RpcClient,
    fvk: &FullViewingKey,
) -> anyhow::Result<ShieldedScan> {
    let ivk = aeon_shielded::incoming_viewing_key(fvk);
    let bundles = client.shielded_actions_since(0).await?;

    let mut all_commitments: Vec<[u8; 32]> = Vec::new();
    let mut all_nullifiers_seen: HashSet<[u8; 32]> = HashSet::new();
    let mut candidates: Vec<(u64, Note)> = Vec::new();

    for info in &bundles {
        let base_position = all_commitments.len() as u64;
        for nf in info.bundle.nullifier_bytes() {
            all_nullifiers_seen.insert(nf);
        }
        for (action_index, note, _address, _memo) in info.bundle.scan_for_incoming_notes(&ivk) {
            candidates.push((base_position + action_index as u64, note));
        }
        all_commitments.extend(info.bundle.note_commitment_bytes());
    }

    let spendable = candidates
        .into_iter()
        .filter(|(_, note)| !all_nullifiers_seen.contains(&note.nullifier(fvk).to_bytes()))
        .map(|(position, note)| SpendableNote {
            position,
            note,
            value_quarks: note.value().inner(),
        })
        .collect();

    Ok(ShieldedScan {
        all_commitments,
        spendable,
    })
}

fn load_wallet(path: &str) -> anyhow::Result<WalletFile> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read wallet file '{path}': {e}"))?;
    Ok(serde_json::from_str(&data)?)
}

fn prompt_new_password() -> anyhow::Result<String> {
    let password = rpassword::prompt_password("Choose a wallet password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("passwords did not match");
    }
    if password.is_empty() {
        anyhow::bail!("password must not be empty");
    }
    Ok(password)
}

fn format_quarks(quarks: u64) -> String {
    format!(
        "{}.{:08}",
        quarks / aeon_core::QUARKS_PER_AEON,
        quarks % aeon_core::QUARKS_PER_AEON
    )
}

fn parse_aeon_amount(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 8 {
        anyhow::bail!("amount has more than 8 decimal places");
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid amount '{s}'"))?;
    let mut frac_digits = frac.to_string();
    while frac_digits.len() < 8 {
        frac_digits.push('0');
    }
    let frac_value: u64 = if frac_digits.is_empty() {
        0
    } else {
        frac_digits
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid amount '{s}'"))?
    };
    whole
        .checked_mul(aeon_core::QUARKS_PER_AEON)
        .and_then(|w| w.checked_add(frac_value))
        .ok_or_else(|| anyhow::anyhow!("amount is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_fractional_amounts() {
        assert_eq!(
            parse_aeon_amount("5").unwrap(),
            5 * aeon_core::QUARKS_PER_AEON
        );
        assert_eq!(parse_aeon_amount("0.1").unwrap(), 10_000_000);
        assert_eq!(parse_aeon_amount("12.00000001").unwrap(), 1_200_000_001);
    }

    #[test]
    fn rejects_too_many_decimals() {
        assert!(parse_aeon_amount("1.123456789").is_err());
    }

    #[test]
    fn formats_quarks_back_to_decimal() {
        assert_eq!(format_quarks(1_200_000_001), "12.00000001");
        assert_eq!(format_quarks(500_000_000), "5.00000000");
    }
}
