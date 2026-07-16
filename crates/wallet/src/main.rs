use std::path::Path;

use aeon_core::{sign_input, OutPoint, Transaction, TxInput, TxOutput};
use aeon_crypto::{Address, KeyPair, Keystore};
use aeon_rpc::RpcClient;
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
    /// with a password you choose.
    Create {
        /// Path to write the new wallet file to.
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
    },
    /// Print the wallet's Aeon address (does not require the password).
    Address {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
    },
    /// Query the wallet's balance from a node.
    Balance {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
    },
    /// Build, sign and broadcast a transaction sending AEON to another
    /// address.
    Send {
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:16111")]
        node: String,
        /// Recipient's Aeon address (aeon1...).
        #[arg(long)]
        to: String,
        /// Amount in AEON, e.g. "12.5".
        #[arg(long)]
        amount: String,
    },
}

#[derive(Serialize, Deserialize)]
struct WalletFile {
    address: String,
    keystore: Keystore,
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
    let seed = aeon_crypto::seed_to_key_material(&mnemonic, "");
    let keypair = KeyPair::from_seed_bytes(&seed)?;
    let address = Address::from_pubkey(&keypair.public_key());
    let keystore = Keystore::encrypt(&seed, &password);

    let file = WalletFile {
        address: address.to_string(),
        keystore,
    };
    std::fs::write(wallet_path, serde_json::to_string_pretty(&file)?)?;

    println!("Wallet written to '{wallet_path}'.");
    println!("Address: {address}");
    Ok(())
}

fn cmd_address(wallet_path: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    println!("{}", file.address);
    Ok(())
}

async fn cmd_balance(wallet_path: &str, node: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let client = RpcClient::new(node.to_string());
    let info = client.balance(&file.address).await?;
    println!("{} AEON", format_quarks(info.balance_quarks));
    Ok(())
}

async fn cmd_send(wallet_path: &str, node: &str, to: &str, amount: &str) -> anyhow::Result<()> {
    let file = load_wallet(wallet_path)?;
    let password = rpassword::prompt_password("Wallet password: ")?;
    let seed = file
        .keystore
        .decrypt(&password)
        .map_err(|_| anyhow::anyhow!("wrong password, or the wallet file is corrupted"))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("wallet file is corrupted (unexpected seed length)"))?;
    let keypair = KeyPair::from_seed_bytes(&seed)?;

    let derived_address = Address::from_pubkey(&keypair.public_key());
    if derived_address.to_string() != file.address {
        anyhow::bail!("wallet file is corrupted: stored address does not match the decrypted key");
    }

    let amount_quarks = parse_aeon_amount(amount)?;
    let recipient_pubkey_hash =
        Address::decode(to).map_err(|e| anyhow::anyhow!("invalid recipient address: {e}"))?;

    let client = RpcClient::new(node.to_string());
    let utxos = client.utxos(&file.address).await?;

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
            "insufficient balance: have {} AEON, need {} AEON",
            format_quarks(total),
            format_quarks(amount_quarks)
        );
    }
    let change = total - amount_quarks;

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|utxo| TxInput {
            prev_out: OutPoint {
                txid: utxo.txid,
                index: utxo.index,
            },
            pubkey: keypair.public_key(),
            // Placeholder; every input shares the same whole-transaction
            // signature, filled in below once `outputs` is finalized.
            signature: keypair.sign(b""),
        })
        .collect();

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
    };
    let signature = sign_input(&tx, &keypair);
    for input in &mut tx.inputs {
        input.signature = signature.clone();
    }

    let txid = tx.txid();
    let result = client.submit_transaction(tx).await?;
    if result.accepted {
        println!("Sent {} AEON to {to}", format_quarks(amount_quarks));
        println!("txid: {txid}");
    } else {
        anyhow::bail!(
            "node rejected the transaction: {}",
            result.reason.unwrap_or_default()
        );
    }
    Ok(())
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
