use std::str::FromStr;

use anyhow::{Context, Result};
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig};
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

const LOCALNET: &str = "http://127.0.0.1:8899";

// Simple TX
async fn send_sol(
    rpc_client: &RpcClient,
    from_keypair: &Keypair,
    to_pubkey: &Pubkey,
    amount_sol: f64,
) -> Result<String> {
    let amount_lamports = (amount_sol * 1_000_000_000.0) as u64;

    let recent_blockhash = rpc_client.get_latest_blockhash().await?;

    let transfer_instruction =
        system_instruction::transfer(&from_keypair.pubkey(), to_pubkey, amount_lamports);

    let transaction = Transaction::new_signed_with_payer(
        &[transfer_instruction],
        Some(&from_keypair.pubkey()),
        &[from_keypair],
        recent_blockhash,
    );

    let signature = rpc_client.send_transaction(&transaction).await?;

    println!("Transaction sent! Signature: {}", signature);

    Ok(signature.to_string())
}

pub async fn create_nonce_account(
    rpc: &RpcClient,
    payer: &Keypair,
    nonce: &Keypair,
    authority: &Keypair,
    lamports: u64,
) -> Result<()> {
    let init_nonce_ixs = system_instruction::create_nonce_account(
        &payer.pubkey(),
        &nonce.pubkey(),
        &authority.pubkey(),
        lamports,
    );

    let blockhash = rpc.get_latest_blockhash().await?;

    let transaction = Transaction::new_signed_with_payer(
        &init_nonce_ixs,
        Some(&payer.pubkey()),
        &[payer, nonce],
        blockhash,
    );

    let signature = rpc.send_and_confirm_transaction(&transaction).await?;
    println!("Created nonce account: {}", signature);

    Ok(())
}

pub async fn get_nonce_acc_data(
    client: &RpcClient,
    nonce_pubkey: &Pubkey,
) -> Result<solana_sdk::nonce::State> {
    let nonce_account = client
        .get_account(nonce_pubkey)
        .await
        .context("Failed to get nonce account")?;

    let state = bincode::deserialize(&nonce_account.data)
        .context("Failed to deserialize nonce account data")?;

    Ok(state)
}

pub async fn create_and_sign_nonce_transaction(
    wallet: &Keypair,
    nonce_pubkey: &Pubkey,
    nonce_authority: &Keypair,
    nonce_hash: String,
    instructions: Vec<Instruction>,
) -> Result<Transaction> {
    let advance_nonce_ix =
        system_instruction::advance_nonce_account(nonce_pubkey, &nonce_authority.pubkey());

    let mut all_instructions = vec![advance_nonce_ix];
    all_instructions.extend(instructions);

    let hash =
        solana_sdk::hash::Hash::from_str(&nonce_hash).context("Failed to parse nonce hash")?;

    let transaction = Transaction::new_signed_with_payer(
        &all_instructions,
        Some(&wallet.pubkey()),
        &[wallet, nonce_authority],
        hash,
    );

    Ok(transaction)
}

pub async fn send_to_multiple_providers(
    rpc_urls: Vec<String>,
    transaction: Transaction,
) -> Result<String> {
    use futures::future::join_all;

    let serialized_tx =
        bincode::serialize(&transaction).context("Failed to serialize transaction")?;

    async fn send_to_provider(url: String, tx_data: Vec<u8>) -> Result<(String, String)> {
        let client = RpcClient::new_with_commitment(url.clone(), CommitmentConfig::finalized());

        let tx: Transaction =
            bincode::deserialize(&tx_data).context("Failed to deserialize transaction")?;

        match client
            .send_transaction_with_config(
                &tx,
                RpcSendTransactionConfig {
                    skip_preflight: true, // CRITICAL for nonce transactions
                    preflight_commitment: Some(CommitmentLevel::Finalized),
                    encoding: None,
                    max_retries: None,
                    min_context_slot: None,
                },
            )
            .await
        {
            Ok(signature) => {
                println!("Transaction submitted to {}: {}", url, signature);
                Ok((url, signature.to_string()))
            }
            Err(e) => {
                println!("Error submitting to {}: {}", url, e);
                Err(anyhow::anyhow!("Transaction submission error: {}", e))
            }
        }
    }

    let futures = rpc_urls
        .into_iter()
        .map(|url| send_to_provider(url, serialized_tx.clone()));

    let results = join_all(futures).await;

    if let Some((provider, signature)) = results.into_iter().flatten().next() {
        return Ok(format!(
            "Transaction processed by {}: {}",
            provider, signature
        ));
    }

    Err(anyhow::anyhow!(
        "All providers failed to process the transaction"
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let rpc_client = RpcClient::new(LOCALNET.to_string());
    let sender = Keypair::new();
    let recipient = Keypair::new();

    tracing::info!("Sender: {:?}", sender.pubkey());

    let self_balance = rpc_client
        .get_balance(&sender.pubkey())
        .await
        .context("Failed to get sender balance")?;

    if self_balance < 1_000_000_000 {
        tracing::info!("Sender balance: {}", self_balance);
        tracing::info!("Sender balance is less than 1 SOL. Requesting airdrop...");

        let signature = rpc_client
            .request_airdrop(&sender.pubkey(), 3 * 1_000_000_000)
            .await
            .context("Failed to airdrop")?;

        tracing::info!("Airdrop requested: {:?}", signature);

        loop {
            let confirmed = rpc_client
                .confirm_transaction(&signature)
                .await
                .context("Failed to confirm airdrop")?;

            if confirmed {
                break;
            } else {
                tracing::info!("Waiting for airdrop confirmation...");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    match send_sol(&rpc_client, &sender, &recipient.pubkey(), 0.001).await {
        Ok(signature) => {
            println!("Success! Transaction signature: {}", signature);
        }
        Err(e) => {
            println!("Transaction failed: {}", e);
        }
    }

    let nonce_acc = Keypair::new();

    create_nonce_account(&rpc_client, &sender, &nonce_acc, &sender, 1_000_000_000)
        .await
        .unwrap();

    let nonce_data = get_nonce_acc_data(&rpc_client, &nonce_acc.pubkey())
        .await
        .context("Failed to get nonce account data")?;

    match nonce_data {
        solana_sdk::nonce::State::Uninitialized => {}
        solana_sdk::nonce::State::Initialized(ref data) => {
            tracing::info!("Nonce data: {nonce_data:?}");

            let nonce_hash = data.blockhash().to_string();
            println!("Current nonce: {}", nonce_hash);

            let transfer_ix =
                system_instruction::transfer(&sender.pubkey(), &Pubkey::new_unique(), 50_000_000);

            let signed_tx = create_and_sign_nonce_transaction(
                &sender,
                &nonce_acc.pubkey(),
                &sender,
                nonce_hash,
                vec![transfer_ix],
            )
            .await?;

            tracing::info!("Transaction created: {:?}", signed_tx);

            let rpc_urls = [LOCALNET, LOCALNET, LOCALNET]
                .iter()
                .map(|el| el.to_string())
                .collect::<Vec<_>>();

            let result = send_to_multiple_providers(rpc_urls, signed_tx).await?;
            println!("Result: {}", result);
        }
    }

    Ok(())
}
