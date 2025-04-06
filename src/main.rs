use std::str::FromStr;

use anyhow::{Context, Error, Result};
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig};
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
    transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;

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

    let signature = rpc
        .send_and_confirm_transaction_with_spinner_and_commitment(
            &transaction,
            CommitmentConfig {
                commitment: CommitmentLevel::Finalized,
            },
        )
        .await?;
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
) -> Result<Vec<Result<(String, String), Error>>> {
    use futures::future::join_all;

    let serialized_tx =
        bincode::serialize(&transaction).context("Failed to serialize transaction")?;

    async fn send_to_provider(url: String, tx_data: Vec<u8>) -> Result<(String, String)> {
        let client = RpcClient::new_with_commitment(url.clone(), CommitmentConfig::finalized());

        let tx: Transaction =
            bincode::deserialize(&tx_data).context("Failed to deserialize transaction")?;

        match client.simulate_transaction(&tx).await {
            Ok(sim_result) => {
                if let Some(err) = sim_result.value.err {
                    tracing::warn!("Transaction simulation error: {:?}", err);
                    tracing::warn!("Logs: {:?}", sim_result.value.logs);
                } else {
                    tracing::info!("Transaction simulation successful");
                }
            }
            Err(e) => {
                tracing::warn!("Failed to simulate transaction: {}", e);
            }
        }

        match client
            .send_transaction_with_config(
                &tx,
                RpcSendTransactionConfig {
                    skip_preflight: true, // CRITICAL for nonce transactions
                    preflight_commitment: Some(CommitmentLevel::Finalized),
                    encoding: None,
                    max_retries: Some(5),
                    min_context_slot: None,
                },
            )
            .await
        {
            Ok(signature) => {
                tracing::info!("Transaction submitted to {}: {}", url, signature);
                Ok((url, signature.to_string()))
            }
            Err(e) => {
                tracing::error!("Error submitting to {}: {:?}", url, e);
                Err(anyhow::anyhow!("Transaction submission error: {}", e))
            }
        }
    }

    let futures = rpc_urls
        .into_iter()
        .map(|url| send_to_provider(url, serialized_tx.clone()));

    let results = join_all(futures).await;

    Ok(results)
}

pub async fn monitor_transaction_status(
    client: &RpcClient,
    signature: &Signature,
    max_attempts: usize,
) -> Result<()> {
    let mut attempts = 0;

    while attempts < max_attempts {
        match client.get_signature_status(signature).await {
            Ok(Some(status)) => {
                if let Err(err) = status {
                    tracing::error!("Transaction failed: {:?}", err);
                    return Err(anyhow::anyhow!("Transaction failed: {:?}", err));
                } else {
                    tracing::info!("Transaction succeeded!");

                    if let Ok(tx_details) = client
                        .get_transaction(signature, UiTransactionEncoding::Json)
                        .await
                    {
                        tracing::info!(
                            "Transaction details: meta.err={:?}, meta.log_messages={:?}",
                            tx_details
                                .transaction
                                .meta
                                .as_ref()
                                .and_then(|m| m.err.clone()),
                            tx_details
                                .transaction
                                .meta
                                .as_ref()
                                .map(|m| &m.log_messages)
                        );
                    }

                    return Ok(());
                }
            }
            Ok(None) => {
                tracing::info!("Transaction status: pending (attempt {})", attempts + 1);
            }
            Err(e) => {
                tracing::warn!("Failed to get transaction status: {}", e);
            }
        }

        attempts += 1;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    Err(anyhow::anyhow!("Transaction status check timed out"))
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

            let first_rpc_url = LOCALNET.to_string();
            let client = RpcClient::new_with_commitment(
                first_rpc_url.clone(),
                CommitmentConfig::finalized(),
            );

            let signed_tx = create_and_sign_nonce_transaction(
                &sender,
                &nonce_acc.pubkey(),
                &sender,
                nonce_hash,
                vec![transfer_ix],
            )
            .await?;

            tracing::info!("Transaction created: {:?}", signed_tx);

            for (i, instruction) in signed_tx.message.instructions.iter().enumerate() {
                tracing::info!(
                    "Instruction {}: program_id_index={}, accounts={:?}, data_len={}",
                    i,
                    instruction.program_id_index,
                    instruction.accounts,
                    instruction.data.len()
                );
            }

            match client
                .send_transaction_with_config(
                    &signed_tx,
                    RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: Some(CommitmentLevel::Finalized),
                        encoding: None,
                        max_retries: Some(5),
                        min_context_slot: None,
                    },
                )
                .await
            {
                Ok(signature) => {
                    tracing::info!("Transaction submitted successfully: {}", signature);

                    let sig = Signature::from_str(&signature.to_string())?;
                    if let Err(e) = monitor_transaction_status(&client, &sig, 10).await {
                        tracing::error!("Transaction monitoring error: {}", e);
                    }

                    let nonce_data_after_first =
                        get_nonce_acc_data(&client, &nonce_acc.pubkey()).await?;
                    tracing::info!(
                        "Nonce data after first transaction: {:?}",
                        nonce_data_after_first
                    );

                    if (client.get_signature_status(&sig).await).is_ok() {
                        tracing::info!("Attempting to send the same transaction again");
                        match client
                            .send_transaction_with_config(
                                &signed_tx,
                                RpcSendTransactionConfig {
                                    skip_preflight: true, // CRITICAL for nonce transactions
                                    preflight_commitment: Some(CommitmentLevel::Finalized),
                                    encoding: None,
                                    max_retries: Some(5),
                                    min_context_slot: None,
                                },
                            )
                            .await
                        {
                            Ok(sig2) => {
                                tracing::warn!(
                                    "Second transaction went through! This shouldn't happen: {}",
                                    sig2
                                );

                                let nonce_data_after_second =
                                    get_nonce_acc_data(&client, &nonce_acc.pubkey()).await?;
                                tracing::info!(
                                    "Nonce data after second transaction: {:?}",
                                    nonce_data_after_second
                                );
                            }
                            Err(e) => {
                                tracing::info!("Second transaction failed as expected: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to send transaction: {:?}", e);
                }
            }
        }
    }

    Ok(())
}
