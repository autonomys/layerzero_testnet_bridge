extern crate core;

use cita_trie::MemoryDB;
use cita_trie::{PatriciaTrie, Trie};
use ethers::abi::{Token, Uint};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::core::types::Filter;
use ethers::prelude::{Http, LocalWallet, ProviderExt, SignerMiddleware, U64};
use ethers::providers::{Middleware, Provider};
use ethers::signers::Signer;
use ethers::types::{BlockNumber, Bytes, H160, H256, U256};
use ethers::utils::keccak256;
use eyre::Result;
use hasher::HasherKeccak;
use std::cmp::min;
use std::fmt;
use std::fmt::Formatter;

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

const RANGE: u64 = 10;
const SRC_CHAIN_ID: u16 = 10161;
const SRC_START_BLOCK: u64 = 3881800;
const SRC_RPC_URL: &'static str = "https://endpoints.omniatech.io/v1/eth/sepolia/public";
const SRC_ENDPOINT_CONTRACT_ADDRESS: &'static str = "0x3aCAAf60502791D199a5a5F0B173D78229eBFe32";

const DST_RPC_URL: &'static str = "https://endpoints.omniatech.io/v1/avax/fuji/public";
const DST_ADDRESS: Address = H160(hex_literal::hex!(
    "3e474377559D2a3519c6B09413D7a55B33f35eDe"
));
const DST_CHAIN_ID: u16 = 10106;
const DST_ULTRALIGHTNODEV2_ADDRESS: Address = H160(hex_literal::hex!(
    "fDDAFFa49e71dA3ef0419a303a6888F94bB5Ba18"
));
const DST_ENDPOINT_ADDRESS: Address = H160(hex_literal::hex!(
    "93f54D755A063cE7bB9e6Ac47Eccc8e33411d706"
));

// Sepolia ExampleOFTV2: 0xc54f4db136D6dF430E37330BA92F432115D05265 with endpoint: 0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1, ULNV2: 0x3aCAAf60502791D199a5a5F0B173D78229eBFe32
// Fuji ExampleOFTV2: 0x3e474377559D2a3519c6B09413D7a55B33f35eDe with endpoint: 0x93f54D755A063cE7bB9e6Ac47Eccc8e33411d706, ULN2:0xfDDAFFa49e71dA3ef0419a303a6888F94bB5Ba18

// Generate the type-safe contract bindings by providing the ABI
// definition in human readable format
abigen!(
    UltraLightClientV2,
    r#"[
        event Packet(bytes payload)
    ]"#,
);

abigen!(ExampleOFTv2, "./ExampleOFTv2.json");
abigen!(UltraLightNodev2, "./UltraLightNodev2.json");
abigen!(Endpoint, "./Endpoint.json");

fn generate_rlp_path(rlp_encoded_key: &Vec<u8>) -> Vec<u8> {
    let mut hex_data = vec![];
    for item in rlp_encoded_key.into_iter() {
        hex_data.push(item / 16);
        hex_data.push(item % 16);
    }
    hex_data.push(1);
    hex_data
}

struct PacketData {
    size: u64,
    nonce: u64,
    src_chain_id: u16,
    src_address: Address,
    dst_chain_id: u16,
    dst_address: Address,
    payload: Vec<u8>,
}

impl fmt::Display for PacketData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "{{")?;
        writeln!(f, "\tsize: {}", self.size)?;
        writeln!(f, "\tnonce: {}", self.nonce)?;
        writeln!(f, "\tsource chain id: {}", self.src_chain_id)?;
        writeln!(f, "\tsource address: {}", self.src_address)?;
        writeln!(f, "\tDestination chain id: {}", self.dst_chain_id)?;
        writeln!(f, "\tDestination address: {}", self.dst_address)?;
        writeln!(f, "\tPayload (hex-encoded): {}", hex::encode(&self.payload))?;
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl PacketData {
    fn read_from_log(data: &Vec<u8>) -> Result<PacketData, String> {
        if data.len() < 116 {
            return Err(
                "Corrupted packet (Data length is not sufficient to hold header)".to_string(),
            );
        }
        let size = u64::from_be_bytes(data[56..64].try_into().unwrap());
        let nonce = u64::from_be_bytes(data[64..72].try_into().unwrap());
        let src_chain_id = u16::from_be_bytes(data[72..74].try_into().unwrap());
        let src_address = Address::from_slice(&data[74..94]);
        let dst_chain_id = u16::from_be_bytes(data[94..96].try_into().unwrap());
        let dst_address = Address::from_slice(&data[96..116]);
        let payload_size = size - (116 - 64);
        if data.len() < (116 + payload_size) as usize {
            return Err(
                "Corrupted packet (Data length is not sufficient to hold payload)".to_string(),
            );
        }
        let payload = data[116..(116 + payload_size as usize)].to_vec();
        Ok(PacketData {
            size,
            nonce,
            src_chain_id,
            src_address,
            dst_chain_id,
            dst_address,
            payload,
        })
    }

    fn is_match(&self, destination_chain_id: u16, destination_address: &Address) -> bool {
        (self.dst_chain_id == destination_chain_id) && (self.dst_address.eq(destination_address))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let event_topic_0 = H256::from(keccak256("Packet(bytes)".as_bytes()));

    let mut current_block = SRC_START_BLOCK;
    //let provider = Provider::<Http>::connect("https://endpoints.omniatech.io/v1/arbitrum/one/public").await;
    let src_provider = Provider::<Http>::connect(SRC_RPC_URL).await;
    let src_chain_id = src_provider.get_chainid().await?;

    let dst_provider = Provider::<Http>::connect(DST_RPC_URL).await;
    let dst_chain_id = dst_provider.get_chainid().await?;

    // This key must be owner of ExampleOFTv2 contract
    let private_key = hex::decode("/* Private key here */").unwrap();
    let src_local_wallet = LocalWallet::from_bytes(private_key.as_slice())
        .unwrap()
        .with_chain_id(src_chain_id.as_u64());
    let dst_local_wallet = LocalWallet::from_bytes(private_key.as_slice())
        .unwrap()
        .with_chain_id(dst_chain_id.as_u64());
    let wallet_address = src_local_wallet.address();
    let src_middleware = SignerMiddleware::new(src_provider, src_local_wallet);
    let dst_middleware = SignerMiddleware::new(dst_provider, dst_local_wallet);

    let src_client = Arc::new(src_middleware);
    let dst_client = Arc::new(dst_middleware);

    // First step is to make sure we are allowed as relayer and oracle both
    let dst_oftv2_contract = ExampleOFTv2::new(DST_ADDRESS, dst_client.clone());
    let dst_endpoint_contract = Endpoint::new(DST_ENDPOINT_ADDRESS, dst_client.clone());

    let encoded_address = ethers::abi::encode(&[Token::Address(wallet_address.clone())]);
    println!("Wallet address being used is: {:?}", wallet_address.clone());

    let encoded_proof_lib_version = ethers::abi::encode(&[Token::Uint(Uint::from(1))]);
    let incoming_prooflib_version_call =
        dst_oftv2_contract.set_config(3, 10161, U256::from(1), encoded_proof_lib_version.into());
    let response = incoming_prooflib_version_call.send().await?.await?;
    println!(
        "Response for encoded proof lib version set is: {:?}",
        response
    );

    let oracle_permission_call =
        dst_oftv2_contract.set_config(3, 10161, U256::from(6), encoded_address.clone().into());
    let response = oracle_permission_call.send().await?.await?;
    println!("Response for oracle permission set: {:?}", response);

    let relayer_permission_call =
        dst_oftv2_contract.set_config(3, 10161, U256::from(3), encoded_address.into());
    let response = relayer_permission_call.send().await?.await?;
    println!("Response for relayer permission set: {:?}", response);

    let dst_ulnv2_contract =
        UltraLightNodev2::new(DST_ULTRALIGHTNODEV2_ADDRESS, dst_client.clone());

    let mut latest_finalized_block = src_client
        .get_block(BlockNumber::Finalized)
        .await
        .unwrap()
        .unwrap()
        .number
        .unwrap()
        .as_u64();

    loop {
        while current_block < latest_finalized_block {
            let current_range = (
                current_block,
                min(current_block + RANGE, latest_finalized_block),
            );
            let filter = Filter::new()
                .address(SRC_ENDPOINT_CONTRACT_ADDRESS.parse::<Address>()?)
                .event("Packet(bytes)")
                .from_block(current_range.0)
                .to_block(current_range.1);

            let logs = src_client.get_logs(&filter).await?;
            if logs.len() == 0 {
                println!("No logs in range: {:?}", current_range);
            } else {
                println!("Range: {:?} Number of logs: {:?}, starting log block num: {}, Ending log block num: {}", current_range, logs.len(), logs.first().unwrap().block_number.unwrap(), logs.last().unwrap().block_number.unwrap());
                for log in &logs {
                    println!(
                        "Tx hash: {:?} Tx index: {:?}",
                        log.transaction_hash, log.transaction_index
                    );
                    let packet_data = PacketData::read_from_log(&log.data.to_vec()).unwrap();
                    if !packet_data.is_match(DST_CHAIN_ID, &DST_ADDRESS) {
                        println!(
                            "Ignoring Packet as it is intended for different destination. {} {}",
                            packet_data.dst_chain_id, packet_data.dst_address
                        );
                        continue;
                    }
                    println!(
                        "*********Found Packet intended for our destination. {}",
                        packet_data
                    );
                    let encoded_address_pair = ethers::abi::encode_packed(&[
                        Token::Address(packet_data.src_address.clone()),
                        Token::Address(packet_data.dst_address.clone()),
                    ])?;

                    // Query inbound nonce on destination. If inbound nonce is greater than stored nonce + 1, this packet is old. But if inbound nonce is less than
                    // we must have missed few packets earlier. Probably because the block number we have started with is greater than it should be.
                    let inbound_nonce = dst_endpoint_contract
                        .get_inbound_nonce(SRC_CHAIN_ID, encoded_address_pair.into())
                        .call()
                        .await?;
                    if inbound_nonce + 1 != packet_data.nonce {
                        if inbound_nonce + 1 > packet_data.nonce {
                            println!("The next nonce on destination chain: {} is higher than packet's nonce: {}. Ignoring packet", inbound_nonce + 1, packet_data.nonce);
                            continue;
                        } else {
                            panic!("FATAL: The next nonce on destination chain: {} is lower than packet's nonce: {}. This could mean we started from later block than we should!!!!! Terminating..", inbound_nonce + 1, packet_data.nonce);
                        }
                    } else {
                        println!(
                            "Info: Next nonce on destination chain: {} and packet's nonce: {}",
                            inbound_nonce + 1,
                            packet_data.nonce
                        );
                    }

                    let tx_hash = log.transaction_hash.unwrap();
                    //let tx_hash = H256::from_str("0xc399b2cb52b37d2be0f1e7b624c17b19967f8fce046d7a0aa95bf816bf092e18").unwrap();
                    // For oracle we need block hash and receipt root
                    // For relayer we need block hash, receipt root, receipt proof (generate), source chain id, destination address

                    // 1. Retrieve the block (Get the receipt root and block hash)
                    //let block_hash = H256::from_str("0x8fde3fb6d7de9969cb55afd0acb8b3d58d94b06fa94867ca38b8259cd42e5700").unwrap();
                    let block = src_client
                        .get_block(log.block_hash.unwrap())
                        .await
                        .unwrap()
                        .unwrap();
                    let reference_receipt_root = block.receipts_root;
                    let mut receipts = vec![];
                    let mut receipt_proof_to_generate = 0;
                    let mut log_index_in_receipt = 0;
                    // -- Offload following to separate function
                    // 2. Fetch receipts of the block store it in tuple of (tx_index, receipt)
                    // 3. Identify the receipt to generate proof of (based on the transaction hash in the log) also note down the log index inside receipt
                    for tx in &block.transactions {
                        let receipt = src_client
                            .get_transaction_receipt(tx.clone())
                            .await
                            .unwrap()
                            .unwrap();
                        if tx.eq(&tx_hash) {
                            for (i, log) in receipt.logs.iter().enumerate() {
                                if log.topics[0].eq(&event_topic_0) {
                                    log_index_in_receipt = i as u64;
                                }
                            }
                            receipt_proof_to_generate = receipt.transaction_index.as_u64();
                        }
                        receipts.push((receipt.transaction_index, receipt));
                    }
                    // 4. Encode receipt and store them in merkle patricia trie
                    let memdb = Arc::new(MemoryDB::new(true));
                    let hasher = Arc::new(HasherKeccak::new());
                    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));

                    for receipt in receipts {
                        let encoded_receipt = match receipt.1.transaction_type {
                            Some(U64([0u64])) => rlp::encode(&receipt.1).to_vec(),
                            Some(U64([1u64])) => {
                                let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                                let mut encoding = vec![1u8];
                                encoding.extend(legacy_encoded);
                                encoding
                            }
                            Some(U64([2u64])) => {
                                let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                                let mut encoding = vec![2u8];
                                encoding.extend(legacy_encoded);
                                encoding
                            }
                            Some(U64([106u64])) => {
                                let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                                let mut encoding = vec![106u8];
                                encoding.extend(legacy_encoded);
                                encoding
                            }
                            _ => {
                                println!("Receipt type: {}", receipt.1.transaction_type.unwrap());
                                panic!("Unsupported");
                            }
                        };
                        trie.insert(rlp::encode(&receipt.0).to_vec(), encoded_receipt)
                            .unwrap();
                    }
                    // 5. (Debug) Calculate and match trie root against receipt root in the block
                    let generated_root = trie.root().unwrap();
                    if !generated_root.eq(&reference_receipt_root.0.to_vec()) {
                        println!(
                            "Mismatch Generated proof: {:?} Actual Proof: {:?}, log details: {:?}",
                            hex::encode(generated_root),
                            hex::encode(reference_receipt_root.0),
                            log
                        );
                        panic!("Receipt roots are not equal. Please investigate.");
                    }
                    println!(
                        "Generated proof: {:?} Actual Proof: {:?}",
                        hex::encode(generated_root),
                        hex::encode(reference_receipt_root.0)
                    );
                    // 6. Generate proof for receipt identified in step 4
                    let encoded_key_for_target_receipt =
                        rlp::encode(&receipt_proof_to_generate).to_vec();
                    let mut generated_proof = trie
                        .get_proof(encoded_key_for_target_receipt.as_slice())
                        .expect("getting proof should not fail.");
                    // 7. Generate rlp path for the receipt identified in step 4.
                    let generated_key_paths = generate_rlp_path(&encoded_key_for_target_receipt);

                    // 8. Return (proof, rlp_path, log_index_inside_receipt) in abi encoded format
                    let encoded_tx_proof = ethers::abi::encode(&[
                        Token::Array(
                            generated_proof
                                .drain(..)
                                .map(|v| Token::Bytes(v.into()))
                                .collect(),
                        ),
                        Token::Array(
                            generated_key_paths
                                .iter()
                                .map(|v| Token::Uint(Uint::from(*v)))
                                .collect(),
                        ),
                        Token::Uint(Uint::from(log_index_in_receipt)),
                    ])
                    .to_vec();
                    // -- Offload complete
                    // Oracle -> Block hash and receipt root
                    println!(
                        "Oracle arguments: block hash: {:?} receipt root: {:?}",
                        hex::encode(log.block_hash.unwrap().0),
                        hex::encode(reference_receipt_root)
                    );
                    // Relayer: Block hash, receipt root, receipt proof, source chain id, destination address
                    println!("Relayer arguments: block hash: {:?} receipt_root: {:?} src_chain_id: {:?} destination address: {:?}", hex::encode(log.block_hash.unwrap().0), hex::encode(reference_receipt_root), packet_data.src_chain_id, hex::encode(packet_data.dst_address.0));
                    println!(
                        "Encoded tx proof: {:?}",
                        hex::encode(encoded_tx_proof.clone())
                    );

                    //  Send the data to destination
                    // Oracle call
                    let oracle_response = dst_ulnv2_contract
                        .update_hash(
                            SRC_CHAIN_ID,
                            log.block_hash.unwrap().0,
                            U256::from(5),
                            reference_receipt_root.0,
                        )
                        .send()
                        .await?
                        .await?;
                    println!("Oracle response: {:?}", oracle_response);

                    sleep(Duration::from_secs(60)).await;

                    // Relayer call
                    let relayer_response = dst_ulnv2_contract
                        .validate_transaction_proof(
                            SRC_CHAIN_ID,
                            packet_data.dst_address,
                            U256::from(100000),
                            log.block_hash.unwrap().0,
                            reference_receipt_root.0,
                            Bytes::from(encoded_tx_proof),
                        )
                        .send()
                        .await?
                        .await?;
                    println!("Relayer response: {:?}", relayer_response);

                    sleep(Duration::from_secs(60)).await;
                }
            }

            current_block = min(current_range.1 + 1, latest_finalized_block);
        }
        println!(
            "Sleeping for a minute as consumed all available blocks till: {}",
            current_block
        );
        sleep(Duration::from_secs(60)).await;
        println!("Woke up");
        latest_finalized_block = src_client
            .get_block(BlockNumber::Finalized)
            .await
            .unwrap()
            .unwrap()
            .number
            .unwrap()
            .as_u64();
        println!("Latest finalized block is: {}", latest_finalized_block);
    }

    Ok(())
}
