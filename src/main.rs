use cita_trie::MemoryDB;
use cita_trie::{PatriciaTrie, Trie};
use ethers::abi::{AbiEncode, Token, Uint};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::core::types::Filter;
use ethers::prelude::{Http, LocalWallet, ProviderExt, SignerMiddleware, U64};
use ethers::providers::{Middleware, Provider};
use ethers::signers::Signer;
use ethers::types::{BlockNumber, H160, H256, U256};
use ethers::utils::keccak256;
use eyre::Result;
use hasher::{Hasher, HasherKeccak};
use std::cmp::min;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

const RANGE: u64 = 10;
const SRC_START_BLOCK: u64 = 3750046;
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

fn generate_rlp_path(rlp_encoded_key: &Vec<u8>) -> Vec<u8> {
    let mut hex_data = vec![];
    for item in rlp_encoded_key.into_iter() {
        hex_data.push(item / 16);
        hex_data.push(item % 16);
    }
    hex_data.push(1);
    hex_data
}

#[derive(Debug)]
struct PacketData {
    size: u64,
    nonce: u64,
    src_chain_id: u16,
    src_address: Address,
    dst_chain_id: u16,
    dst_address: Address,
    payload: Vec<u8>,
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
    let private_key = hex::decode("/* private key here */").unwrap();
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
    let encoded_address = ethers::abi::encode(&[Token::Address(wallet_address.clone())]);
    println!("Wallet address being used is: {:?}", wallet_address.clone());
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

            let mut logs = src_client.get_logs(&filter).await?;
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
                        "*********Found Packet intended for our destination. {:?}",
                        packet_data
                    );

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
                    println!("Encoded tx proof: {:?}", hex::encode(encoded_tx_proof));

                    //  Send the data to destination
                    dst_ulnv2_contract.update_hash();
                    dst_ulnv2_contract.validate_transaction_proof();
                }
            }

            current_block = current_range.1 + 1;
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

    /*
    let reference_data_hex = "0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000098000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000053f851a0370bf5b87aefe766a171b936c299f351f13735e9d5ef7f4bfe6964ed0189d3bf80808080808080a0e14b2cfebe7f66456fd4eeced9b38c4836b55c0c1cb1f345b9fc210d63e8884a80808080808080800000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f4f901f180a0b7b98431b399d8c30607f37c04d8b938faf05fdf6b6a56419f7d30feeb456d36a05bddc4e9875f5da7a2f1f0a6808c2b96214ef031485664e870d5bcd6f8f62acca09471663e77f00a49909209e4cc1e17f364859eecc2567014c1d91546df97f9a7a0169aa01c8c6d89e708a301632f3cde8af3d76113d3ecdaf928aaa6cbade26d74a0af77a08eeb746cfe2f148c9b2b9ed427e0fec1c80ed61ee0e57bdcb88fe61d2fa0d6273902027d907b5ab1a874e6b20d097ba7c02d07a58de8fdd02ee13757f2e1a0570bb654e4fae56d65b6b25cb456588bb0a4f5643fafe3b6945ac0e1f95e474aa0ab50bbdb78484aefb59e738fc371a8c6914732a76f25935687637af6ef7765bca057ba1942358c27c1cc4d04d922315878294a51ace239046109e6a906f946abd7a09f32bf91b9eda29fd030c442779181ecfd2de972a40bd0d5c3a8ff5887ebc773a0b9e4828d2f341ca9605ac7290695dddb48ca52442b7efa7bff1912f9ace89193a029bbeaec1d65208da2db6b142c44e1cfe4389d5ae1878a82e7e520df64447816a0e405b16a3d531e2e7e08e0fddb238273ee6ad87999a4fb704e8fbd991662211da058cf9c0e7ee88a3e9d512d612936ddad7df270f3797e11ed42d51644c8e3ebbda06cd86d1903e7075982bdacc9f23555873135e11c82d8ecd000f568654ae7e8818000000000000000000000000000000000000000000000000000000000000000000000000000000000000005dbf905d820b905d402f905d00183232f6eb9010000000000400000000000000000000000000040000000000000004000000000101000000040000000000000000010000001000000000000000000000000000000004000000000000000000008000000080000000000000000000000000000000000040000020000000000000000000802000000000000000002000010000000000000000400000000000000000000000000000000280000000000000000000000020000004000020000000004000000000000000200000000000000000000000000001002000008000000000000000000000000000000000000000200000020001000800000000000000100000000002000000000000000200000000000080000f904c5f89b942f6f07cdcf3588944bf4c42ac74ff24bf56e7590f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000465045e5fb8f4a7b94ed2efde0f5ec734b8f942aa00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000fd3aa5cafa7e8d6ff85894cd2e3622d483c7dc855f72e5eafadcd577ac78b4e1a0df21c415b78ed2552cc9971249e32a053abce6087a0ae0fbf3f78db5174a3493a000000000000000000000000000000000000000000000000007a0092b44f13c8af8d9944d73adb72bc3dd368966edd0f0b2148401a178e2e1a0b0c632f55f1e1b3b2c3d82f41ee4716bb4c00f0f5d84cdafc141581bb8757a4fb8a000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002200010000000000000000000000000000000000000000000000000000000000014c08000000000000000000000000000000000000000000000000000000000000f8d9945a54fe5234e811466d5366846283323c954310b2e1a04e41ee13e03cd5e0446487b524fdc48af6acf26c074dacdbdfb6b574b42c8146b8a000000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000002f6f07cdcf3588944bf4c42ac74ff24bf56e759000000000000000000000000000000000000000000000000002ed35bfd5286c24f9013a944d73adb72bc3dd368966edd0f0b2148401a178e2e1a0e9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82b90100000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000b40000000000000146006a2f6f07cdcf3588944bf4c42ac74ff24bf56e75900065af5191b0de278c7286d6c7cc6ab6bb8a73ba2cd60000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000fd3aa5cafa7e8d6f0000000000000000000000000000000000000000000000000000000000000014465045e5fb8f4a7b94ed2efde0f5ec734b8f942a000000000000000000000000000000000000000000000000f8d9942f6f07cdcf3588944bf4c42ac74ff24bf56e7590e1a0664e26797cde1146ddfcb9a5d3f4de61179f9c11b2698599bb09e686f442172bb8a000000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000fd3aa5cafa7e8d6f0000000000000000000000000000000000000000000000000000000000000014465045e5fb8f4a7b94ed2efde0f5ec734b8f942a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000001";
    let parameter_type = vec![ParamType::Array(Box::new(ParamType::Bytes)), ParamType::Array(Box::new(ParamType::Uint(32))), ParamType::Uint(32)];
    let tokens = ethers::abi::decode(parameter_type.as_slice(), hex::decode(reference_data_hex).unwrap().as_slice()).unwrap();

    let proof_array = tokens[0].clone().into_array().unwrap();
    let nibbles_array = tokens[1].clone().into_array().unwrap();
    // 0 12 1
    for element in &proof_array {
        println!("Proof array element: 0x{}", hex::encode(element.clone().into_bytes().unwrap()));
    }
    for element in &nibbles_array {
        println!("Nibbles array element: {}", element.clone().into_uint().unwrap());
    }

    println!("Log index: {}", tokens[2].clone().into_uint().unwrap());

    let provider = Provider::<Http>::connect("https://api.avax.network/ext/bc/C/rpc").await;
    let client = Arc::new(provider);
    let block = client.get_block(BlockNumber::Number(U64::from(31618537))).await.unwrap().unwrap();
    println!("Receipt root: {:?}", block.receipts_root.encode_hex());
    let mut receipts = vec![];
    let mut receipt_proof_to_generate = 0u64;
    let mut log_index_in_receipt = 0u64;
    // We need to generate proof of receipt for tx hash of := 0x7092c130f0d73dbc708c08fd18e20d58fc481bede2c067df857a38b9937d6668

    for tx in &block.transactions {
        let receipt = client.get_transaction_receipt(tx.clone()).await.unwrap().unwrap();
        if tx.encode_hex() == "0x7092c130f0d73dbc708c08fd18e20d58fc481bede2c067df857a38b9937d6668" {
            println!("Receipt found: {:?}", receipt.transaction_type);
            for (i, log) in receipt.logs.iter().enumerate() {
                if log.topics[0].eq(&event_topic_0) {
                    log_index_in_receipt = i as u64;
                }
            }
            receipt_proof_to_generate = receipt.transaction_index.as_u64();
        }
        if receipt.root.is_some() {
            println!("Receipt root printing for index: {} : {}", receipt.transaction_index, receipt.root.unwrap());
        }
        receipts.push((receipt.transaction_index, receipt));
    }

    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));

    for receipt in receipts {
        println!("Inserting receipt at index: {}", receipt.0);
        let encoded_receipt = match receipt.1.transaction_type {
            Some(U64([0u64])) => {
                rlp::encode(&receipt.1).to_vec()
            },
            Some(U64([1u64])) => {
                let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                let mut encoding = vec![1u8];
                encoding.extend(legacy_encoded);
                encoding
            },
            Some(U64([2u64])) => {
                let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                let mut encoding = vec![2u8];
                encoding.extend(legacy_encoded);
                encoding
            },
            _ => {
              println!("Receipt type: {}", receipt.1.transaction_type.unwrap());
                panic!("Unsupported");
            }
        };
        trie.insert(rlp::encode(&receipt.0).to_vec(), encoded_receipt).unwrap();
    }
    println!("Generated root is: {:?}",  hex::encode(trie.root().unwrap()));

    let proof = trie.get_proof(rlp::encode(&receipt_proof_to_generate).to_vec().as_slice()).expect("TODO: panic message");
    for element in &proof {
        let node = trie.decode_node(element.as_slice()).unwrap();
        println!("Decoded Node: {:?}", node);
    }
    let encoded_key = rlp::encode(&receipt_proof_to_generate).to_vec();
    println!("Nibbles generated: {:?}", generate_rlp_path(encoded_key));
    println!("Log index in receipt: {:?}", log_index_in_receipt);

    Ok(())
     */

    /*
       let reference_data_hex = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000008a000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000053f851a00e838ca8f41421a6208de6891e3bab5d788344855afb83ba8907c37cdfa8203080808080808080a0b0f51de7909653fadedb604e425c3ae1245d466325c8296662c289fa327eeeea80808080808080800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b3f8b180a0e429fd649667ee035c826107b6c30c9cc089550ab0a4fce36a55715c224f7a13a02efaf730d8eae8b2da5460be3a4f4e633df4455582ca39b4675c879bcc14e852a0cd224e3bb860e709ebc3ff1827d9f340d45609a98348963839029a3f88243643a021492a3c8f4c5198dc3d4c11c6c07869f8b98aae30a1c41378000afa614b5fffa0b88f596808cf64fe7c756ed55fc7ef6a1136a2839363177a0eb234b96082659f8080808080808080808080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000640f9063d20b9063902f9063501833f105fb9010002000000040000004000000000000000000040000002800100000000000000100000002000000000000000000014000000000000000000108000200000000010004000000000000000000008000000000000000000000000004000001000000000040000000000000080000000020000000020000000000000000010020000000000000400000000000000000000000080000000388000000000000000040000000000004000020000000004000000000000000000000000000000000000000000001402000008000000000000000000000000000000000000000000000000001080800000000000000000000000000000018000000000000000001000000000f9052af89c94f42647d472b6d2299eb283081714c8657e657295f884a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000003f9fd6e9d909f0bc5f4f416f525a5af90469658ba0000000000000000000000000f42647d472b6d2299eb283081714c8657e657295a00000000000000000000000000000000000000000000000000000000000000c0c80f85894177d36dbe2271a4ddb2ad8304d82628eb921d790e1a0df21c415b78ed2552cc9971249e32a053abce6087a0ae0fbf3f78db5174a3493a00000000000000000000000000000000000000000000000000015a801b51f7a71f8d9944d73adb72bc3dd368966edd0f0b2148401a178e2e1a0b0c632f55f1e1b3b2c3d82f41ee4716bb4c00f0f5d84cdafc141581bb8757a4fb8a00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000220001000000000000000000000000000000000000000000000000000000000003f7a0000000000000000000000000000000000000000000000000000000000000f8d994a0cc33dd6f4819d473226257792afe230ec3c67fe1a04e41ee13e03cd5e0446487b524fdc48af6acf26c074dacdbdfb6b574b42c8146b8a0000000000000000000000000000000000000000000000000000000000000006500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000014000000000000000000000000f42647d472b6d2299eb283081714c8657e6572950000000000000000000000000000000000000000000000000004ebab824f6138f9017a944d73adb72bc3dd368966edd0f0b2148401a178e2e1a0e9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82b90140000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000f40000000000000024006ef42647d472b6d2299eb283081714c8657e6572950065f6f02e017870859e7265010bb6ffb0664747169f0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000143f9fd6e9d909f0bc5f4f416f525a5af90469658b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000c0c000000000000000000000000f8fd94f42647d472b6d2299eb283081714c8657e657295f884a0e1b87c47fdeb4f9cbadbca9df3af7aba453bb6e501075d0440d88125b711522aa00000000000000000000000000000000000000000000000000000000000000065a00000000000000000000000003f9fd6e9d909f0bc5f4f416f525a5af90469658ba0b6ede9d5e1b0a691fbf2f515203f067a1b77b9bebb2a0d5bfc5b7ae7f95ef674b860000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000c0c0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001";
       let parameter_type = vec![ParamType::Array(Box::new(ParamType::Bytes)), ParamType::Array(Box::new(ParamType::Uint(32))), ParamType::Uint(32)];
       let tokens = ethers::abi::decode(parameter_type.as_slice(), hex::decode(reference_data_hex).unwrap().as_slice()).unwrap();

       let proof_array = tokens[0].clone().into_array().unwrap();
       let nibbles_array = tokens[1].clone().into_array().unwrap();
       // 0 12 1
       for element in &proof_array {
           println!("Proof array element: 0x{}", hex::encode(element.clone().into_bytes().unwrap()));
       }
       for element in &nibbles_array {
           println!("Nibbles array element: {}", element.clone().into_uint().unwrap());
       }

       println!("Log index: {}", tokens[2].clone().into_uint().unwrap());
    // Experiment
       let provider = Provider::<Http>::connect("https://endpoints.omniatech.io/v1/arbitrum/one/public").await;
       let client = Arc::new(provider);
       let block = client.get_block(BlockId::from_str("0x8fde3fb6d7de9969cb55afd0acb8b3d58d94b06fa94867ca38b8259cd42e5700").unwrap()).await.unwrap().unwrap();
       println!("Block number: {:?}", block.number.unwrap().as_u64());
       println!("Receipt root: {:?}", block.receipts_root.encode_hex());
       let mut receipts = vec![];
       let mut receipt_proof_to_generate = 0u64;
       let mut log_index_in_receipt = 0u64;
       // We need to generate proof of receipt for tx hash of := 0xc399b2cb52b37d2be0f1e7b624c17b19967f8fce046d7a0aa95bf816bf092e18

       for tx in &block.transactions {
           let receipt = client.get_transaction_receipt(tx.clone()).await.unwrap().unwrap();
           if tx.encode_hex() == "0xc399b2cb52b37d2be0f1e7b624c17b19967f8fce046d7a0aa95bf816bf092e18" {
               println!("Receipt found: {:?}", receipt.transaction_type);
               for (i, log) in receipt.logs.iter().enumerate() {
                   if log.topics[0].eq(&event_topic_0) {
                       log_index_in_receipt = i as u64;
                   }
               }
               receipt_proof_to_generate = receipt.transaction_index.as_u64();
           }
           println!("{:?} {:?}", tx.encode_hex(), receipt.transaction_type);
           if receipt.root.is_some() {
               println!("Receipt root printing for index: {} : {}", receipt.transaction_index, receipt.root.unwrap());
           }
           receipts.push((receipt.transaction_index, receipt));
       }

       let memdb = Arc::new(MemoryDB::new(true));
       let hasher = Arc::new(HasherKeccak::new());

       let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));

       for receipt in receipts {
           println!("Inserting receipt at index: {}", receipt.0);
           let encoded_receipt = match receipt.1.transaction_type {
               Some(U64([0u64])) => {
                   rlp::encode(&receipt.1).to_vec()
               },
               Some(U64([1u64])) => {
                   let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                   let mut encoding = vec![1u8];
                   encoding.extend(legacy_encoded);
                   encoding
               },
               Some(U64([2u64])) => {
                   let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                   let mut encoding = vec![2u8];
                   encoding.extend(legacy_encoded);
                   encoding
               },
               Some(U64([106u64])) => {
                   let legacy_encoded = rlp::encode(&receipt.1).to_vec();
                   let mut encoding = vec![106u8];
                   encoding.extend(legacy_encoded);
                   encoding
               },
               _ => {
                   println!("Receipt type: {} is not supported.", receipt.1.transaction_type.unwrap());
                   panic!("Unsupported");
               }
           };
           trie.insert(rlp::encode(&receipt.0).to_vec(), encoded_receipt).unwrap();
       }
       println!("Generated root is: {:?}",  hex::encode(trie.root().unwrap()));

       let proof = trie.get_proof(rlp::encode(&receipt_proof_to_generate).to_vec().as_slice()).expect("TODO: panic message");
       for element in &proof {
           println!("Encoded node: {:?}", hex::encode(element));
           let node = trie.decode_node(element.as_slice()).unwrap();
           println!("Decoded Node: {:?}", node);
       }
       let encoded_key = rlp::encode(&receipt_proof_to_generate).to_vec();
       println!("Nibbles generated: {:?}", generate_rlp_path(encoded_key));
       println!("Log index in receipt: {:?}", log_index_in_receipt);

       Ok(())

        */
}
