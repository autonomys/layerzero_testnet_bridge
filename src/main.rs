extern crate core;

use cita_trie::MemoryDB;
use cita_trie::{PatriciaTrie, Trie};
use ethers::abi::{Token, Uint};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::core::types::Filter;
use ethers::prelude::{
    Client, Http, JsonRpcClient, LocalWallet, ProviderExt, SignerMiddleware, U64,
};
use ethers::providers::{Middleware, Provider, Ws};
use ethers::signers::Signer;
use ethers::types::{
    Block, BlockId, BlockNumber, Bytes, Log, TransactionReceipt, TxHash, H160, H256, U256,
};
use ethers::utils::keccak256;
use eyre::{Report, Result};
use hasher::HasherKeccak;
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Formatter;
use std::path::Path;
use std::str::FromStr;

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// Source chain id
// Source RPC URL
// Source endpoint contract address

// Destination Chain id
// Destination Address
// Destination RPC URL
// Destination ultra light node v2 address
// Destination endpoint address
// Destination tx signer

// Agnostic
// Mode: Src/Dest/Both
// Chain ID
// (Only destination) Payload recipient user application contract
// RPC URL
// Ultra light node v2 address
// Endpoint
// (Only destination) Tx private key environment variable

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

// Sepolia UserApplication: 0xc54f4db136D6dF430E37330BA92F432115D05265 with endpoint: 0xae92d5aD7583AD66E49A0c67BAd18F6ba52dDDc1, ULNV2: 0x3aCAAf60502791D199a5a5F0B173D78229eBFe32
// Fuji UserApplication: 0x3e474377559D2a3519c6B09413D7a55B33f35eDe with endpoint: 0x93f54D755A063cE7bB9e6Ac47Eccc8e33411d706, ULN2:0xfDDAFFa49e71dA3ef0419a303a6888F94bB5Ba18

// Generate the type-safe contract bindings by providing the ABI
// definition in human readable format
abigen!(
    UltraLightClientV2,
    r#"[
        event Packet(bytes payload)
    ]"#,
);

abigen!(
    UserApplication,
    r"[
    function setConfig(uint16 _version, uint16 _chainId, uint256 _configType, bytes calldata _config) external
    function getConfig(uint16 _version, uint16 _chainId, address, uint _configType) external view returns (bytes memory)
]"
);

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
    fn read_from_log(data: &Vec<u8>) -> Result<PacketData> {
        if data.len() < 116 {
            return Err(Report::msg(
                "Corrupted packet (Data length is not sufficient to hold header)",
            ));
        }
        let size = u64::from_be_bytes(data[56..64].try_into().unwrap());
        let nonce = u64::from_be_bytes(data[64..72].try_into().unwrap());
        let src_chain_id = u16::from_be_bytes(data[72..74].try_into().unwrap());
        let src_address = Address::from_slice(&data[74..94]);
        let dst_chain_id = u16::from_be_bytes(data[94..96].try_into().unwrap());
        let dst_address = Address::from_slice(&data[96..116]);
        let payload_size = size - (116 - 64);
        if data.len() < (116 + payload_size) as usize {
            return Err(Report::msg(
                "Corrupted packet (Data length is not sufficient to hold header)",
            ));
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

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub enum ChainMode {
    Source,
    Destination,
    SourceAndDestination,
}

impl ChainMode {
    pub fn is_source(&self) -> bool {
        match self {
            ChainMode::Source | ChainMode::SourceAndDestination => true,
            _ => false,
        }
    }

    pub fn is_destination(&self) -> bool {
        match self {
            ChainMode::Destination | ChainMode::SourceAndDestination => true,
            _ => false,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct SerializedSetupData {
    layerzero_id: u16,
    rpc_url: String,
    user_application_env_vars: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct SerializedChainData {
    mode: ChainMode,
    layerzero_id: u16,
    ultra_light_node_v2_address: String,
    starting_block: u64,
    endpoint_address: String,
    rpc_url: String,
    signer_key_env_var: String,
    user_application_address: Vec<String>,
}

pub enum RpcUrl {
    Http(String),
    Ws(String),
}

pub struct ChainData {
    mode: ChainMode,
    layerzero_id: u16,
    rpc_url: RpcUrl,
    ultra_light_node_v2_address: Option<Address>,
    starting_block: u64,
    endpoint_address: Address,
    signer_wallet: Option<LocalWallet>,
    user_application_addresses: Vec<Address>,
}

pub struct SetupData {
    layerzero_id: u16,
    rpc_url: RpcUrl,
    user_application_setup_wallet: Vec<(Address, LocalWallet)>,
}

impl SerializedSetupData {
    pub fn to_setup(self) -> Result<SetupData> {
        if self.rpc_url.is_empty() {
            return Err(Report::msg(format!(
                "empty rpc url for layerzero chain id: {}",
                self.layerzero_id
            )));
        }
        let lowercased_rpc_url = self.rpc_url.to_lowercase();
        let rpc_url = if lowercased_rpc_url.starts_with("http") {
            // Covers http and https
            RpcUrl::Http(lowercased_rpc_url)
        } else if lowercased_rpc_url.starts_with("ws") {
            RpcUrl::Ws(lowercased_rpc_url)
        } else {
            return Err(Report::msg("invalid rpc url"));
        };

        let mut user_application_setup_wallet = vec![];
        for env_var in self.user_application_env_vars {
            if env_var.is_empty() {
                return Err(Report::msg(format!(
                    "empty signer key environment variable for layerzero chain id: {}",
                    self.layerzero_id
                )));
            }
            let signer_key = std::env::var(env_var)?;
            let signer_key_bytes = hex::decode(&signer_key)?;
            let signer_wallet = LocalWallet::from_bytes(&signer_key_bytes)?;
            user_application_setup_wallet.push((signer_wallet.address(), signer_wallet));
        }

        Ok(SetupData {
            layerzero_id: self.layerzero_id,
            rpc_url,
            user_application_setup_wallet,
        })
    }
}

impl SerializedChainData {
    pub fn to_chain(self) -> Result<ChainData> {
        if self.rpc_url.is_empty() {
            return Err(Report::msg(format!(
                "empty rpc url for layerzero chain id: {}",
                self.layerzero_id
            )));
        }
        let lowercased_rpc_url = self.rpc_url.to_lowercase();
        let rpc_url = if lowercased_rpc_url.starts_with("http") {
            // Covers http and https
            RpcUrl::Http(lowercased_rpc_url)
        } else if lowercased_rpc_url.starts_with("ws") {
            RpcUrl::Ws(lowercased_rpc_url)
        } else {
            return Err(Report::msg("invalid rpc url"));
        };

        if self.endpoint_address.is_empty() {
            return Err(Report::msg(format!(
                "empty endpoint address for layerzero chain id: {}",
                self.layerzero_id
            )));
        }
        let endpoint_address = Address::from_str(&self.endpoint_address)?;
        if endpoint_address.is_zero() {
            return Err(Report::msg(format!(
                "empty endpoint address for layerzero chain id: {}",
                self.layerzero_id
            )));
        }

        let mut ultra_light_node_v2_address = None;
        let mut user_application_addresses = vec![];
        if self.mode.is_destination() {
            if self.ultra_light_node_v2_address.is_empty() {
                return Err(Report::msg(format!(
                    "empty ultra light node v2 address for layerzero chain id: {}",
                    self.layerzero_id
                )));
            }
            let parsed_ultra_light_node_v2_address =
                Address::from_str(&self.ultra_light_node_v2_address)?;
            if parsed_ultra_light_node_v2_address.is_zero() {
                return Err(Report::msg(format!(
                    "empty ultra light node v2 address for layerzero chain id: {}",
                    self.layerzero_id
                )));
            }
            ultra_light_node_v2_address = Some(parsed_ultra_light_node_v2_address);
        }
        if self.mode.is_destination() {
            for (i, address) in self.user_application_address.iter().enumerate() {
                if address.is_empty() {
                    return Err(Report::msg(format!("empty user application address  in the address list for layerzero chain id: {} at index: {}", self.layerzero_id, i)));
                }
                let parsed_address = Address::from_str(&address)?;
                if parsed_address.is_zero() {
                    return Err(Report::msg(format!("zero user application address  in the address list for layerzero chain id: {} at index: {}", self.layerzero_id, i)));
                }
                user_application_addresses.push(Address::from_str(&address)?);
            }
        }

        let mut signer_wallet = None;
        if self.mode.is_destination() {
            if self.signer_key_env_var.is_empty() {
                return Err(Report::msg(format!(
                    "empty signer key environment variable for layerzero chain id: {}",
                    self.layerzero_id
                )));
            }
            let signer_key = std::env::var(self.signer_key_env_var)?;
            let signer_key_bytes = hex::decode(&signer_key)?;
            signer_wallet = Some(LocalWallet::from_bytes(&signer_key_bytes)?);
        }

        Ok(ChainData {
            mode: self.mode,
            layerzero_id: self.layerzero_id,
            starting_block: self.starting_block,
            user_application_addresses,
            ultra_light_node_v2_address,
            endpoint_address,
            rpc_url,
            signer_wallet,
        })
    }
}

#[derive(Debug)]
pub struct DestPayload {
    block_hash: H256,
    receipts_root: H256,
    confirmations: U256,
    dest_address: Address,
    tx_proof: Bytes,
    gas_limit: U256,
}

#[derive(Debug)]
pub struct DestPayloadGenerationData {
    dest_chain_id: u16,
    dest_address: Address,
    target_log: Log,
}

use async_trait::async_trait;

#[async_trait]
pub trait BlockJournal {
    async fn get_last_processed_block(&self, chain_id: u16) -> Result<Option<u64>>;
    async fn complete_processing_of_block(&mut self, chain_id: u16, block_id: u64) -> Result<()>;
}

#[async_trait]
pub trait BaseChain {
    // Base
    fn layerzero_chain_id(&self) -> u16;
    async fn get_chain_id(&self) -> Result<U256>;
}

#[async_trait]
pub trait SourceChain: BaseChain {
    // Provider (Only source)
    async fn get_endpoint_packet_logs(&self, block_range: (u64, u64)) -> Result<Vec<Log>>;
    async fn get_block(&self, block_hash_or_number: BlockId) -> Result<Option<Block<H256>>>;
    async fn get_transaction_receipt(
        &self,
        transaction_hash: TxHash,
    ) -> Result<Option<TransactionReceipt>>;

    fn get_starting_block(&self) -> u64;
}

#[async_trait]
pub trait DestinationChain: BaseChain {
    // Ultra light node relayer and oracle submission (Only dest)
    async fn update_hash(
        &self,
        src_chain_id: u16,
        lookup_hash: [u8; 32],
        confirmations: U256,
        block_data: [u8; 32],
    ) -> Result<Option<TransactionReceipt>>;
    async fn validate_transaction_proof(
        &self,
        src_chain_id: u16,
        dst_address: Address,
        gas_limit: U256,
        lookup_hash: [u8; 32],
        block_data: [u8; 32],
        tx_proof: Bytes,
    ) -> Result<Option<TransactionReceipt>>;

    // Endpoint (Only dest)
    async fn get_inbound_nonce(
        &self,
        src_chain_id: u16,
        encoded_address_pair: Bytes,
    ) -> Result<u64>;

    // Get list of destination address for which we have permission
    fn get_destination_addresses(&self) -> &Vec<Address>;
}

#[async_trait]
pub trait ConfigurableChain: BaseChain {
    // User application configuration (Only dest:setup)
    async fn get_ua_config(
        &self,
        user_application: Address,
        version: u16,
        chain_id: u16,
        config_type: U256,
    ) -> Result<Bytes>;
    async fn set_ua_config(
        &self,
        user_application: Address,
        version: u16,
        chain_id: u16,
        config_type: U256,
        config: Bytes,
    ) -> Result<Option<TransactionReceipt>>;
}

pub struct SourceChainImpl<C: JsonRpcClient> {
    layerzero_id: u16,
    provider: Provider<C>,
    endpoint_address: Address,
    starting_block: u64,
}

impl<C: JsonRpcClient> SourceChainImpl<C> {
    fn new(
        layerzero_id: u16,
        provider: Provider<C>,
        endpoint_address: Address,
        starting_block: u64,
    ) -> Self {
        SourceChainImpl {
            provider,
            layerzero_id,
            endpoint_address,
            starting_block,
        }
    }
}

pub async fn new_source_chain(
    chain_data: &ChainData,
) -> Result<Arc<dyn SourceChain + Send + Sync>> {
    match &chain_data.rpc_url {
        RpcUrl::Http(connection_url) => {
            let provider = Provider::<Http>::try_connect(connection_url).await?;
            Ok(Arc::new(SourceChainImpl::new(
                chain_data.layerzero_id,
                provider,
                chain_data.endpoint_address.clone(),
                chain_data.starting_block,
            )))
        }
        RpcUrl::Ws(connection_url) => {
            let provider = Provider::<Ws>::connect(connection_url).await?;
            Ok(Arc::new(SourceChainImpl::new(
                chain_data.layerzero_id,
                provider,
                chain_data.endpoint_address.clone(),
                chain_data.starting_block,
            )))
        }
    }
}

#[async_trait]
impl<C: JsonRpcClient> BaseChain for SourceChainImpl<C> {
    fn layerzero_chain_id(&self) -> u16 {
        self.layerzero_id
    }

    async fn get_chain_id(&self) -> Result<U256> {
        self.provider.get_chainid().await.map_err(Into::into)
    }
}

#[async_trait]
impl<C: JsonRpcClient> SourceChain for SourceChainImpl<C> {
    async fn get_endpoint_packet_logs(&self, block_range: (u64, u64)) -> Result<Vec<Log>> {
        let filter = Filter::new()
            .address(self.endpoint_address.clone())
            .event("Packet(bytes)")
            .from_block(block_range.0)
            .to_block(block_range.1);
        self.provider.get_logs(&filter).await.map_err(Into::into)
    }

    fn get_starting_block(&self) -> u64 {
        self.starting_block
    }

    async fn get_block(&self, block_id: BlockId) -> Result<Option<Block<H256>>> {
        self.provider.get_block(block_id).await.map_err(Into::into)
    }

    async fn get_transaction_receipt(
        &self,
        transaction_hash: TxHash,
    ) -> Result<Option<TransactionReceipt>> {
        self.provider
            .get_transaction_receipt(transaction_hash)
            .await
            .map_err(Into::into)
    }
}

pub struct DestinationChainImpl<M: Middleware, C: JsonRpcClient> {
    layerzero_id: u16,
    provider: Provider<C>,
    ultra_light_node_v2: UltraLightNodev2<M>,
    endpoint: Endpoint<Provider<C>>,
    user_application_addresses: Vec<Address>,
}

impl<M: Middleware, C: JsonRpcClient> DestinationChainImpl<M, C> {
    pub fn new(
        layerzero_id: u16,
        provider: Provider<C>,
        ultra_light_node_v2: UltraLightNodev2<M>,
        endpoint: Endpoint<Provider<C>>,
        user_application_addresses: Vec<Address>,
    ) -> Self {
        Self {
            layerzero_id,
            provider,
            ultra_light_node_v2,
            endpoint,
            user_application_addresses,
        }
    }
}

pub async fn new_destination_chain(
    chain_data: &ChainData,
) -> Result<Arc<dyn DestinationChain + Send + Sync>> {
    match &chain_data.rpc_url {
        RpcUrl::Http(connection_url) => {
            let provider = Provider::<Http>::try_connect(connection_url).await?;
            let chain_id = provider.get_chainid().await?;
            let signer = chain_data
                .signer_wallet
                .clone()
                .ok_or(Report::msg("Signer wallet in chain data is None."))?
                .with_chain_id(chain_id.as_u64());
            let signing_middleware = SignerMiddleware::new(provider.clone(), signer);
            let ultra_light_node_v2 = UltraLightNodev2::new(
                chain_data
                    .ultra_light_node_v2_address
                    .ok_or(Report::msg("Ultra light node v2 address is none"))?,
                Arc::new(signing_middleware),
            );
            let endpoint = Endpoint::new(chain_data.endpoint_address, Arc::new(provider.clone()));

            Ok(Arc::new(DestinationChainImpl::new(
                chain_data.layerzero_id,
                provider,
                ultra_light_node_v2,
                endpoint,
                chain_data.user_application_addresses.clone(),
            )))
        }
        RpcUrl::Ws(connection_url) => {
            let provider = Provider::<Ws>::connect(connection_url).await?;
            let chain_id = provider.get_chainid().await?;
            let signer = chain_data
                .signer_wallet
                .clone()
                .ok_or(Report::msg("Signer wallet in chain data is None."))?
                .with_chain_id(chain_id.as_u64());
            let signing_middleware = SignerMiddleware::new(provider.clone(), signer);
            let ultra_light_node_v2 = UltraLightNodev2::new(
                chain_data
                    .ultra_light_node_v2_address
                    .ok_or(Report::msg("Ultra light node v2 address is none"))?,
                Arc::new(signing_middleware),
            );
            let endpoint = Endpoint::new(chain_data.endpoint_address, Arc::new(provider.clone()));

            Ok(Arc::new(DestinationChainImpl::new(
                chain_data.layerzero_id,
                provider,
                ultra_light_node_v2,
                endpoint,
                chain_data.user_application_addresses.clone(),
            )))
        }
    }
}

#[async_trait]
impl<M: Middleware, C: JsonRpcClient> BaseChain for DestinationChainImpl<M, C> {
    fn layerzero_chain_id(&self) -> u16 {
        self.layerzero_id
    }

    async fn get_chain_id(&self) -> Result<U256> {
        self.provider.get_chainid().await.map_err(Into::into)
    }
}

#[async_trait]
impl<M: Middleware + 'static, C: JsonRpcClient + 'static> DestinationChain
    for DestinationChainImpl<M, C>
{
    async fn update_hash(
        &self,
        src_chain_id: u16,
        lookup_hash: [u8; 32],
        confirmations: U256,
        block_data: [u8; 32],
    ) -> Result<Option<TransactionReceipt>> {
        self.ultra_light_node_v2
            .update_hash(src_chain_id, lookup_hash, confirmations, block_data)
            .send()
            .await?
            .await
            .map_err(Into::into)
    }

    async fn validate_transaction_proof(
        &self,
        src_chain_id: u16,
        dst_address: Address,
        gas_limit: U256,
        lookup_hash: [u8; 32],
        block_data: [u8; 32],
        tx_proof: Bytes,
    ) -> Result<Option<TransactionReceipt>> {
        self.ultra_light_node_v2
            .validate_transaction_proof(
                src_chain_id,
                dst_address,
                gas_limit,
                lookup_hash,
                block_data,
                tx_proof,
            )
            .send()
            .await?
            .await
            .map_err(Into::into)
    }

    async fn get_inbound_nonce(
        &self,
        src_chain_id: u16,
        encoded_address_pair: Bytes,
    ) -> Result<u64> {
        self.endpoint
            .get_inbound_nonce(src_chain_id, encoded_address_pair)
            .call()
            .await
            .map_err(Into::into)
    }

    fn get_destination_addresses(&self) -> &Vec<Address> {
        &self.user_application_addresses
    }
}

pub struct ConfigurableChainImpl<M: Middleware, C: JsonRpcClient> {
    layerzero_id: u16,
    provider: Arc<Provider<C>>,
    user_application_map: HashMap<Address, UserApplication<M>>,
}

impl<M: Middleware, C: JsonRpcClient> ConfigurableChainImpl<M, C> {
    pub fn new(
        layerzero_id: u16,
        provider: Arc<Provider<C>>,
        user_application_map: HashMap<Address, UserApplication<M>>,
    ) -> Self {
        Self {
            layerzero_id,
            provider,
            user_application_map,
        }
    }
}

// setup data is passed as value, since it is not going to be shared between multiple routines
pub async fn new_configurable_chain(setup_data: SetupData) -> Result<Arc<dyn ConfigurableChain>> {
    match &setup_data.rpc_url {
        RpcUrl::Http(connection_url) => {
            let mut user_application_map = HashMap::new();
            let provider = Arc::new(Provider::<Http>::try_connect(connection_url).await?);
            let chain_id = provider.get_chainid().await?;
            for (address, wallet) in setup_data.user_application_setup_wallet {
                let signing_middleware = SignerMiddleware::new(
                    provider.clone(),
                    wallet.with_chain_id(chain_id.as_u64()),
                );
                let user_application = UserApplication::new(address, Arc::new(signing_middleware));
                user_application_map.insert(address, user_application);
            }

            Ok(Arc::new(ConfigurableChainImpl::new(
                setup_data.layerzero_id,
                provider,
                user_application_map,
            )))
        }
        RpcUrl::Ws(connection_url) => {
            let mut user_application_map = HashMap::new();
            let provider = Arc::new(Provider::<Ws>::connect(connection_url).await?);
            let chain_id = provider.get_chainid().await?;
            for (address, wallet) in setup_data.user_application_setup_wallet {
                let signing_middleware = SignerMiddleware::new(
                    provider.clone(),
                    wallet.with_chain_id(chain_id.as_u64()),
                );
                let user_application = UserApplication::new(address, Arc::new(signing_middleware));
                user_application_map.insert(address, user_application);
            }

            Ok(Arc::new(ConfigurableChainImpl::new(
                setup_data.layerzero_id,
                provider,
                user_application_map,
            )))
        }
    }
}

#[async_trait]
impl<M: Middleware, C: JsonRpcClient> BaseChain for ConfigurableChainImpl<M, C> {
    fn layerzero_chain_id(&self) -> u16 {
        self.layerzero_id
    }

    async fn get_chain_id(&self) -> Result<U256> {
        self.provider.get_chainid().await.map_err(Into::into)
    }
}

#[async_trait]
impl<M: Middleware + 'static, C: JsonRpcClient + 'static> ConfigurableChain
    for ConfigurableChainImpl<M, C>
{
    async fn get_ua_config(
        &self,
        user_application: Address,
        version: u16,
        chain_id: u16,
        config_type: U256,
    ) -> Result<Bytes> {
        let user_contract_instance =
            self.user_application_map
                .get(&user_application)
                .ok_or(Report::msg(format!(
                    "unable to find user application contract configured for {}",
                    user_application
                )))?;
        user_contract_instance
            .get_config(version, chain_id, Address::zero(), config_type)
            .call()
            .await
            .map_err(Into::into)
    }

    async fn set_ua_config(
        &self,
        user_application: Address,
        version: u16,
        chain_id: u16,
        config_type: U256,
        config: Bytes,
    ) -> Result<Option<TransactionReceipt>> {
        let user_contract_instance =
            self.user_application_map
                .get(&user_application)
                .ok_or(Report::msg(format!(
                    "unable to find user application contract configured for {}",
                    user_application
                )))?;
        user_contract_instance
            .set_config(version, chain_id, config_type, config)
            .send()
            .await?
            .await
            .map_err(Into::into)
    }
}

async fn get_last_processed_block(
    layerzero_chain_id: u16,
    shared_block_journal: &Arc<RwLock<dyn BlockJournal + Send + Sync>>,
) -> Result<Option<u64>> {
    let borrowed_block_journal = shared_block_journal.read().await;
    borrowed_block_journal
        .get_last_processed_block(layerzero_chain_id)
        .await
}

async fn complete_processing_of_block(
    layerzero_chain_id: u16,
    source_block_number: u64,
    shared_block_journal: &Arc<RwLock<dyn BlockJournal + Send + Sync>>,
) -> Result<()> {
    let mut mutable_shared_block_journal = shared_block_journal.write().await;
    mutable_shared_block_journal
        .complete_processing_of_block(layerzero_chain_id, source_block_number)
        .await
}

async fn get_logs_by_block_numbers(
    range: (u64, u64),
    source: &Arc<dyn SourceChain + Send + Sync>,
) -> Result<Vec<(u64, Vec<Log>)>> {
    let mut logs = source
        .get_endpoint_packet_logs((range.0, range.1))
        .await?
        .drain(..)
        .filter_map(|log| {
            let maybe_block_number = log.block_number;
            if maybe_block_number.is_none() {
                None
            } else {
                let block_number = maybe_block_number
                    .expect("already checked for none above; qed")
                    .as_u64();
                Some((block_number, log))
            }
        })
        .collect::<Vec<(u64, Log)>>();

    logs.sort_by(|(block_number_1, _), (block_number_2, _)| block_number_1.cmp(block_number_2));

    if logs.is_empty() {
        return Ok(vec![]);
    }

    let mut logs_by_block_num = vec![];
    let mut current_block_logs = vec![];
    let mut current_block_num = 0;
    for (log_block_num, log) in logs {
        if logs_by_block_num.is_empty() {
            current_block_num = log_block_num;
            current_block_logs.push(log);
        } else {
            if log_block_num != current_block_num {
                logs_by_block_num.push((current_block_num, current_block_logs));
                current_block_num = log_block_num;
                current_block_logs = vec![];
            } else {
                current_block_logs.push(log);
            }
        }
    }

    if !current_block_logs.is_empty() {
        logs_by_block_num.push((current_block_num, current_block_logs));
    }

    Ok(logs_by_block_num)
}

async fn log_fetching_task(
    source: Arc<dyn SourceChain + Send + Sync>,
    destination_address_set: Arc<HashSet<(u16, H160)>>,
    destination_map: Arc<HashMap<u16, Arc<dyn DestinationChain + Send + Sync>>>,
    log_sender: tokio::sync::mpsc::Sender<(u16, u64, DestPayloadGenerationData)>,
    shared_block_journal: Arc<RwLock<dyn BlockJournal + Send + Sync>>,
) -> Result<()> {
    let maybe_read_block_number =
        get_last_processed_block(source.layerzero_chain_id(), &shared_block_journal).await?;
    let starting_block = if maybe_read_block_number.is_none() {
        source.get_starting_block()
    } else {
        let read_block_number =
            maybe_read_block_number.expect("already checked for none in if branch; qed.");
        max(read_block_number, source.get_starting_block())
    };
    let mut current_starting_block = starting_block;
    loop {
        let last_finalized_block = source
            .get_block(BlockId::Number(BlockNumber::Finalized))
            .await?
            .ok_or(Report::msg("unable to find the last finalized block."))?;
        let mut last_finalized_block_number = last_finalized_block
            .number
            .ok_or(Report::msg(format!(
                "block number of block: {:?} is none.",
                last_finalized_block
            )))?
            .as_u64();
        let mut current_range = (
            current_starting_block,
            min(current_starting_block + 10, last_finalized_block_number),
        );
        println!("Current range: {:?}", current_range);
        current_starting_block = max(last_finalized_block_number + 1, current_range.0);
        println!(
            "Current starting block: {} {} {}",
            current_starting_block,
            last_finalized_block_number + 1,
            current_range.0
        );
        while current_range.0 < current_range.1 {
            let mut logs_by_block_num = get_logs_by_block_numbers(current_range, &source).await?;

            if logs_by_block_num.is_empty() {
                complete_processing_of_block(
                    source.layerzero_chain_id(),
                    current_range.1,
                    &shared_block_journal,
                )
                .await?;
            }

            current_range = (
                current_range.1 + 1,
                min(current_range.1 + 1 + 10, last_finalized_block_number),
            );
            println!("Updated range is: {:?}", current_range);

            for (log_block_number, logs) in logs_by_block_num {
                let mut did_we_found_eligible_log = false;
                for log in logs {
                    let packet_data = PacketData::read_from_log(&log.data.to_vec())?;
                    if !destination_address_set
                        .contains(&(packet_data.dst_chain_id, packet_data.dst_address))
                        && !destination_address_set
                            .contains(&(packet_data.dst_chain_id, Address::zero()))
                    {
                        // This is not a match
                        continue;
                    }
                    // Check for nonce
                    let dest =
                        destination_map
                            .get(&packet_data.dst_chain_id)
                            .ok_or(Report::msg(format!(
                                "unable to find destination chain object for chain id: {}",
                                packet_data.dst_chain_id
                            )))?;
                    let encoded_address_pair = ethers::abi::encode_packed(&[
                        Token::Address(packet_data.src_address.clone()),
                        Token::Address(packet_data.dst_address.clone()),
                    ])?;
                    let destination_inbound_nonce = dest
                        .get_inbound_nonce(packet_data.src_chain_id, encoded_address_pair.into())
                        .await?;
                    if destination_inbound_nonce + 1 != packet_data.nonce {
                        if destination_inbound_nonce + 1 > packet_data.nonce {
                            println!("The next nonce on destination chain with chain id: {} is: {} is higher than packet's nonce: {}. Ignoring packet", packet_data.dst_chain_id, destination_inbound_nonce + 1, packet_data.nonce);
                            continue;
                        } else {
                            return Err(Report::msg(format!("FATAL: The next nonce on destination chain with chain id: {} is : {} is lower than packet's nonce: {}. This could mean we started from later block than we should!!!!!", packet_data.dst_chain_id, destination_inbound_nonce + 1, packet_data.nonce)));
                        }
                    }
                    // Packet is match and nonce is valid
                    log_sender
                        .send((
                            source.layerzero_chain_id(),
                            log_block_number,
                            DestPayloadGenerationData {
                                dest_chain_id: packet_data.dst_chain_id,
                                dest_address: packet_data.dst_address,
                                target_log: log,
                            },
                        ))
                        .await?;
                    did_we_found_eligible_log = true;
                }

                // We did not find anything for this block, let's mark it complete
                if !did_we_found_eligible_log {
                    complete_processing_of_block(
                        source.layerzero_chain_id(),
                        log_block_number,
                        &shared_block_journal,
                    )
                    .await?;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5 * 60)).await;
    }
}

fn generate_receipt_proof_and_root(
    layerzero_chain_id: u16,
    receipt_proof_to_generate: u64,
    tx_receipts: &Vec<(U64, TransactionReceipt)>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());
    let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));

    for (tx_receipt_index, tx_receipt) in tx_receipts {
        let transaction_type = u8::try_from(tx_receipt.transaction_type
            .ok_or(Report::msg(format!("tx receipt for tx hash: {} does not have transaction type inside with layerzero chain id: {}", tx_receipt.transaction_hash, layerzero_chain_id)))?
            .as_u64())?;
        let encoded_receipt = match transaction_type {
            0 => rlp::encode(tx_receipt).to_vec(),
            1 | 2 | 106 => {
                let encoded_receipt = rlp::encode(tx_receipt).to_vec();
                let mut encoding_with_version = vec![transaction_type];
                encoding_with_version.extend(encoded_receipt);
                encoding_with_version
            }
            _ => {
                // Unknown transaction type
                return Err(Report::msg(format!(
                    "FATAL: unknown transaction type detected: {} for tx receipt for tx hash: {}",
                    transaction_type, tx_receipt.transaction_hash
                )));
            }
        };
        trie.insert(rlp::encode(tx_receipt_index).to_vec(), encoded_receipt)?;
    }

    let encoded_key_for_target_receipt = rlp::encode(&receipt_proof_to_generate).to_vec();
    Ok((
        trie.root()?,
        trie.get_proof(encoded_key_for_target_receipt.as_slice())?,
    ))
}

async fn create_proof_task(
    source: Arc<dyn SourceChain + Send + Sync>,
    mut log_receiver: tokio::sync::mpsc::Receiver<(u16, u64, DestPayloadGenerationData)>,
    proof_sender_map: Arc<HashMap<u16, tokio::sync::mpsc::Sender<(u16, u64, DestPayload)>>>,
) -> Result<()> {
    while let Some((
        target_log_source_chain_id,
        target_log_block_number,
        DestPayloadGenerationData {
            dest_chain_id,
            dest_address,
            target_log,
        },
    )) = log_receiver.recv().await
    {
        println!("DEBUG: Found eligible log");
        let log_block = source
            .get_block(BlockId::Number(BlockNumber::Number(U64::from(
                target_log_block_number,
            ))))
            .await?
            .ok_or(Report::msg(format!(
                "unable to find the block by number: {} for layer zero chain id: {}",
                target_log_block_number,
                source.layerzero_chain_id()
            )))?;
        let log_block_hash = log_block.hash.ok_or(Report::msg(format!(
            "block: {:?} do not have hash for layer zero chain id: {}",
            log_block,
            source.layerzero_chain_id()
        )))?;
        let log_tx_hash = target_log.transaction_hash.ok_or(Report::msg(format!(
            "log object: {:?} does not contain tx hash for layer zero chain id: {}",
            target_log, target_log_source_chain_id
        )))?;

        let mut receipt_proof_to_generate = 0;
        let mut target_log_index_in_receipt = 0;
        let mut tx_receipts = vec![];
        for tx in log_block.transactions {
            let tx_receipt = source.get_transaction_receipt(tx)
                .await?
                .ok_or(Report::msg(format!("unable to find transaction receipt for tx hash: {}, for block number: {} in layer zero chain id: {}", tx, target_log_block_number, target_log_source_chain_id)))?;

            if tx.eq(&log_tx_hash) {
                // This is the receipt for which we have to generate proof
                receipt_proof_to_generate = tx_receipt.transaction_index.as_u64();
                for (i, receipt_log) in tx_receipt.logs.iter().enumerate() {
                    if receipt_log.eq(&target_log) {
                        target_log_index_in_receipt = i as u64;
                        break;
                    }
                }
            }
            tx_receipts.push((tx_receipt.transaction_index, tx_receipt));
        }

        let (generated_root, mut generated_proof) = generate_receipt_proof_and_root(
            source.layerzero_chain_id(),
            receipt_proof_to_generate,
            &tx_receipts,
        )?;
        if !generated_root.eq(&log_block.receipts_root.0.to_vec()) {
            return Err(Report::msg(format!(
                "Mismatch Generated proof: {:?} Actual Proof: {:?}, block hash: {:?} for layerzero chain id: {}",
                hex::encode(generated_root),
                hex::encode(log_block.receipts_root.0),
                log_block_hash,
                source.layerzero_chain_id()
            )));
        }

        let encoded_key_for_target_receipt = rlp::encode(&receipt_proof_to_generate).to_vec();
        let generated_key_paths = generate_rlp_path(&encoded_key_for_target_receipt);

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
            Token::Uint(Uint::from(target_log_index_in_receipt)),
        ])
        .to_vec();

        let proof_sender_channel =
            proof_sender_map
                .get(&dest_chain_id)
                .ok_or(Report::msg(format!(
                    "unable to find proof sending channel for destination id: {}",
                    dest_chain_id
                )))?;
        proof_sender_channel
            .send((
                target_log_source_chain_id,
                target_log_block_number,
                DestPayload {
                    block_hash: log_block_hash,
                    receipts_root: log_block.receipts_root,
                    confirmations: U256::from(5),
                    dest_address,
                    tx_proof: Bytes::from(encoded_tx_proof),
                    gas_limit: U256::from(10000),
                },
            ))
            .await?;
    }

    Ok(())
}

async fn destination_tx_task(
    dest: Arc<dyn DestinationChain + Send + Sync>,
    mut proof_receiver: tokio::sync::mpsc::Receiver<(u16, u64, DestPayload)>,
    shared_block_journal: Arc<RwLock<dyn BlockJournal + Send + Sync>>,
) -> Result<()> {
    while let Some((source_chain_id, source_block_number, payload)) = proof_receiver.recv().await {
        println!("DEBUG: Sending tx to destination");
        let update_hash_tx_receipt = dest
            .update_hash(
                source_chain_id,
                payload.block_hash.0,
                payload.confirmations,
                payload.receipts_root.0,
            )
            .await?
            .ok_or(Report::msg(format!(
                "unable to call update_hash for payload: {:?}",
                payload
            )))?;
        println!(
            "Tx sent as oracle for chain_id: {} and address: {}, receipt: {:?}",
            dest.layerzero_chain_id(),
            payload.dest_address,
            update_hash_tx_receipt
        );

        let validate_tx_proof_receipt = dest
            .validate_transaction_proof(
                source_chain_id,
                payload.dest_address,
                U256::from(100000),
                payload.block_hash.0,
                payload.receipts_root.0,
                payload.tx_proof.clone(),
            )
            .await?
            .ok_or(Report::msg(format!(
                "unable to call verify tx proof for payload: {:?}",
                payload
            )))?;
        println!(
            "Tx sent as relayer for chain_id: {} and address: {}, receipt: {:?}",
            dest.layerzero_chain_id(),
            payload.dest_address,
            validate_tx_proof_receipt
        );

        complete_processing_of_block(source_chain_id, source_block_number, &shared_block_journal)
            .await?;
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleBlockJournal {
    file_to_sync: String,
    synced_data: HashMap<u16, u64>,
}

impl SimpleBlockJournal {
    async fn initialize(file_to_sync: &String) -> Result<Self> {
        let file_exists = tokio::fs::try_exists(file_to_sync).await?;
        let synced_data = if file_exists {
            let read_synced_data = tokio::fs::read(file_to_sync).await?;
            serde_json::from_slice(read_synced_data.as_slice())?
        } else {
            HashMap::new()
        };

        Ok(Self {
            file_to_sync: file_to_sync.clone(),
            synced_data,
        })
    }
}

#[async_trait]
impl BlockJournal for SimpleBlockJournal {
    async fn get_last_processed_block(&self, chain_id: u16) -> Result<Option<u64>> {
        Ok(self.synced_data.get(&chain_id).cloned())
    }

    async fn complete_processing_of_block(
        &mut self,
        chain_id: u16,
        block_number: u64,
    ) -> Result<()> {
        self.synced_data.insert(chain_id, block_number);
        let serialized_hashmap = serde_json::to_vec_pretty(&self.synced_data)?;
        tokio::fs::write(&self.file_to_sync, serialized_hashmap)
            .await
            .map_err(Into::into)
    }
}

use tokio::fs::{create_dir_all, read_dir};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<()> {
    create_dir_all("./config").await?;
    let mut result = read_dir("./config").await?;
    let mut sources: Vec<Arc<dyn SourceChain + Send + Sync>> = vec![];
    let mut destinations: Vec<Arc<dyn DestinationChain + Send + Sync>> = vec![];

    let mut block_journal_file_path = String::from("./config/blockdata.journal");
    let simple_block_journal = SimpleBlockJournal::initialize(&block_journal_file_path).await?;
    let shared_block_journal: Arc<RwLock<dyn BlockJournal + Send + Sync>> =
        Arc::new(RwLock::new(simple_block_journal));

    while let Some(entry) = result.next_entry().await? {
        let metadata = entry.metadata().await?;
        if !metadata.is_file() {
            continue;
        }

        let file_path = entry.path();
        let maybe_file_extension = file_path.extension();
        if maybe_file_extension.is_none() {
            continue;
        }
        let file_extension = maybe_file_extension
            .expect("Already checked for None above; qed")
            .to_str()
            .ok_or(Report::msg("unable to convert OsStr to str"))?;
        if !file_extension.eq_ignore_ascii_case("json") {
            continue;
        }

        let maybe_file_name = file_path.file_stem();
        if maybe_file_name.is_none() {
            continue;
        }
        let file_data = tokio::fs::read(entry.path()).await.map_err(|e| {
            Report::msg(format!(
                "Unable to read data from file: {:?} with an error: {}",
                entry.path(),
                e
            ))
        })?;
        let serialized_chain_data: SerializedChainData = serde_json::from_slice(&file_data)
            .map_err(|e| {
                Report::msg(format!(
                    "Unable to deserialize ChainData from data of file: {:?} with an error: {}",
                    entry.path(),
                    e
                ))
            })?;
        let chain_data = serialized_chain_data.to_chain().map_err(|e| {
            Report::msg(format!(
                "Unable to convert serialized ChainData to parsed chain data for file: {:?} with an error: {}",
                entry.path(),
                e
            ))
        })?;

        if chain_data.mode.is_source() {
            sources.push(new_source_chain(&chain_data).await?);
        }

        if chain_data.mode.is_destination() {
            destinations.push(new_destination_chain(&chain_data).await?);
        }
    }

    // TODO: Setup mode:

    // Normal mode:

    let mut task_join_handles = vec![];

    let mut address_set = HashSet::new();
    let mut destination_map = HashMap::new();
    let mut proof_sender_map = HashMap::new();
    // sending tx to destination
    for dest in destinations {
        let (proof_sender, proof_receiver) = tokio::sync::mpsc::channel(100);
        proof_sender_map.insert(dest.layerzero_chain_id(), proof_sender);
        let addresses = dest.get_destination_addresses();
        if addresses.is_empty() {
            address_set.insert((dest.layerzero_chain_id(), Address::zero()));
        } else {
            for address in addresses {
                address_set.insert((dest.layerzero_chain_id(), address.clone()));
            }
        }
        destination_map.insert(dest.layerzero_chain_id(), dest.clone());
        task_join_handles.push(tokio::spawn(destination_tx_task(
            dest,
            proof_receiver,
            shared_block_journal.clone(),
        )));
    }
    let shared_address_set = Arc::new(address_set);
    let shared_proof_sender_map = Arc::new(proof_sender_map);
    let shared_destination_map = Arc::new(destination_map);

    // the log fetching and filtering (Involvement: Source, destination)
    for source in sources {
        let (log_sender, log_receiver) = tokio::sync::mpsc::channel(100);
        // spawn a task with source, shared address set and log sender
        task_join_handles.push(tokio::spawn(log_fetching_task(
            source.clone(),
            shared_address_set.clone(),
            shared_destination_map.clone(),
            log_sender,
            shared_block_journal.clone(),
        )));
        // spawn a task with source, shared address set and log receiver, proof sender
        task_join_handles.push(tokio::spawn(create_proof_task(
            source.clone(),
            log_receiver,
            shared_proof_sender_map.clone(),
        )));
    }

    futures::future::join_all(task_join_handles).await;

    Ok(())
}

async fn main1() -> Result<()> {
    let event_topic_0 = H256::from(keccak256("Packet(bytes)".as_bytes()));

    let mut current_block = SRC_START_BLOCK;
    //let provider = Provider::<Http>::connect("https://endpoints.omniatech.io/v1/arbitrum/one/public").await;
    let src_provider = Provider::<Http>::connect(SRC_RPC_URL).await;
    let src_chain_id = src_provider.get_chainid().await?;

    let dst_provider = Provider::<Http>::connect(DST_RPC_URL).await;
    let dst_chain_id = dst_provider.get_chainid().await?;

    // This key must be owner of UserApplication contract
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
    let dst_oftv2_contract = UserApplication::new(DST_ADDRESS, dst_client.clone());
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
                    // DST Address whitelist this relayer. Specifically, each destination address can receive from every source
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
