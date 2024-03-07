use {
    crate::connection_cache::{dispatch, ConnectionCache},
    solana_connection_cache::connection_cache::{
        ConnectionCache as BackendConnectionCache, ConnectionManager, ConnectionPool,
        NewConnectionConfig,
    },
    solana_quic_client::{QuicConfig, QuicConnectionManager, QuicPool},
    solana_rpc_client::rpc_client::RpcClient,
    solana_sdk::{
        hash::Hash,
        message::Message,
        signers::Signers,
        signer::keypair::Keypair,
        signature::Signature,
        transaction::{Transaction, TransactionError},
        transport::Result as TransportResult,
        pubkey::Pubkey,
        commitment_config::CommitmentConfig,
    },
    solana_tpu_client::tpu_client::{Result, TpuClient as BackendTpuClient},
    solana_udp_client::{UdpConfig, UdpConnectionManager, UdpPool},
    std::sync::Arc,
};
pub use {
    crate::nonblocking::tpu_client::TpuSenderError,
    solana_tpu_client::tpu_client::{TpuClientConfig, DEFAULT_FANOUT_SLOTS, MAX_FANOUT_SLOTS},
};

pub enum TpuClientWrapper {
    Quic(TpuClient<QuicPool, QuicConnectionManager, QuicConfig>),
    Udp(TpuClient<UdpPool, UdpConnectionManager, UdpConfig>),
}

impl TpuClientWrapper {
    dispatch!(pub fn poll_get_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig
    ) -> TransportResult<u64>);

    //greg: should this be pub? it isn't in thinclient. but idk how they use it then
    dispatch!(fn get_latest_blockhash_with_commitment(
        &self,
        commitment_config: CommitmentConfig
    ) -> TransportResult<(Hash, u64)>);

    dispatch!(pub fn retry_transfer_until_confirmed(&self, keypair: &Keypair, transaction: &mut Transaction, tries: usize, min_confirmed_blocks: usize) -> TransportResult<Signature>);

}

/// Client which sends transactions directly to the current leader's TPU port over UDP.
/// The client uses RPC to determine the current leader and fetch node contact info
/// This is just a thin wrapper over the "BackendTpuClient", use that directly for more efficiency.
pub struct TpuClient<
    P, // ConnectionPool
    M, // ConnectionManager
    C, // NewConnectionConfig
> {
    tpu_client: BackendTpuClient<P, M, C>,
}

impl<P, M, C> TpuClient<P, M, C>
where
    P: ConnectionPool<NewConnectionConfig = C>,
    M: ConnectionManager<ConnectionPool = P, NewConnectionConfig = C>,
    C: NewConnectionConfig,
{
    /// Serialize and send transaction to the current and upcoming leader TPUs according to fanout
    /// size
    pub fn send_transaction(&self, transaction: &Transaction) -> bool {
        self.tpu_client.send_transaction(transaction)
    }

    /// Send a wire transaction to the current and upcoming leader TPUs according to fanout size
    pub fn send_wire_transaction(&self, wire_transaction: Vec<u8>) -> bool {
        self.tpu_client.send_wire_transaction(wire_transaction)
    }

    /// Serialize and send transaction to the current and upcoming leader TPUs according to fanout
    /// size
    /// Returns the last error if all sends fail
    pub fn try_send_transaction(&self, transaction: &Transaction) -> TransportResult<()> {
        self.tpu_client.try_send_transaction(transaction)
    }

    /// Serialize and send a batch of transactions to the current and upcoming leader TPUs according
    /// to fanout size
    /// Returns the last error if all sends fail
    pub fn try_send_transaction_batch(&self, transactions: &[Transaction]) -> TransportResult<()> {
        self.tpu_client.try_send_transaction_batch(transactions)
    }

    /// Send a wire transaction to the current and upcoming leader TPUs according to fanout size
    /// Returns the last error if all sends fail
    pub fn try_send_wire_transaction(&self, wire_transaction: Vec<u8>) -> TransportResult<()> {
        self.tpu_client.try_send_wire_transaction(wire_transaction)
    }

    pub fn poll_get_balance_with_commitment(
        &self,
        pubkey: &Pubkey,
        commitment_config: CommitmentConfig,
    ) -> TransportResult<u64> {
        self.rpc_client()
            .poll_get_balance_with_commitment(pubkey, commitment_config)
            .map_err(|e| e.into())
    }

    pub fn get_latest_blockhash_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> TransportResult<(Hash, u64)> {
        self.rpc_client()
            .get_latest_blockhash_with_commitment(commitment_config)
            .map_err(|err| err.into())
    }

    /// Retry a sending a signed Transaction to the server for processing.
    pub fn retry_transfer_until_confirmed(
        &self,
        keypair: &Keypair,
        transaction: &mut Transaction,
        tries: usize,
        min_confirmed_blocks: usize,
    ) -> TransportResult<Signature> {
        self.tpu_client.send_transaction(transaction)
        // self.rpc_client().send_and_confirm_transaction(transaction)
        // self.send_and_confirm_transaction(&[keypair], transaction, tries, min_confirmed_blocks)
    }

}

impl TpuClient<QuicPool, QuicConnectionManager, QuicConfig> {
    /// Create a new client that disconnects when dropped
    pub fn new(
        rpc_client: Arc<RpcClient>,
        websocket_url: &str,
        config: TpuClientConfig,
    ) -> Result<Self> {
        let connection_cache = match ConnectionCache::new("connection_cache_tpu_client") {
            ConnectionCache::Quic(cache) => cache,
            ConnectionCache::Udp(_) => {
                return Err(TpuSenderError::Custom(String::from(
                    "Invalid default connection cache",
                )))
            }
        };
        Self::new_with_connection_cache(rpc_client, websocket_url, config, connection_cache)
    }
}

impl<P, M, C> TpuClient<P, M, C>
where
    P: ConnectionPool<NewConnectionConfig = C>,
    M: ConnectionManager<ConnectionPool = P, NewConnectionConfig = C>,
    C: NewConnectionConfig,
{
    /// Create a new client that disconnects when dropped
    pub fn new_with_connection_cache(
        rpc_client: Arc<RpcClient>,
        websocket_url: &str,
        config: TpuClientConfig,
        connection_cache: Arc<BackendConnectionCache<P, M, C>>,
    ) -> Result<Self> {
        Ok(Self {
            tpu_client: BackendTpuClient::new_with_connection_cache(
                rpc_client,
                websocket_url,
                config,
                connection_cache,
            )?,
        })
    }

    pub fn send_and_confirm_messages_with_spinner<T: Signers + ?Sized>(
        &self,
        messages: &[Message],
        signers: &T,
    ) -> Result<Vec<Option<TransactionError>>> {
        self.tpu_client
            .send_and_confirm_messages_with_spinner(messages, signers)
    }

    pub fn rpc_client(&self) -> &RpcClient {
        self.tpu_client.rpc_client()
    }
}
