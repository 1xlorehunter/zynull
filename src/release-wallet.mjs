import { V9Wallet, V9Relayer } from './wallet.mjs';
import { createProductionConfig, assertRpcMatchesProductionConfig, assertMainnetReleasePolicy } from './production-config.mjs';
export async function createReleaseWallet(options) {
  const config = createProductionConfig(options.config);
  if (config.network === 'mainnet') assertMainnetReleasePolicy(config);
  const checked = await assertRpcMatchesProductionConfig(options.connection, config);
  const policy = (connection) => { if (new URL(connection.rpcEndpoint).href !== config.rpcUrl) throw Error('Кошелёк подключён к другой сети'); };
  const wallet = new V9Wallet({ ...options, programId: config.programId, connectionPolicy: policy });
  wallet.releaseConfig = config; wallet.releaseCheck = checked; return wallet;
}
export async function createReleaseRelayer(options) {
  const config = createProductionConfig(options.config);
  if (config.network === 'mainnet') assertMainnetReleasePolicy(config);
  const checked = await assertRpcMatchesProductionConfig(options.connection, config);
  const policy = (connection) => { if (new URL(connection.rpcEndpoint).href !== config.rpcUrl) throw Error('Релейер подключён к другой сети'); };
  const relayer = new V9Relayer({ ...options, programId: config.programId, connectionPolicy: policy });
  relayer.releaseConfig = config; relayer.releaseCheck = checked; return relayer;
}
