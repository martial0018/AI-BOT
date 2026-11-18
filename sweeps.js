const bitcoin = require('bitcoinjs-lib');
const bs58check = require('bs58check').default;
const { isAddress } = require('ethers');
const { isValidSolanaAddress } = require('./wallet');

const sweepDestinations = [
  ['BTC', 'bitcoin', 'SWEEP_DESTINATION_BTC_BITCOIN'],
  ['ETH', 'ethereum', 'SWEEP_DESTINATION_ETH_ETHEREUM'],
  ['USDT', 'ethereum', 'SWEEP_DESTINATION_USDT_ETHEREUM'],
  ['USDT', 'tron', 'SWEEP_DESTINATION_USDT_TRON'],
  ['USDT', 'solana', 'SWEEP_DESTINATION_USDT_SOLANA'],
  ['USDT', 'bsc', 'SWEEP_DESTINATION_USDT_BSC'],
  ['SOL', 'solana', 'SWEEP_DESTINATION_SOL_SOLANA'],
  ['BNB', 'bsc', 'SWEEP_DESTINATION_BNB_BSC'],
];

const confirmationSettings = [
  'SWEEP_CONFIRMATIONS_BITCOIN',
  'SWEEP_CONFIRMATIONS_ETHEREUM',
  'SWEEP_CONFIRMATIONS_TRON',
  'SWEEP_CONFIRMATIONS_SOLANA',
  'SWEEP_CONFIRMATIONS_BSC',
];

const confirmationSettingByNetwork = {
  bitcoin: 'SWEEP_CONFIRMATIONS_BITCOIN',
  ethereum: 'SWEEP_CONFIRMATIONS_ETHEREUM',
  tron: 'SWEEP_CONFIRMATIONS_TRON',
  solana: 'SWEEP_CONFIRMATIONS_SOLANA',
  bsc: 'SWEEP_CONFIRMATIONS_BSC',
};

function isValidDestination(network, destination) {
  if (network === 'bitcoin') {
    try {
      bitcoin.address.toOutputScript(destination, bitcoin.networks.bitcoin);
      return true;
    } catch {
      return false;
    }
  }
  if (network === 'ethereum' || network === 'bsc') return isAddress(destination);
  if (network === 'solana') return isValidSolanaAddress(destination);
  if (network === 'tron') {
    try {
      const payload = bs58check.decode(destination);
      return payload.length === 21 && payload[0] === 0x41;
    } catch {
      return false;
    }
  }
  return false;
}

function planSweepEvents(deposits, env = process.env) {
  if (!Array.isArray(deposits)) throw new TypeError('Expected a deposits array.');

  return deposits.map(deposit => {
    const { txId, asset, network, amountBaseUnits, confirmations } = deposit || {};
    const destinationSetting = sweepDestinations.find(
      ([supportedAsset, supportedNetwork]) =>
        supportedAsset === asset && supportedNetwork === network
    )?.[2];
    if (!destinationSetting || !confirmationSettingByNetwork[network]) {
      return { txId: txId || null, status: 'blocked', reason: 'Unsupported asset/network.' };
    }
    if (typeof txId !== 'string' || !txId.trim()
      || typeof amountBaseUnits !== 'string' || !/^[1-9]\d*$/.test(amountBaseUnits)
      || !Number.isSafeInteger(confirmations) || confirmations < 0) {
      return { txId: txId || null, status: 'blocked', reason: 'Invalid normalized deposit event.' };
    }

    const destination = env[destinationSetting]?.trim();
    if (!destination || !isValidDestination(network, destination)) {
      return { txId, status: 'blocked', reason: 'Missing or invalid public destination address.' };
    }

    const confirmationSetting = confirmationSettingByNetwork[network];
    const confirmationThreshold = Number(env[confirmationSetting]);
    if (!Number.isSafeInteger(confirmationThreshold) || confirmationThreshold < 1) {
      return { txId, status: 'blocked', reason: 'Missing or invalid confirmation threshold.' };
    }
    if (confirmations < confirmationThreshold) {
      return {
        txId,
        asset,
        network,
        status: 'waiting-confirmations',
        confirmations,
        confirmationThreshold,
      };
    }

    return {
      txId,
      asset,
      network,
      amountBaseUnits,
      destination,
      status: 'dry-run-ready',
      confirmations,
      confirmationThreshold,
      transfersEnabled: false,
    };
  });
}

function getSweepReadiness(env = process.env) {
  const requiredSettings = [
    'CHAIN_MONITOR_URL',
    'CHAIN_MONITOR_TOKEN',
    'SWEEP_SIGNER_URL',
    'SWEEP_SIGNER_TOKEN',
    ...confirmationSettings,
    ...sweepDestinations.map(([, , setting]) => setting),
  ];
  const missing = requiredSettings.filter(setting => !env[setting]?.trim());
  return {
    configured: missing.length === 0,
    mode: missing.length === 0 ? 'configured-not-enabled' : 'disabled',
    missing,
  };
}

module.exports = { getSweepReadiness, planSweepEvents, sweepDestinations };
