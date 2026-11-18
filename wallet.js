const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const bs58 = require('bs58').default;
const bs58check = require('bs58check').default;
const { computeAddress, SigningKey, keccak256 } = require('ethers');

bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

const assets = {
  BTC: { bitcoin: 'bitcoin' },
  ETH: { ethereum: 'evm', arbitrum: 'evm' },
  USDC: { ethereum: 'evm', arbitrum: 'evm', bsc: 'evm' },
  USDT: {
    ethereum: 'evm',
    arbitrum: 'evm',
    tron: 'tron',
    solana: 'solana',
    bsc: 'evm',
  },
  SOL: { solana: 'solana' },
  BNB: { bsc: 'evm' },
};

function deriveSecpAddress(asset, network, index, env = process.env) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
    throw new Error('Invalid deposit address index');
  }
  const derivationKind = assets[asset]?.[network];
  const xpubName = {
    bitcoin: 'BTC_ACCOUNT_XPUB',
    evm: 'EVM_ACCOUNT_XPUB',
    tron: 'TRON_ACCOUNT_XPUB',
  }[derivationKind];
  if (!xpubName) throw new Error('Unsupported secp256k1 asset/network');

  const xpub = env[xpubName];
  if (!xpub) throw new Error(`Missing account xpub for ${derivationKind}`);

  let account;
  try {
    account = bip32.fromBase58(xpub);
  } catch {
    throw new Error(`Invalid account xpub for ${derivationKind}`);
  }
  if (!account.isNeutered()) throw new Error('Only public extended keys are accepted');

  const child = account.derive(0).derive(index);
  if (!child.publicKey) throw new Error('Could not derive public child key');

  if (derivationKind === 'bitcoin') {
    const payment = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(child.publicKey),
      network: bitcoin.networks.bitcoin,
    });
    if (!payment.address) throw new Error('Could not encode Bitcoin address');
    return payment.address;
  }

  const uncompressedKey = SigningKey.computePublicKey(
    `0x${Buffer.from(child.publicKey).toString('hex')}`,
    false
  );
  if (derivationKind === 'evm') return computeAddress(uncompressedKey);

  const tronPayload = Buffer.concat([
    Buffer.from([0x41]),
    Buffer.from(keccak256(`0x${uncompressedKey.slice(4)}`).slice(-40), 'hex'),
  ]);
  return bs58check.encode(tronPayload);
}

function isValidSolanaAddress(address) {
  try {
    return bs58.decode(address).length === 32;
  } catch {
    return false;
  }
}

module.exports = { assets, deriveSecpAddress, isValidSolanaAddress };
