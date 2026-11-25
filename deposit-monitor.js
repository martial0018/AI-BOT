const crypto = require('node:crypto');
const { isAddress } = require('ethers');

const sepoliaChainId = 11155111;
const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const signatureToleranceMs = 5 * 60 * 1000;

function getMonitorConfiguration(env = process.env) {
  const missing = [
    'SEPOLIA_RPC_URL',
    'QUICKNODE_STREAMS_SECRET',
    'SEPOLIA_CONFIRMATIONS',
  ].filter(name => !env[name]?.trim());
  if (env.SEPOLIA_RPC_URL?.trim()) {
    try {
      const rpcUrl = new URL(env.SEPOLIA_RPC_URL);
      if (rpcUrl.protocol !== 'https:'
        && !['localhost', '127.0.0.1'].includes(rpcUrl.hostname)) {
        missing.push('SEPOLIA_RPC_URL');
      }
    } catch {
      missing.push('SEPOLIA_RPC_URL');
    }
  }
  const confirmations = Number(env.SEPOLIA_CONFIRMATIONS);
  if (env.SEPOLIA_CONFIRMATIONS?.trim()
    && (!Number.isSafeInteger(confirmations) || confirmations < 1)) {
    missing.push('SEPOLIA_CONFIRMATIONS');
  }

  const tokens = {};
  for (const asset of ['USDC', 'USDT']) {
    const name = `SEPOLIA_${asset}_CONTRACT`;
    const address = env[name]?.trim();
    if (address && isAddress(address)) tokens[asset] = address;
    else if (address) missing.push(name);
  }

  return {
    configured: missing.length === 0,
    missing: [...new Set(missing)],
    confirmations: Number.isSafeInteger(confirmations) && confirmations > 0
      ? confirmations
      : null,
    tokens,
  };
}

function verifyQuickNodeSignature({
  secret,
  body,
  nonce,
  timestamp,
  signature,
  now = Date.now(),
}) {
  if (!secret || typeof body !== 'string'
    || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{8,256}$/.test(nonce)
    || typeof timestamp !== 'string' || !/^\d{10,13}$/.test(timestamp)
    || typeof signature !== 'string' || !/^[a-fA-F0-9]{64}$/.test(signature)) {
    return false;
  }

  const sentAt = Number(timestamp);
  const sentAtMs = timestamp.length <= 10 ? sentAt * 1000 : sentAt;
  if (!Number.isSafeInteger(sentAtMs) || Math.abs(now - sentAtMs) > signatureToleranceMs) {
    return false;
  }

  const expected = crypto.createHmac('sha256', secret)
    .update(nonce + timestamp + body, 'utf8')
    .digest();
  const received = Buffer.from(signature, 'hex');
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

function parseSepoliaPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Expected a JSON object payload.');
  }
  const chainId = payload.chainId;
  if (chainId !== sepoliaChainId && chainId !== '0xaa36a7') {
    throw new Error('Only Ethereum Sepolia events are accepted.');
  }
  if (!Array.isArray(payload.logs) || !Array.isArray(payload.transactions)
    || payload.logs.length + payload.transactions.length > 500) {
    throw new Error('Expected bounded logs and transactions arrays.');
  }

  const logs = payload.logs.map(log => {
    if (!log || typeof log !== 'object' || Array.isArray(log)
      || typeof log.address !== 'string' || !isAddress(log.address)
      || !Array.isArray(log.topics) || log.topics.length !== 3
      || log.topics.some(topic => typeof topic !== 'string' || !/^0x[0-9a-f]{64}$/i.test(topic))
      || log.topics[0].toLowerCase() !== transferTopic
      || !/^0x0{24}[0-9a-f]{40}$/i.test(log.topics[1])
      || !/^0x0{24}[0-9a-f]{40}$/i.test(log.topics[2])
      || typeof log.data !== 'string' || !/^0x[0-9a-f]{64}$/i.test(log.data)
      || typeof log.transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(log.transactionHash)
      || typeof log.blockHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(log.blockHash)
      || typeof log.blockNumber !== 'string' || !/^0x[0-9a-f]+$/i.test(log.blockNumber)
      || typeof log.logIndex !== 'string' || !/^0x[0-9a-f]+$/i.test(log.logIndex)
      || (log.removed !== undefined && typeof log.removed !== 'boolean')) {
      throw new Error('Invalid ERC-20 transfer log.');
    }
    return log;
  });

  const transactions = payload.transactions.map(transaction => {
    if (!transaction || typeof transaction !== 'object' || Array.isArray(transaction)
      || typeof transaction.hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(transaction.hash)
      || typeof transaction.to !== 'string' || !isAddress(transaction.to)
      || typeof transaction.value !== 'string' || !/^0x[0-9a-f]+$/i.test(transaction.value)
      || typeof transaction.blockHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(transaction.blockHash)
      || typeof transaction.blockNumber !== 'string' || !/^0x[0-9a-f]+$/i.test(transaction.blockNumber)
      || (transaction.removed !== undefined && typeof transaction.removed !== 'boolean')) {
      throw new Error('Invalid native transaction.');
    }
    return transaction;
  });

  return { logs, transactions };
}

async function rpcRequest(url, method, params, fetchImpl = fetch) {
  let endpoint;
  try {
    endpoint = new URL(url);
  } catch {
    throw new Error('SEPOLIA_RPC_URL must be a valid HTTPS URL.');
  }
  if (endpoint.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(endpoint.hostname)) {
    throw new Error('SEPOLIA_RPC_URL must use HTTPS.');
  }

  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`Sepolia RPC returned HTTP ${response.status}.`);
  const result = await response.json();
  if (result?.error || !Object.hasOwn(result || {}, 'result')) {
    throw new Error('Sepolia RPC returned an invalid response.');
  }
  return result.result;
}

module.exports = {
  getMonitorConfiguration,
  parseSepoliaPayload,
  rpcRequest,
  sepoliaChainId,
  transferTopic,
  verifyQuickNodeSignature,
};
