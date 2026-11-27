require('dotenv').config();

const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit').rateLimit;
const QRCode = require('qrcode');
const { getSweepReadiness } = require('./sweeps');
const { deriveSecpAddress } = require('./wallet');
const { deriveTurnkeyEvmAddress, getTurnkeyConfiguration } = require('./turnkey');
const {
  getMonitorConfiguration,
  parseSepoliaPayload,
  rpcRequest,
  sepoliaChainId,
  transferTopic,
  verifyQuickNodeSignature,
} = require('./deposit-monitor');

const scrypt = promisify(crypto.scrypt);
const passwordHashN = 32768;

const publicPages = new Map([
  ['/', 'auth.html'],
  ['/auth', 'auth.html'],
  ['/auth.html', 'auth.html'],
  ['/register', 'auth.html'],
  ['/login', 'auth.html'],
  ['/dashboard', 'index.html'],
  ['/dashboard.html', 'index.html'],
  ['/index.html', 'index.html'],
  ['/bots.html', 'bots.html'],
  ['/copy-trading.html', 'copy-trading.html'],
  ['/assets.html', 'assets.html'],
]);

const app = express();
const isVercelRuntime = process.env.VERCEL === '1';
if (process.env.TRUST_PROXY === 'true' || isVercelRuntime) app.set('trust proxy', 1);
const databaseUrl = process.env.DATABASE_URL
  || process.env.DATABASE_URL_POOLED
  || process.env.POSTGRES_URL
  || process.env.DATABASE_POSTGRES_URL
  || process.env.DATABASE_PRISMA_DATABASE_URL;
let sqliteDatabase;
let postgresPool;
let databaseInitError;
let databaseReady = Promise.resolve();

const postgresSchema = `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS wallet_address_counters (
    derivation_family TEXT PRIMARY KEY,
    next_index BIGINT NOT NULL CHECK (next_index >= 0)
  );
  CREATE TABLE IF NOT EXISTS wallet_deposits (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL,
    network TEXT NOT NULL,
    address TEXT NOT NULL,
    derivation_family TEXT NOT NULL,
    derivation_index BIGINT NOT NULL CHECK (derivation_index >= 0),
    status TEXT NOT NULL CHECK (status IN ('awaiting_payment', 'confirming', 'confirmed')),
    created_at TEXT NOT NULL,
    UNIQUE (derivation_family, derivation_index),
    UNIQUE (network, address)
  );
  CREATE TABLE IF NOT EXISTS quicknode_webhook_nonces (
    nonce TEXT PRIMARY KEY,
    received_at BIGINT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS monitored_deposit_events (
    event_id TEXT PRIMARY KEY,
    deposit_id TEXT NOT NULL REFERENCES wallet_deposits(id),
    transaction_hash TEXT NOT NULL,
    event_index INTEGER NOT NULL,
    asset TEXT NOT NULL,
    amount_base_units TEXT NOT NULL,
    block_number BIGINT NOT NULL,
    block_hash TEXT NOT NULL,
    confirmations INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('confirming', 'confirmed', 'reorged')),
    updated_at TEXT NOT NULL,
    UNIQUE (transaction_hash, event_index)
  );
  CREATE TABLE IF NOT EXISTS testnet_ledger_entries (
    event_id TEXT PRIMARY KEY REFERENCES monitored_deposit_events(event_id),
    deposit_id TEXT NOT NULL REFERENCES wallet_deposits(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL,
    amount_base_units TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('credited', 'reversed')),
    updated_at TEXT NOT NULL
  )
`;

if (databaseUrl) {
  const { Pool } = require('pg');
  postgresPool = new Pool({ connectionString: databaseUrl, max: 5, connectionTimeoutMillis: 5000 });
  databaseReady = postgresPool.query(postgresSchema).catch(error => {
    databaseInitError = error;
    console.error(
      'Persistent PostgreSQL initialization failed:',
      error.code || error.name || 'database error'
    );
  });
} else if (!isVercelRuntime) {
  const Database = require('better-sqlite3');
  const databasePath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'deposits.sqlite');
  require('node:fs').mkdirSync(path.dirname(databasePath), { recursive: true });
  sqliteDatabase = new Database(databasePath);
  sqliteDatabase.pragma('journal_mode = WAL');
  sqliteDatabase.pragma('busy_timeout = 5000');
  sqliteDatabase.exec(`
  CREATE TABLE IF NOT EXISTS shieldz_deposits (
    id TEXT PRIMARY KEY,
    invoice_id TEXT NOT NULL UNIQUE,
    amount_usd_cents INTEGER NOT NULL CHECK (amount_usd_cents > 0),
    settlement_asset TEXT NOT NULL DEFAULT 'USDT',
    settlement_network TEXT NOT NULL DEFAULT 'base',
    settlement_chain TEXT NOT NULL DEFAULT 'BASE',
    pay_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'expired', 'failed')),
    expires_at INTEGER,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS wallet_address_counters (
    derivation_family TEXT PRIMARY KEY,
    next_index INTEGER NOT NULL CHECK (next_index >= 0)
  );
  CREATE TABLE IF NOT EXISTS wallet_deposits (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL,
    network TEXT NOT NULL,
    address TEXT NOT NULL,
    derivation_family TEXT NOT NULL,
    derivation_index INTEGER NOT NULL CHECK (derivation_index >= 0),
    status TEXT NOT NULL CHECK (status IN ('awaiting_payment', 'confirming', 'confirmed')),
    created_at TEXT NOT NULL,
    UNIQUE (derivation_family, derivation_index),
    UNIQUE (network, address)
  );
  CREATE TABLE IF NOT EXISTS quicknode_webhook_nonces (
    nonce TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS monitored_deposit_events (
    event_id TEXT PRIMARY KEY,
    deposit_id TEXT NOT NULL REFERENCES wallet_deposits(id),
    transaction_hash TEXT NOT NULL,
    event_index INTEGER NOT NULL,
    asset TEXT NOT NULL,
    amount_base_units TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    confirmations INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('confirming', 'confirmed', 'reorged')),
    updated_at TEXT NOT NULL,
    UNIQUE (transaction_hash, event_index)
  );
  CREATE TABLE IF NOT EXISTS testnet_ledger_entries (
    event_id TEXT PRIMARY KEY REFERENCES monitored_deposit_events(event_id),
    deposit_id TEXT NOT NULL REFERENCES wallet_deposits(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL,
    amount_base_units TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('credited', 'reversed')),
    updated_at TEXT NOT NULL
  );
  `);
  sqliteDatabase.pragma('foreign_keys = ON');
  sqliteDatabase.exec(`
    INSERT OR IGNORE INTO wallet_address_counters (derivation_family, next_index)
    SELECT derivation_family, MAX(derivation_index) + 1
    FROM wallet_deposits
    GROUP BY derivation_family
  `);
  databaseReady = Promise.resolve();
}

function isDatabaseConfigured() {
  return Boolean(sqliteDatabase || postgresPool);
}

async function ensureDatabaseReady() {
  await databaseReady;
  if (!isDatabaseConfigured()) {
    throw new Error('Persistent database is not configured. Add DATABASE_URL in the deployment environment.');
  }
  if (databaseInitError) throw new Error('Persistent database is unavailable.');
}

function postgresPlaceholders(statement) {
  let index = 0;
  return statement.replace(/\?/g, () => `$${++index}`);
}

async function databaseGet(statement, parameters = []) {
  await ensureDatabaseReady();
  if (postgresPool) {
    const result = await postgresPool.query(postgresPlaceholders(statement), parameters);
    return result.rows[0];
  }
  return sqliteDatabase.prepare(statement).get(...parameters);
}

async function databaseAll(statement, parameters = []) {
  await ensureDatabaseReady();
  if (postgresPool) {
    const result = await postgresPool.query(postgresPlaceholders(statement), parameters);
    return result.rows;
  }
  return sqliteDatabase.prepare(statement).all(...parameters);
}

async function databaseRun(statement, parameters = []) {
  await ensureDatabaseReady();
  if (postgresPool) return postgresPool.query(postgresPlaceholders(statement), parameters);
  return sqliteDatabase.prepare(statement).run(...parameters);
}

const depositColumns = new Set(
  sqliteDatabase?.pragma('table_info(shieldz_deposits)').map(column => column.name) || []
);
if (!depositColumns.has('settlement_asset')) {
  sqliteDatabase?.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_asset TEXT NOT NULL DEFAULT 'USDT'");
}
if (!depositColumns.has('settlement_network')) {
  sqliteDatabase?.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_network TEXT NOT NULL DEFAULT 'base'");
}
if (!depositColumns.has('settlement_chain')) {
  sqliteDatabase?.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_chain TEXT NOT NULL DEFAULT 'BASE'");
}

const depositOptionCodes = {
  'BTC:Bitcoin': 'bitcoin',
  'ETH:Ethereum': 'ethereum',
  'ETH:Sepolia': 'ethereum',
  'ETH:Arbitrum': 'arbitrum',
  'USDC:Ethereum': 'ethereum',
  'USDC:Sepolia': 'ethereum',
  'USDC:Arbitrum': 'arbitrum',
  'USDC:BNB Chain': 'bsc',
  'USDT:Ethereum': 'ethereum',
  'USDT:Sepolia': 'ethereum',
  'USDT:Arbitrum': 'arbitrum',
  'USDT:BNB Chain': 'bsc',
  'USDT:Tron': 'tron',
};
const depositDerivationFamilies = {
  bitcoin: { envKey: 'BTC_ACCOUNT_XPUB', family: 'bitcoin' },
  ethereum: { envKey: 'EVM_ACCOUNT_XPUB', family: 'evm' },
  arbitrum: { envKey: 'EVM_ACCOUNT_XPUB', family: 'evm' },
  bsc: { envKey: 'EVM_ACCOUNT_XPUB', family: 'evm' },
  tron: { envKey: 'TRON_ACCOUNT_XPUB', family: 'tron' },
};

function getDepositOptions(env = process.env) {
  const turnkeyConfigured = getTurnkeyConfiguration(env).configured;
  const monitorConfigured = getMonitorConfiguration(env).configured;
  const groups = [
    ...getShieldzSupportedPaymentGroups(),
    {
      name: 'Sepolia testnet only',
      options: [
        { asset: 'ETH', network: 'Sepolia', label: 'ETH · Sepolia testnet' },
        { asset: 'USDC', network: 'Sepolia', label: 'USDC · Sepolia testnet' },
        { asset: 'USDT', network: 'Sepolia', label: 'USDT · Sepolia testnet' },
      ],
    },
  ];
  return groups.map(group => ({
    ...group,
    options: group.options.map(option => ({
      ...option,
      networkCode: depositOptionCodes[`${option.asset}:${option.network}`],
      addressReady: isDepositAddressIssuanceAllowed(env, option.network)
        && isDepositAddressReady(
          depositOptionCodes[`${option.asset}:${option.network}`], env, turnkeyConfigured
        )
        && (option.network !== 'Sepolia'
          || (monitorConfigured
            && env.SEPOLIA_DEPOSITS_ENABLED === 'true'
            && (option.asset === 'ETH' || Boolean(env[`SEPOLIA_${option.asset}_CONTRACT`])))),
    })),
  }));
}

function isDepositAddressIssuanceAllowed(env = process.env, network) {
  if (network === 'Sepolia') {
    return env.SEPOLIA_DEPOSITS_ENABLED === 'true'
      && getMonitorConfiguration(env).configured;
  }
  if (env.VERCEL !== '1' && env.NODE_ENV !== 'production') return true;
  return false;
}

function isDepositAddressReady(networkCode, env, turnkeyConfigured) {
  const familyConfig = depositDerivationFamilies[networkCode];
  if (!familyConfig) return false;
  const provider = env.DEPOSIT_EVM_PROVIDER?.trim().toLowerCase() || 'xpub';
  if (familyConfig.family === 'evm' && provider === 'turnkey') return turnkeyConfigured;
  if (familyConfig.family === 'evm' && provider !== 'xpub') return false;
  return Boolean(env[familyConfig.envKey]?.trim());
}

function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getCookieValue(header, name) {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=') || null;
  }
  return null;
}

function setSessionCookie(res, token) {
  const maxAge = 30 * 24 * 60 * 60;
  const secure = process.env.NODE_ENV === 'production' || isVercelRuntime ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `cv_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' || isVercelRuntime ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cv_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return res.status(403).json({ error: 'Request origin is required.' });
  let originUrl;
  try {
    originUrl = new URL(origin);
  } catch {
    return res.status(403).json({ error: 'Request origin is invalid.' });
  }
  if (originUrl.host !== req.get('host')) {
    return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
  }
  return next();
}

function requireUser(req, res, next) {
  if (req.databaseUnavailable || !isDatabaseConfigured() || databaseInitError) {
    return res.status(503).json({
      error: isDatabaseConfigured()
        ? 'Persistent database is unavailable. Check the DATABASE_URL deployment setting.'
        : 'Persistent database is not configured. Add DATABASE_URL to the Vercel project settings.',
    });
  }
  if (!req.user) return res.status(401).json({ error: 'Sign in to continue.' });
  return next();
}

function requirePersistentDatabase(req, res, next) {
  if (req.databaseUnavailable) {
    return res.status(503).json({
      error: 'Persistent database is unavailable. Check the DATABASE_URL deployment setting.',
    });
  }
  ensureDatabaseReady().then(next).catch(() => {
    res.status(503).json({
      error: 'Persistent database is unavailable. Configure DATABASE_URL in the deployment settings.',
    });
  });
}

async function createPasswordHash(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, {
    N: passwordHashN,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  return {
    salt: salt.toString('hex'),
    hash: `scrypt$${passwordHashN}$8$1$${hash.toString('hex')}`,
  };
}

async function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const match = /^scrypt\$(\d{5})\$8\$1\$([a-f0-9]{128})$/.exec(hashHex);
  if (salt.length !== 16 || !match || Number(match[1]) !== passwordHashN) return false;
  const expected = Buffer.from(match[2], 'hex');
  const actual = Buffer.from(await scrypt(password, salt, expected.length, {
    N: passwordHashN,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  }));
  return crypto.timingSafeEqual(actual, expected);
}

async function createDepositAddress({ userId, asset, network, env = process.env }) {
  const networkCode = depositOptionCodes[`${asset}:${network}`];
  const familyConfig = depositDerivationFamilies[networkCode];
  if (!networkCode || !familyConfig) throw new Error('Unsupported asset and network.');
  const evmProvider = env.DEPOSIT_EVM_PROVIDER?.trim().toLowerCase() || 'xpub';
  if (familyConfig.family === 'evm' && !['xpub', 'turnkey'].includes(evmProvider)) {
    throw new Error('Configure DEPOSIT_EVM_PROVIDER as xpub or turnkey.');
  }
  if (familyConfig.family !== 'evm' || evmProvider === 'xpub') {
    if (!env[familyConfig.envKey]?.trim()) {
      throw new Error(`Configure ${familyConfig.envKey} before creating deposit addresses.`);
    }
  } else if (!getTurnkeyConfiguration(env).configured) {
    const { missing } = getTurnkeyConfiguration(env);
    throw new Error(`Configure ${missing[0]} before creating Turnkey deposit addresses.`);
  }

  let index;
  if (postgresPool) {
    await ensureDatabaseReady();
    const client = await postgresPool.connect();
    try {
      await client.query('BEGIN');
      const { rows: [row] } = await client.query(`
        INSERT INTO wallet_address_counters (derivation_family, next_index)
        VALUES ($1, 1)
        ON CONFLICT (derivation_family)
        DO UPDATE SET next_index = wallet_address_counters.next_index + 1
        RETURNING next_index - 1 AS "nextIndex"
      `, [familyConfig.family]);
      index = Number(row.nextIndex);
      if (!Number.isSafeInteger(index) || index >= 0x80000000) {
        throw new Error('Deposit address index limit reached.');
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } else {
    const reserve = sqliteDatabase.transaction(() => {
      const row = sqliteDatabase.prepare(`
        SELECT next_index AS nextIndex
        FROM wallet_address_counters WHERE derivation_family = ?
      `).get(familyConfig.family);
      if (!row) {
        sqliteDatabase.prepare(`
          INSERT INTO wallet_address_counters (derivation_family, next_index) VALUES (?, 1)
        `).run(familyConfig.family);
        return 0;
      }
      sqliteDatabase.prepare(`
        UPDATE wallet_address_counters SET next_index = next_index + 1
        WHERE derivation_family = ?
      `).run(familyConfig.family);
      return Number(row.nextIndex);
    });
    index = reserve.immediate();
  }

  if (!Number.isSafeInteger(index) || index >= 0x80000000) {
    throw new Error('Deposit address index limit reached.');
  }
  const address = familyConfig.family === 'evm' && evmProvider === 'turnkey'
    ? await deriveTurnkeyEvmAddress(index, env)
    : deriveSecpAddress(asset, networkCode, index, env);
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  await databaseRun(`
    INSERT INTO wallet_deposits (
      id, user_id, asset, network, address, derivation_family,
      derivation_index, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'awaiting_payment', ?)
  `, [id, userId, asset, network, address, familyConfig.family, index, createdAt]);
  return { id, asset, network, address, status: 'awaiting_payment', createdAt };
}

async function findSepoliaDeposit(address) {
  if (!isEthereumAddress(address)) return undefined;
  return databaseGet(`
    SELECT id, asset, network, address
    FROM wallet_deposits
    WHERE network = 'Sepolia' AND LOWER(address) = LOWER(?)
  `, [address]);
}

function isEthereumAddress(address) {
  return typeof address === 'string' && /^0x[0-9a-f]{40}$/i.test(address);
}

function matchingReceiptLog(receipt, event) {
  return Array.isArray(receipt?.logs) && receipt.logs.some(log =>
    typeof log.logIndex === 'string'
    && Number.parseInt(log.logIndex, 16) === Number.parseInt(event.logIndex, 16)
    && log.address?.toLowerCase() === event.address.toLowerCase()
    && log.transactionHash?.toLowerCase() === event.transactionHash.toLowerCase()
    && log.blockHash?.toLowerCase() === event.blockHash.toLowerCase()
    && JSON.stringify(log.topics?.map(topic => topic.toLowerCase()))
      === JSON.stringify(event.topics.map(topic => topic.toLowerCase()))
    && log.data?.toLowerCase() === event.data.toLowerCase()
    && log.removed !== true
  );
}

async function verifySepoliaEvent(event, type, configuration, rpcUrl, latestBlock) {
  const transactionHash = type === 'log' ? event.transactionHash : event.hash;
  const receipt = await rpcRequest(rpcUrl, 'eth_getTransactionReceipt', [transactionHash]);
  const blockNumber = Number.parseInt(event.blockNumber, 16);
  const blockHash = event.blockHash.toLowerCase();
  if (!receipt || receipt.status !== '0x1'
    || receipt.transactionHash?.toLowerCase() !== transactionHash.toLowerCase()
    || receipt.blockHash?.toLowerCase() !== blockHash
    || receipt.blockNumber !== event.blockNumber) {
    return { status: 'reorged' };
  }

  let deposit;
  let asset;
  let amountBaseUnits;
  let eventIndex;
  if (type === 'log') {
    const token = Object.entries(configuration.tokens).find(
      ([, contract]) => contract.toLowerCase() === event.address.toLowerCase()
    );
    if (!token || !matchingReceiptLog(receipt, event)) return null;
    const recipient = `0x${event.topics[2].slice(-40)}`;
    deposit = await findSepoliaDeposit(recipient);
    asset = token[0];
    amountBaseUnits = BigInt(event.data).toString();
    if (amountBaseUnits === '0') return null;
    eventIndex = Number.parseInt(event.logIndex, 16);
  } else {
    const transaction = await rpcRequest(rpcUrl, 'eth_getTransactionByHash', [event.hash]);
    if (!transaction || transaction.hash?.toLowerCase() !== event.hash.toLowerCase()
      || transaction.to?.toLowerCase() !== event.to.toLowerCase()
      || transaction.value !== event.value
      || transaction.blockHash?.toLowerCase() !== blockHash
      || transaction.blockNumber !== event.blockNumber
      || BigInt(event.value) <= 0n) {
      return null;
    }
    deposit = await findSepoliaDeposit(event.to);
    asset = 'ETH';
    amountBaseUnits = BigInt(event.value).toString();
    eventIndex = -1;
  }

  if (!deposit || !['ETH', 'USDC', 'USDT'].includes(deposit.asset)
    || (asset !== 'ETH' && deposit.asset !== asset)) return null;

  const confirmations = Math.max(0, latestBlock - blockNumber + 1);
  const status = confirmations >= configuration.confirmations ? 'confirmed' : 'confirming';
  return {
    eventId: `${transactionHash.toLowerCase()}:${eventIndex}`,
    depositId: deposit.id,
    transactionHash: transactionHash.toLowerCase(),
    eventIndex,
    asset,
    amountBaseUnits,
    blockNumber,
    blockHash,
    confirmations,
    status,
  };
}

async function storeSepoliaEvent(event) {
  await databaseRun(`
    INSERT INTO monitored_deposit_events (
      event_id, deposit_id, transaction_hash, event_index, asset,
      amount_base_units, block_number, block_hash, confirmations, status, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (transaction_hash, event_index) DO UPDATE SET
      deposit_id = excluded.deposit_id,
      asset = excluded.asset,
      amount_base_units = excluded.amount_base_units,
      block_number = excluded.block_number,
      block_hash = excluded.block_hash,
      confirmations = excluded.confirmations,
      status = excluded.status,
      updated_at = excluded.updated_at
  `, [
    event.eventId,
    event.depositId,
    event.transactionHash,
    event.eventIndex,
    event.asset,
    event.amountBaseUnits,
    event.blockNumber,
    event.blockHash,
    event.confirmations,
    event.status,
    new Date().toISOString(),
  ]);
  await syncTestnetLedgerEntry(event.eventId);
}

async function syncTestnetLedgerEntry(eventId) {
  const now = new Date().toISOString();
  await databaseRun(`
    INSERT INTO testnet_ledger_entries (
      event_id, deposit_id, user_id, asset, amount_base_units,
      block_hash, status, updated_at
    )
    SELECT event.event_id, event.deposit_id, deposit.user_id, event.asset,
      event.amount_base_units, event.block_hash, 'credited', ?
    FROM monitored_deposit_events AS event
    JOIN wallet_deposits AS deposit ON deposit.id = event.deposit_id
    WHERE event.event_id = ? AND event.status = 'confirmed'
    ON CONFLICT (event_id) DO UPDATE SET
      deposit_id = excluded.deposit_id,
      user_id = excluded.user_id,
      asset = excluded.asset,
      amount_base_units = excluded.amount_base_units,
      block_hash = excluded.block_hash,
      status = 'credited',
      updated_at = excluded.updated_at
  `, [now, eventId]);
  await databaseRun(`
    UPDATE testnet_ledger_entries
    SET status = 'reversed', updated_at = ?
    WHERE event_id = ? AND status = 'credited'
      AND EXISTS (
        SELECT 1 FROM monitored_deposit_events
        WHERE event_id = ? AND status != 'confirmed'
      )
  `, [now, eventId, eventId]);
}

async function markSepoliaEventReorged(event, type, configuration) {
  let recipient;
  let asset;
  let transactionHash;
  let eventIndex;
  let amountBaseUnits;
  let blockNumber;
  let blockHash;
  if (type === 'log') {
    const token = Object.entries(configuration.tokens).find(
      ([, address]) => address.toLowerCase() === event.address.toLowerCase()
    );
    if (!token) return false;
    recipient = `0x${event.topics[2].slice(-40)}`;
    asset = token[0];
    transactionHash = event.transactionHash.toLowerCase();
    eventIndex = Number.parseInt(event.logIndex, 16);
    amountBaseUnits = BigInt(event.data).toString();
  } else {
    recipient = event.to;
    asset = 'ETH';
    transactionHash = event.hash.toLowerCase();
    eventIndex = -1;
    amountBaseUnits = BigInt(event.value).toString();
  }
  const deposit = await findSepoliaDeposit(recipient);
  if (!deposit || deposit.asset !== asset) return false;
  blockNumber = Number.parseInt(event.blockNumber, 16);
  blockHash = event.blockHash.toLowerCase();
  await storeSepoliaEvent({
    eventId: `${transactionHash}:${eventIndex}`,
    depositId: deposit.id,
    transactionHash,
    eventIndex,
    asset,
    amountBaseUnits,
    blockNumber,
    blockHash,
    confirmations: 0,
    status: 'reorged',
  });
  return true;
}

async function reconcileSepoliaEvents(latestBlock, configuration, rpcUrl) {
  const rows = await databaseAll(`
    SELECT event_id AS "eventId", transaction_hash AS "transactionHash",
      block_number AS "blockNumber", block_hash AS "blockHash", confirmations, status
    FROM monitored_deposit_events
    WHERE status = 'confirming' OR (status = 'confirmed' AND block_number >= ?)
    ORDER BY block_number DESC
    LIMIT 500
  `, [Math.max(0, latestBlock - 128)]);
  let confirmed = 0;
  let reorged = 0;
  for (const event of rows) {
    const receipt = await rpcRequest(
      rpcUrl, 'eth_getTransactionReceipt', [event.transactionHash]
    );
    const canonical = receipt?.status === '0x1'
      && receipt.transactionHash?.toLowerCase() === event.transactionHash.toLowerCase()
      && receipt.blockHash?.toLowerCase() === event.blockHash.toLowerCase()
      && Number.parseInt(receipt.blockNumber, 16) === Number(event.blockNumber);
    const confirmations = canonical
      ? Math.max(0, latestBlock - Number(event.blockNumber) + 1)
      : 0;
    const status = canonical
      ? confirmations >= configuration.confirmations ? 'confirmed' : 'confirming'
      : 'reorged';
    await databaseRun(`
      UPDATE monitored_deposit_events
      SET confirmations = ?, status = ?, updated_at = ?
      WHERE event_id = ?
    `, [confirmations, status, new Date().toISOString(), event.eventId]);
    await syncTestnetLedgerEntry(event.eventId);
    if (status === 'confirmed') confirmed += 1;
    if (status === 'reorged') reorged += 1;
  }
  return { reconciled: rows.length, confirmed, reorged };
}

async function processSepoliaPayload(payload, env = process.env) {
  const configuration = getMonitorConfiguration(env);
  if (!configuration.configured) {
    throw new Error(`Configure ${configuration.missing[0]} before monitoring Sepolia deposits.`);
  }
  const { logs, transactions } = parseSepoliaPayload(payload);
  const rpcUrl = env.SEPOLIA_RPC_URL.trim();
  const chainId = await rpcRequest(rpcUrl, 'eth_chainId', []);
  if (typeof chainId !== 'string'
    || chainId.toLowerCase() !== `0x${sepoliaChainId.toString(16)}`) {
    throw new Error('Configured RPC endpoint is not connected to Ethereum Sepolia.');
  }
  const head = await rpcRequest(rpcUrl, 'eth_blockNumber', []);
  if (typeof head !== 'string' || !/^0x[0-9a-f]+$/i.test(head)) {
    throw new Error('Sepolia RPC returned an invalid latest block.');
  }
  const latestBlock = Number.parseInt(head, 16);
  const recorded = [];
  let reorged = 0;
  for (const [type, events] of [['log', logs], ['transaction', transactions]]) {
    for (const event of events) {
      if (event.removed === true) {
        reorged += Number(await markSepoliaEventReorged(event, type, configuration));
        continue;
      }
      const verified = await verifySepoliaEvent(
        event, type, configuration, rpcUrl, latestBlock
      );
      if (!verified || verified.status === 'reorged') continue;
      await storeSepoliaEvent(verified);
      recorded.push({
        asset: verified.asset,
        amountBaseUnits: verified.amountBaseUnits,
        confirmations: verified.confirmations,
        status: verified.status,
      });
    }
  }
  const reconciliation = await reconcileSepoliaEvents(latestBlock, configuration, rpcUrl);
  return {
    recorded,
    reorged,
    reconciliation,
    dryRunSweeps: recorded.map(event => ({
      asset: event.asset,
      amountBaseUnits: event.amountBaseUnits,
      status: event.status === 'confirmed' ? 'eligible-for-manual-review' : 'waiting-confirmations',
      transfersEnabled: false,
    })),
    transfersEnabled: false,
  };
}

let sepoliaRpcPollCursor = null;
let sepoliaRpcPollTimer = null;

async function pollSepoliaRpc(env = process.env) {
  const configuration = getMonitorConfiguration(env);
  if (!configuration.configured
    || env.SEPOLIA_MONITOR_MODE?.trim().toLowerCase() !== 'rpc'
    || env.SEPOLIA_DEPOSITS_ENABLED !== 'true') {
    return { skipped: true };
  }

  const rpcUrl = env.SEPOLIA_RPC_URL.trim();
  const headResult = await rpcRequest(rpcUrl, 'eth_blockNumber', []);
  if (typeof headResult !== 'string' || !/^0x[0-9a-f]+$/i.test(headResult)) {
    throw new Error('Sepolia RPC returned an invalid latest block.');
  }
  const head = Number.parseInt(headResult, 16);
  if (sepoliaRpcPollCursor === null) {
    sepoliaRpcPollCursor = Math.max(0, head - 20);
  }
  const start = Math.min(sepoliaRpcPollCursor, head);
  const end = head;
  const logs = [];

  if (Object.keys(configuration.tokens).length > 0) {
    const contractAddresses = Object.values(configuration.tokens);
    const rangeSize = 100;
    for (let rangeStart = start; rangeStart <= end; rangeStart += rangeSize) {
      const rangeEnd = Math.min(end, rangeStart + rangeSize - 1);
      const rangeLogs = await rpcRequest(rpcUrl, 'eth_getLogs', [{
        address: contractAddresses,
        topics: [transferTopic],
        fromBlock: `0x${rangeStart.toString(16)}`,
        toBlock: `0x${rangeEnd.toString(16)}`,
      }]);
      if (!Array.isArray(rangeLogs)) {
        throw new Error('Sepolia RPC returned invalid log data.');
      }
      logs.push(...rangeLogs);
    }
  }

  const transactions = [];
  for (let blockNumber = start; blockNumber <= end; blockNumber += 1) {
    const block = await rpcRequest(
      rpcUrl,
      'eth_getBlockByNumber',
      [`0x${blockNumber.toString(16)}`, true]
    );
    if (!block?.hash || !/^0x[0-9a-f]{64}$/i.test(block.hash)
      || !Array.isArray(block.transactions)) continue;
    for (const transaction of block.transactions) {
      if (typeof transaction?.to !== 'string'
        || typeof transaction.hash !== 'string'
        || typeof transaction.value !== 'string') continue;
      const deposit = await findSepoliaDeposit(transaction.to);
      if (!deposit || deposit.asset !== 'ETH') continue;
      transactions.push({
        hash: transaction.hash,
        to: transaction.to,
        value: transaction.value,
        blockHash: block.hash,
        blockNumber: `0x${blockNumber.toString(16)}`,
      });
    }
  }

  sepoliaRpcPollCursor = end + 1;
  return processSepoliaPayload({
    chainId: sepoliaChainId,
    logs,
    transactions,
  }, env);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.tailwindcss.com'],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
      connectSrc: ["'self'", 'https://api.coingecko.com'],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  skip: req => req.path === '/monitor/quicknode',
}));
app.use(async (req, _res, next) => {
  try {
    await databaseReady;
    if (databaseInitError) {
      req.databaseUnavailable = true;
      return next();
    }
    const token = getCookieValue(req.get('cookie'), 'cv_session');
    if (token && /^[A-Za-z0-9_-]{40,}$/.test(token) && isDatabaseConfigured()) {
      req.user = await databaseGet(`
        SELECT users.id, users.email, users.name
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
      `, [hashSessionToken(token), Date.now()]);
    }
    next();
  } catch (error) {
    req.databaseUnavailable = true;
    console.error('Session lookup failed:', error.message);
    next();
  }
});

app.post(
  '/api/monitor/quicknode',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }),
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {
    const configuration = getMonitorConfiguration();
    if (!configuration.configured) {
      return res.status(503).json({
        error: 'Sepolia monitoring is not configured.',
        missing: configuration.missing,
      });
    }

    if (!Buffer.isBuffer(req.body)) {
      return res.status(400).json({ error: 'Expected an application/json payload.' });
    }
    const body = req.body.toString('utf8');
    const nonce = req.get('x-qn-nonce');
    const timestamp = req.get('x-qn-timestamp');
    if (!verifyQuickNodeSignature({
      secret: process.env.QUICKNODE_STREAMS_SECRET,
      body,
      nonce,
      timestamp,
      signature: req.get('x-qn-signature'),
    })) {
      return res.status(401).json({ error: 'Invalid QuickNode signature.' });
    }

    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON payload.' });
    }

    await databaseRun(
      'DELETE FROM quicknode_webhook_nonces WHERE received_at < ?',
      [Date.now() - 24 * 60 * 60 * 1000]
    );
    try {
      await databaseRun(
        'INSERT INTO quicknode_webhook_nonces (nonce, received_at) VALUES (?, ?)',
        [nonce, Date.now()]
      );
    } catch (error) {
      if (error.code === '23505' || error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY'
        || error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(200).json({ accepted: true, duplicate: true });
      }
      throw error;
    }

    try {
      const result = await processSepoliaPayload(payload);
      return res.status(200).json({
        accepted: true,
        network: 'ethereum-sepolia',
        ...result,
        warning: 'Testnet observations only. No account balances are credited and no transactions are sent.',
      });
    } catch (error) {
      await databaseRun('DELETE FROM quicknode_webhook_nonces WHERE nonce = ?', [nonce]);
      console.error('Sepolia webhook processing failed:', error.name || 'Error');
      return res.status(503).json({ error: 'Sepolia event verification failed; QuickNode may retry.' });
    }
  }
);

app.use(express.json({ limit: '4kb', type: 'application/json' }));

app.post('/api/auth/register', requireSameOrigin, requirePersistentDatabase, async (req, res) => {
  const { email, name, password, passwordConfirmation } = req.body || {};
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  const normalizedName = typeof name === 'string' ? name.trim() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || normalizedEmail.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (!normalizedName || normalizedName.length > 100) {
    return res.status(400).json({ error: 'Enter a name between 1 and 100 characters.' });
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 12 and 128 characters.' });
  }
  if (password !== passwordConfirmation) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  const credentials = await createPasswordHash(password);
  const user = { id: crypto.randomUUID(), email: normalizedEmail, name: normalizedName };
  const createdAt = new Date().toISOString();
  try {
    await databaseRun(`
      INSERT INTO users (id, email, name, password_salt, password_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [user.id, user.email, user.name, credentials.salt, credentials.hash, createdAt]);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE' || error.code === '23505') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    throw error;
  }
  const token = crypto.randomBytes(32).toString('base64url');
  await databaseRun(`
    INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)
  `, [hashSessionToken(token), user.id, Date.now() + 30 * 24 * 60 * 60 * 1000, createdAt]);
  setSessionCookie(res, token);
  return res.status(201).json({ user });
});

app.post('/api/auth/login', requireSameOrigin, requirePersistentDatabase, async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  if (!normalizedEmail || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }
  const account = await databaseGet(`
    SELECT id, email, name, password_salt, password_hash FROM users WHERE email = ?
  `, [normalizedEmail]);
  const valid = account
    ? await verifyPassword(password, account.password_salt, account.password_hash)
    : false;
  if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' });

  const token = crypto.randomBytes(32).toString('base64url');
  const createdAt = new Date().toISOString();
  await databaseRun(`
    INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)
  `, [hashSessionToken(token), account.id, Date.now() + 30 * 24 * 60 * 60 * 1000, createdAt]);
  setSessionCookie(res, token);
  return res.json({ user: { id: account.id, email: account.email, name: account.name } });
});

app.get('/api/auth/session', requirePersistentDatabase, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Sign in to continue.' });
  res.json({ user: req.user });
});

app.post('/api/auth/logout', requireSameOrigin, async (req, res) => {
  const token = getCookieValue(req.get('cookie'), 'cv_session');
  if (token) {
    try {
      await databaseRun('DELETE FROM sessions WHERE token_hash = ?', [hashSessionToken(token)]);
    } catch {
      return res.status(503).json({ error: 'Could not sign out because the persistent database is unavailable.' });
    }
  }
  clearSessionCookie(res);
  res.json({ status: 'ok' });
});

const shieldzApiBase = 'https://shieldz.cash/api/v1';
const shieldzInvoiceStatuses = new Set(['pending', 'paid', 'expired', 'failed']);
const shieldzSupportedPaymentGroups = [
  {
    name: 'Native coins',
    options: [
      { asset: 'BTC', network: 'Bitcoin', label: 'BTC · Bitcoin' },
      { asset: 'ETH', network: 'Ethereum', label: 'ETH · Ethereum' },
      { asset: 'ETH', network: 'Arbitrum', label: 'ETH · Arbitrum' },
      { asset: 'ETH', network: 'Base', label: 'ETH · Base' },
      { asset: 'ETH', network: 'Optimism', label: 'ETH · Optimism' },
      { asset: 'BNB', network: 'BNB Chain', label: 'BNB · BNB Chain' },
      { asset: 'AVAX', network: 'Avalanche', label: 'AVAX · Avalanche' },
      { asset: 'TRX', network: 'Tron', label: 'TRX · Tron' },
      { asset: 'LTC', network: 'Litecoin', label: 'LTC · Litecoin' },
      { asset: 'DASH', network: 'Dash', label: 'DASH · Dash' },
      { asset: 'BCH', network: 'Bitcoin Cash', label: 'BCH · Bitcoin Cash' },
      { asset: 'TON', network: 'Toncoin', label: 'TON · Toncoin' },
      { asset: 'ZEC', network: 'Zcash', label: 'ZEC · Zcash' },
    ],
  },
  {
    name: 'Stablecoins',
    options: [
      { asset: 'USDC', network: 'Ethereum', label: 'USDC · Ethereum' },
      { asset: 'USDC', network: 'Arbitrum', label: 'USDC · Arbitrum' },
      { asset: 'USDC', network: 'Optimism', label: 'USDC · Optimism' },
      { asset: 'USDC', network: 'Polygon', label: 'USDC · Polygon' },
      { asset: 'USDC', network: 'BNB Chain', label: 'USDC · BNB Chain' },
      { asset: 'USDC', network: 'Avalanche', label: 'USDC · Avalanche' },
      {
        asset: 'USDC',
        network: 'Base',
        label: 'USDC · Base',
        available: false,
        note: 'Temporarily unavailable on Shieldz',
      },
      { asset: 'USDT', network: 'Ethereum', label: 'USDT · Ethereum' },
      { asset: 'USDT', network: 'Arbitrum', label: 'USDT · Arbitrum' },
      { asset: 'USDT', network: 'Optimism', label: 'USDT · Optimism' },
      { asset: 'USDT', network: 'Polygon', label: 'USDT · Polygon' },
      { asset: 'USDT', network: 'BNB Chain', label: 'USDT · BNB Chain' },
      { asset: 'USDT', network: 'Base', label: 'USDT · Base' },
      { asset: 'USDT', network: 'Avalanche', label: 'USDT · Avalanche' },
      { asset: 'USDT', network: 'Tron', label: 'USDT · Tron' },
      { asset: 'DAI', network: 'Ethereum', label: 'DAI · Ethereum' },
      { asset: 'USDe', network: 'Ethereum', label: 'USDe · Ethereum' },
      { asset: 'USDe', network: 'Arbitrum', label: 'USDe · Arbitrum' },
      { asset: 'USDe', network: 'BNB Chain', label: 'USDe · BNB Chain' },
      { asset: 'USDe', network: 'Avalanche', label: 'USDe · Avalanche' },
      { asset: 'PYUSD', label: 'PYUSD' },
      { asset: 'USD1', label: 'USD1' },
      { asset: 'USDG', label: 'USDG' },
    ],
  },
  {
    name: 'Other tokens',
    options: [
      { asset: 'WBTC', label: 'Wrapped Bitcoin · WBTC' },
      { asset: 'cbBTC', label: 'Coinbase Wrapped BTC · cbBTC' },
      { asset: 'XAUT', label: 'Tether Gold · XAUT' },
      { asset: 'LINK', label: 'Chainlink · LINK' },
      { asset: 'UNI', label: 'Uniswap · UNI' },
      { asset: 'AAVE', label: 'Aave · AAVE' },
      { asset: 'SHIB', label: 'Shiba Inu · SHIB' },
      { asset: 'PEPE', label: 'Pepe · PEPE' },
      { asset: 'WETH', label: 'Wrapped Ether · WETH' },
      { asset: 'WETH', network: 'Arbitrum', label: 'WETH · Arbitrum' },
      { asset: 'WETH', network: 'Base', label: 'WETH · Base' },
      { asset: 'WETH', network: 'Optimism', label: 'WETH · Optimism' },
      { asset: 'ARB', label: 'Arbitrum · ARB' },
    ],
  },
];
const requestedPaymentAssets = new Set(['BTC', 'ETH', 'USDC', 'USDT']);
const requestedPaymentNetworks = {
  BTC: new Set(['Bitcoin']),
  ETH: new Set(['Ethereum', 'Arbitrum']),
  USDC: new Set(['Ethereum', 'Arbitrum', 'BNB Chain']),
  USDT: new Set(['Ethereum', 'Arbitrum', 'BNB Chain', 'Tron']),
};

function getPaymentNetworkLabel(asset, network) {
  if (network === 'Ethereum') return `${asset} · ERC20 (Ethereum)`;
  if (network === 'BNB Chain') return `${asset} · BEP20 (BNB Chain)`;
  if (network === 'Tron') return `${asset} · TRC20 (Tron)`;
  if (network === 'Arbitrum') return `${asset} · Arbitrum`;
  return `${asset} · Bitcoin`;
}

function getShieldzSupportedPaymentGroups() {
  return shieldzSupportedPaymentGroups
    .map(group => ({
      ...group,
      options: group.options
        .filter(option => requestedPaymentAssets.has(option.asset)
          && requestedPaymentNetworks[option.asset]?.has(option.network))
        .map(option => ({
          ...option,
          label: getPaymentNetworkLabel(option.asset, option.network),
        })),
    }))
    .filter(group => group.options.length > 0);
}

function isShieldzApiConfigured(env = process.env) {
  return Boolean(env.SHIELDZ_API_KEY?.trim());
}

function getShieldzApiKey(env) {
  if (!isShieldzApiConfigured(env)) {
    throw new Error('Shieldz API key is not configured. Set SHIELDZ_API_KEY in .env.');
  }
  const apiKey = env.SHIELDZ_API_KEY.trim();
  return apiKey;
}

async function requestShieldz(pathname, { method = 'GET', body } = {}, {
  env = process.env,
  fetchImpl = fetch,
} = {}) {
  const response = await fetchImpl(`${shieldzApiBase}${pathname}`, {
    method,
    headers: {
      authorization: `Bearer ${getShieldzApiKey(env)}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(10000),
  });

  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error('Shieldz returned an invalid response.');
  }
  if (!response.ok) throw new Error(`Shieldz API returned HTTP ${response.status}.`);
  return result;
}

function formatShieldzSettlement(settlement) {
  if (settlement === undefined || settlement === null) return null;
  if (typeof settlement.asset !== 'string' || typeof settlement.chain !== 'string'
    || !settlement.asset.trim() || !settlement.chain.trim()) {
    throw new Error('Shieldz returned an invalid invoice settlement.');
  }
  const asset = settlement.asset.trim();
  let chain = settlement.chain.trim();
  const assetPrefix = `${chain}.`;
  const normalizedAsset = asset.startsWith(assetPrefix) ? asset.slice(assetPrefix.length) : asset;
  const network = chain.toLowerCase();
  const networkLabel = chain[0].toUpperCase() + chain.slice(1).toLowerCase();
  return { asset: normalizedAsset, network, label: `${normalizedAsset} on ${networkLabel}` };
}

async function createShieldzInvoice(amountUsdCents, options = {}) {
  if (!Number.isSafeInteger(amountUsdCents) || amountUsdCents < 100 || amountUsdCents > 10_000_000) {
    throw new Error('Enter a deposit amount between $1 and $100,000 USD.');
  }
  const result = await requestShieldz('/invoices', {
    method: 'POST',
    body: {
      amount_usd_cents: amountUsdCents,
      memo: 'CryptoVault deposit',
      idempotency_key: crypto.randomUUID(),
    },
  }, options);

  if (!result || typeof result.id !== 'string' || !result.id
    || result.amount_usd_cents !== amountUsdCents
    || result.status !== 'pending'
    || typeof result.pay_url !== 'string') {
    throw new Error('Shieldz returned an invalid invoice.');
  }
  let payUrl;
  try {
    payUrl = new URL(result.pay_url);
  } catch {
    throw new Error('Shieldz returned an invalid checkout URL.');
  }
  if (payUrl.origin !== 'https://shieldz.cash' || !payUrl.pathname.startsWith('/pay/')) {
    throw new Error('Shieldz returned an unexpected checkout URL.');
  }
  return {
    invoiceId: result.id,
    amountUsdCents: result.amount_usd_cents,
    settlement: formatShieldzSettlement(result.settlement),
    payUrl: payUrl.href,
    expiresAt: Number.isSafeInteger(result.expires_at) ? result.expires_at : null,
  };
}

async function getShieldzInvoice(invoiceId, options = {}) {
  const result = await requestShieldz(`/invoices/${encodeURIComponent(invoiceId)}`, {}, options);
  if (!result || result.id !== invoiceId || !shieldzInvoiceStatuses.has(result.status)
    || !Number.isSafeInteger(result.amount_usd_cents)) {
    throw new Error('Shieldz returned an invalid invoice status.');
  }
  return {
    status: result.status,
    amountUsdCents: result.amount_usd_cents,
    expiresAt: Number.isSafeInteger(result.expires_at) ? result.expires_at : null,
  };
}

app.get('/api/health', async (_req, res) => {
  await databaseReady;
  const configured = isDatabaseConfigured();
  const ready = configured && !databaseInitError;
  const monitorReady = getMonitorConfiguration().configured;
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ok' : 'degraded',
    mode: 'self-custody-addresses',
    monitoring: monitorReady ? 'sepolia-configured-not-verified' : 'disabled',
    persistentStorage: ready ? 'configured' : configured ? 'unavailable' : 'unconfigured',
    databaseErrorCode: databaseInitError?.code,
    databaseErrorType: databaseInitError?.name,
    setup: ready
      ? undefined
      : configured
        ? 'Check DATABASE_URL and confirm the PostgreSQL database is reachable.'
        : 'Configure DATABASE_URL with a persistent PostgreSQL database.',
  });
});

app.get('/api/sweeps/readiness', (_req, res) => {
  res.json({
    ...getSweepReadiness(),
    transfersEnabled: false,
  });
});

app.get('/api/monitor/readiness', (_req, res) => {
  const configuration = getMonitorConfiguration();
  const depositsEnabled = configuration.configured
    && process.env.SEPOLIA_DEPOSITS_ENABLED === 'true';
  const missing = [...configuration.missing];
  if (configuration.configured && !depositsEnabled) {
    missing.push('SEPOLIA_DEPOSITS_ENABLED');
  }
  res.json({
    network: 'ethereum-sepolia',
    configured: configuration.configured,
    depositsEnabled,
    mode: depositsEnabled ? 'configured-not-verified' : 'disabled',
    missing,
    transfersEnabled: false,
    testnetLedgerEnabled: true,
    productionBalanceCreditEnabled: false,
    monitorMode: process.env.SEPOLIA_MONITOR_MODE?.trim().toLowerCase() === 'rpc'
      ? 'rpc-polling'
      : 'quicknode-webhook',
  });
});

app.post('/api/monitor/poll-sepolia', express.json({ limit: '1kb' }), async (req, res) => {
  const secret = process.env.SEPOLIA_POLL_SECRET?.trim();
  const supplied = req.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!secret || supplied !== secret) {
    return res.status(401).json({ error: 'Invalid polling secret.' });
  }
  try {
    const result = await pollSepoliaRpc();
    return res.json(result);
  } catch (error) {
    console.error('Sepolia RPC poll failed:', error.message);
    return res.status(503).json({ error: 'Sepolia RPC polling failed.' });
  }
});

app.get('/api/deposits/options', requireUser, (_req, res) => {
  res.json({
    apiConfigured: isShieldzApiConfigured(),
    supportedPaymentGroups: getShieldzSupportedPaymentGroups(),
    testnetDepositIssuanceEnabled: isDepositAddressIssuanceAllowed(process.env, 'Sepolia'),
    addressGenerationReady: getDepositOptions().some(group =>
      group.options.some(option => option.addressReady)),
    depositOptions: getDepositOptions(),
  });
});

app.post('/api/deposits/address', requireSameOrigin, requireUser, async (req, res) => {
  const { asset, network, amountUsdCents } = req.body || {};
  if (typeof asset !== 'string' || typeof network !== 'string'
    || !depositOptionCodes[`${asset}:${network}`]) {
    return res.status(400).json({ error: 'Choose a supported asset and network.' });
  }
  if (!isDepositAddressIssuanceAllowed(process.env, network)) {
    return res.status(503).json({
      error: network === 'Sepolia'
        ? 'Sepolia testnet deposits require complete monitor configuration and SEPOLIA_DEPOSITS_ENABLED=true.'
        : 'Mainnet deposit addresses are disabled in production until monitoring and crediting are verified.',
    });
  }
  if (!Number.isSafeInteger(amountUsdCents) || amountUsdCents <= 0) {
    return res.status(400).json({ error: 'Enter a valid USD reference amount.' });
  }
  try {
    const deposit = await createDepositAddress({
      userId: req.user.id,
      asset,
      network,
    });
    const qrCode = await QRCode.toDataURL(deposit.address, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 240,
      color: { dark: '#111613', light: '#ffffff' },
    });
    return res.status(201).json({
      ...deposit,
      amountUsdCents,
      qrCode,
      monitoringReady: network === 'Sepolia'
        && getMonitorConfiguration().configured
        && process.env.SEPOLIA_DEPOSITS_ENABLED === 'true',
      warning: network === 'Sepolia'
        ? 'Sepolia testnet only. Confirmed testnet events appear in the separate testnet ledger; no production account balance is credited and no transfers are sent.'
        : 'Mainnet deposits remain disabled until production monitoring and accounting are verified.',
    });
  } catch (error) {
    const networkCode = depositOptionCodes[`${asset}:${network}`];
    const provider = depositDerivationFamilies[networkCode]?.family === 'evm'
      ? process.env.DEPOSIT_EVM_PROVIDER?.trim().toLowerCase() || 'xpub'
      : 'xpub';
    console.error('Deposit address creation failed:', error.name || 'Error');
    return res.status(503).json({
      error: error.message.startsWith('Configure ')
        ? error.message
        : provider === 'turnkey'
          ? 'Turnkey could not create the address. Check the wallet ID, API key permissions, and expected Ethereum address configuration.'
          : 'Could not create a deposit address. Check the public extended-key configuration.',
    });
  }
});

app.get('/api/deposits/address/:id', requireUser, async (req, res) => {
  const deposit = await databaseGet(`
    SELECT id, asset, network, address, status, created_at AS createdAt
    FROM wallet_deposits WHERE id = ? AND user_id = ?
  `, [req.params.id, req.user.id]);
  if (!deposit) return res.status(404).json({ error: 'Deposit address not found.' });
  const events = await databaseAll(`
    SELECT event_id AS "eventId", asset, amount_base_units AS "amountBaseUnits",
      block_number AS "blockNumber", confirmations, status, updated_at AS "updatedAt"
    FROM monitored_deposit_events WHERE deposit_id = ? ORDER BY block_number DESC
  `, [deposit.id]);
  const ledgerEntries = await databaseAll(`
    SELECT event_id AS "eventId", asset, amount_base_units AS "amountBaseUnits",
      block_hash AS "blockHash", status, updated_at AS "updatedAt"
    FROM testnet_ledger_entries
    WHERE deposit_id = ?
    ORDER BY updated_at DESC
  `, [deposit.id]);
  return res.json({
    ...deposit,
    monitoringReady: isDepositAddressIssuanceAllowed(process.env, 'Sepolia'),
    observedTestnetEvents: events,
    testnetLedgerEntries: ledgerEntries,
    productionBalanceCredited: false,
  });
});

app.get('/api/deposits/testnet-ledger', requireUser, async (req, res) => {
  const creditedEntries = await databaseAll(`
    SELECT asset, amount_base_units AS "amountBaseUnits"
    FROM testnet_ledger_entries
    WHERE user_id = ? AND status = 'credited'
  `, [req.user.id]);
  const entries = await databaseAll(`
    SELECT event_id AS "eventId", deposit_id AS "depositId", asset,
      amount_base_units AS "amountBaseUnits", block_hash AS "blockHash",
      status, updated_at AS "updatedAt"
    FROM testnet_ledger_entries
    WHERE user_id = ?
    ORDER BY updated_at DESC
    LIMIT 200
  `, [req.user.id]);
  const totals = new Map();
  for (const entry of creditedEntries) {
    totals.set(entry.asset, (totals.get(entry.asset) || 0n) + BigInt(entry.amountBaseUnits));
  }
  return res.json({
    network: 'ethereum-sepolia',
    balances: [...totals].sort(([assetA], [assetB]) => assetA.localeCompare(assetB))
      .map(([asset, amount]) => ({
        asset,
        amountBaseUnits: amount.toString(),
      })),
    entries,
    productionBalanceCredited: false,
    transfersEnabled: false,
  });
});

app.get([...publicPages.keys()], (req, res) => {
  if (publicPages.get(req.path) !== 'auth.html' && !req.user) {
    return res.redirect('/auth');
  }
  res.sendFile(path.join(__dirname, publicPages.get(req.path)));
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({ error: 'Invalid JSON request body.' });
  }
  console.error('Unhandled server error:', error.message);
  return res.status(500).json({ error: 'Unexpected server error.' });
});

if (require.main === module) {
  const host = process.env.HOST || '127.0.0.1';
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    throw new Error('Bind the app to loopback and use a TLS-terminating reverse proxy for public access.');
  }

  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }

  const server = app.listen(port, host, () => {
    console.log(`CryptoVault listening on http://${host}:${port}`);
    console.log('Direct deposit addresses are not monitored or credited until chain monitoring is configured.');
    if (process.env.SEPOLIA_MONITOR_MODE?.trim().toLowerCase() === 'rpc'
      && process.env.SEPOLIA_DEPOSITS_ENABLED === 'true'
      && getMonitorConfiguration().configured) {
      sepoliaRpcPollTimer = setInterval(() => {
        pollSepoliaRpc().catch(error => {
          console.error('Sepolia RPC poll failed:', error.message);
        });
      }, 60_000);
      pollSepoliaRpc().catch(error => {
        console.error('Sepolia RPC poll failed:', error.message);
      });
    }
  });

  function shutdown() {
    if (sepoliaRpcPollTimer) clearInterval(sepoliaRpcPollTimer);
    server.close(() => {
      if (sqliteDatabase) sqliteDatabase.close();
      if (postgresPool) postgresPool.end();
      process.exit(0);
    });
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = Object.assign(app, {
  app,
  createShieldzInvoice,
  getShieldzInvoice,
  isShieldzApiConfigured,
  getShieldzSupportedPaymentGroups,
  getDepositOptions,
  createDepositAddress,
  hashSessionToken,
  createPasswordHash,
  verifyPassword,
  closeDatabase: async () => {
    if (sqliteDatabase) sqliteDatabase.close();
    if (postgresPool) await postgresPool.end();
  },
});
