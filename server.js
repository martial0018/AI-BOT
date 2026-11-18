require('dotenv').config();

const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit').rateLimit;
const Database = require('better-sqlite3');
const QRCode = require('qrcode');
const { getSweepReadiness } = require('./sweeps');
const { deriveSecpAddress } = require('./wallet');

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
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
const databasePath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'deposits.sqlite');
require('node:fs').mkdirSync(path.dirname(databasePath), { recursive: true });
const database = new Database(databasePath);
database.pragma('journal_mode = WAL');
database.pragma('busy_timeout = 5000');
database.exec(`
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
`);
database.pragma('foreign_keys = ON');
const depositColumns = new Set(
  database.pragma('table_info(shieldz_deposits)').map(column => column.name)
);
if (!depositColumns.has('settlement_asset')) {
  database.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_asset TEXT NOT NULL DEFAULT 'USDT'");
}
if (!depositColumns.has('settlement_network')) {
  database.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_network TEXT NOT NULL DEFAULT 'base'");
}
if (!depositColumns.has('settlement_chain')) {
  database.exec("ALTER TABLE shieldz_deposits ADD COLUMN settlement_chain TEXT NOT NULL DEFAULT 'BASE'");
}

const depositOptionCodes = {
  'BTC:Bitcoin': 'bitcoin',
  'ETH:Ethereum': 'ethereum',
  'ETH:Arbitrum': 'arbitrum',
  'USDC:Ethereum': 'ethereum',
  'USDC:Arbitrum': 'arbitrum',
  'USDC:BNB Chain': 'bsc',
  'USDT:Ethereum': 'ethereum',
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
  return getShieldzSupportedPaymentGroups().map(group => ({
    ...group,
    options: group.options.map(option => ({
      ...option,
      networkCode: depositOptionCodes[`${option.asset}:${option.network}`],
      addressReady: Boolean(env[depositDerivationFamilies[
        depositOptionCodes[`${option.asset}:${option.network}`]
      ]?.envKey]?.trim()),
    })),
  }));
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
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `cv_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
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
  if (!req.user) return res.status(401).json({ error: 'Sign in to continue.' });
  return next();
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

function createDepositAddress({ userId, asset, network, env = process.env }) {
  const networkCode = depositOptionCodes[`${asset}:${network}`];
  const familyConfig = depositDerivationFamilies[networkCode];
  if (!networkCode || !familyConfig) throw new Error('Unsupported asset and network.');
  if (!env[familyConfig.envKey]?.trim()) {
    throw new Error(`Configure ${familyConfig.envKey} before creating deposit addresses.`);
  }

  const allocate = database.transaction(() => {
    const row = database.prepare(`
      SELECT COALESCE(MAX(derivation_index), -1) + 1 AS nextIndex
      FROM wallet_deposits WHERE derivation_family = ?
    `).get(familyConfig.family);
    const index = row.nextIndex;
    if (!Number.isSafeInteger(index) || index >= 0x80000000) {
      throw new Error('Deposit address index limit reached.');
    }

    const address = deriveSecpAddress(asset, networkCode, index, env);
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    database.prepare(`
      INSERT INTO wallet_deposits (
        id, user_id, asset, network, address, derivation_family,
        derivation_index, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'awaiting_payment', ?)
    `).run(id, userId, asset, network, address, familyConfig.family, index, createdAt);
    return { id, asset, network, address, status: 'awaiting_payment', createdAt };
  });
  return allocate.immediate();
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
app.use(express.json({ limit: '4kb', type: 'application/json' }));
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
}));
app.use((req, _res, next) => {
  const token = getCookieValue(req.get('cookie'), 'cv_session');
  if (token && /^[A-Za-z0-9_-]{40,}$/.test(token)) {
    const session = database.prepare(`
      SELECT users.id, users.email, users.name
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(hashSessionToken(token), Date.now());
    if (session) req.user = session;
  }
  next();
});

app.post('/api/auth/register', requireSameOrigin, async (req, res) => {
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
    database.prepare(`
      INSERT INTO users (id, email, name, password_salt, password_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(user.id, user.email, user.name, credentials.salt, credentials.hash, createdAt);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    throw error;
  }
  const token = crypto.randomBytes(32).toString('base64url');
  database.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)
  `).run(hashSessionToken(token), user.id, Date.now() + 30 * 24 * 60 * 60 * 1000, createdAt);
  setSessionCookie(res, token);
  return res.status(201).json({ user });
});

app.post('/api/auth/login', requireSameOrigin, async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  if (!normalizedEmail || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }
  const account = database.prepare(`
    SELECT id, email, name, password_salt, password_hash FROM users WHERE email = ?
  `).get(normalizedEmail);
  const valid = account
    ? await verifyPassword(password, account.password_salt, account.password_hash)
    : false;
  if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' });

  const token = crypto.randomBytes(32).toString('base64url');
  const createdAt = new Date().toISOString();
  database.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)
  `).run(hashSessionToken(token), account.id, Date.now() + 30 * 24 * 60 * 60 * 1000, createdAt);
  setSessionCookie(res, token);
  return res.json({ user: { id: account.id, email: account.email, name: account.name } });
});

app.get('/api/auth/session', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Sign in to continue.' });
  res.json({ user: req.user });
});

app.post('/api/auth/logout', requireSameOrigin, (req, res) => {
  const token = getCookieValue(req.get('cookie'), 'cv_session');
  if (token) {
    database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashSessionToken(token));
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

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', mode: 'self-custody-addresses', monitoring: 'disabled' });
});

app.get('/api/sweeps/readiness', (_req, res) => {
  res.json({
    ...getSweepReadiness(),
    transfersEnabled: false,
  });
});

app.get('/api/deposits/options', requireUser, (_req, res) => {
  res.json({
    apiConfigured: isShieldzApiConfigured(),
    supportedPaymentGroups: getShieldzSupportedPaymentGroups(),
    addressGenerationReady: getDepositOptions().some(group =>
      group.options.some(option => option.addressReady)),
    depositOptions: getDepositOptions(),
  });
});

app.post('/api/deposits/address', requireSameOrigin, requireUser, async (req, res) => {
  const { asset, network } = req.body || {};
  if (typeof asset !== 'string' || typeof network !== 'string'
    || !depositOptionCodes[`${asset}:${network}`]) {
    return res.status(400).json({ error: 'Choose a supported asset and network.' });
  }
  try {
    const deposit = createDepositAddress({ userId: req.user.id, asset, network });
    const qrCode = await QRCode.toDataURL(deposit.address, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 240,
      color: { dark: '#111613', light: '#ffffff' },
    });
    return res.status(201).json({
      ...deposit,
      qrCode,
      monitoringReady: false,
      warning: 'On-chain monitoring is not configured. This address is not monitored or credited automatically.',
    });
  } catch (error) {
    console.error('Deposit address creation failed:', error.message);
    return res.status(503).json({
      error: error.message.startsWith('Configure ')
        ? error.message
        : 'Could not create a deposit address. Check the public extended-key configuration.',
    });
  }
});

app.get('/api/deposits/address/:id', requireUser, (req, res) => {
  const deposit = database.prepare(`
    SELECT id, asset, network, address, status, created_at AS createdAt
    FROM wallet_deposits WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.id);
  if (!deposit) return res.status(404).json({ error: 'Deposit address not found.' });
  return res.json({ ...deposit, monitoringReady: false });
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
  });

  function shutdown() {
    server.close(() => {
      database.close();
      process.exit(0);
    });
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = {
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
  closeDatabase: () => database.close(),
};
