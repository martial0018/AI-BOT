const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { once } = require('node:events');
const { promisify } = require('node:util');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { deriveSecpAddress, isValidSolanaAddress } = require('./wallet');
const { deriveTurnkeyEvmAddress } = require('./turnkey');
const testDataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptovault-test-'));
process.env.DATABASE_PATH = path.join(testDataDirectory, 'deposits.sqlite');
const {
  app,
  createShieldzInvoice,
  getShieldzInvoice,
  isShieldzApiConfigured,
  getShieldzSupportedPaymentGroups,
  getDepositOptions,
  createPasswordHash,
  verifyPassword,
  closeDatabase,
} = require('./server');

const bip32 = BIP32Factory(ecc);
const execFileAsync = promisify(execFile);

test.after(() => {
  closeDatabase();
  fs.rmSync(testDataDirectory, { recursive: true, force: true });
});

test('Vercel bundles the HTML pages and secp256k1 WASM runtime asset', () => {
  const vercelConfig = JSON.parse(fs.readFileSync(path.join(__dirname, 'vercel.json'), 'utf8'));
  assert.equal(
    vercelConfig.functions['server.js'].includeFiles,
    '{*.html,node_modules/tiny-secp256k1/lib/secp256k1.wasm}'
  );
  assert.equal(
    fs.existsSync(path.join(__dirname, 'node_modules', 'tiny-secp256k1', 'lib', 'secp256k1.wasm')),
    true
  );
});

test('Vercel cold start exports Express and reports missing persistent storage without crashing', async () => {
  const script = `
    const app = require('./server');
    const server = app.listen(0, '127.0.0.1', async () => {
      try {
        const baseUrl = 'http://127.0.0.1:' + server.address().port;
        const health = await fetch(baseUrl + '/api/health');
        const healthBody = await health.json();
        const authPage = await fetch(baseUrl + '/');
        const authApi = await fetch(baseUrl + '/api/auth/session');
        if (typeof app !== 'function'
          || health.status !== 503
          || healthBody.status !== 'degraded'
          || healthBody.persistentStorage !== 'unconfigured'
          || authPage.status !== 200
          || authApi.status !== 503) {
          throw new Error('Unexpected Vercel cold-start responses.');
        }
      } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
      } finally {
        server.close(async () => app.closeDatabase());
      }
    });
  `;
  const env = {
    ...process.env,
    VERCEL: '1',
    DATABASE_URL: '',
    POSTGRES_URL: '',
  };
  const { stdout, stderr } = await execFileAsync(process.execPath, ['-e', script], {
    cwd: __dirname,
    env,
    timeout: 30_000,
  });
  assert.equal(stderr, '');
  assert.equal(stdout, '');
});

test('reports whether the Shieldz API key is configured without exposing it', () => {
  assert.equal(isShieldzApiConfigured({ SHIELDZ_API_KEY: '  sk_test_example  ' }), true);
  assert.equal(isShieldzApiConfigured({ SHIELDZ_API_KEY: '   ' }), false);
  assert.equal(isShieldzApiConfigured({}), false);
});

test('exposes address-ready status without returning public extended keys', () => {
  const options = getDepositOptions({
    BTC_ACCOUNT_XPUB: 'btc-public-key',
    EVM_ACCOUNT_XPUB: 'evm-public-key',
    TRON_ACCOUNT_XPUB: 'tron-public-key',
  }).flatMap(group => group.options);

  assert.equal(options.length, 10);
  assert.equal(options.every(option => option.addressReady), true);
  assert.equal(options.some(option => option.networkCode === 'arbitrum'), true);
  assert.equal(JSON.stringify(options).includes('public-key'), false);
});

test('reports EVM address readiness from the selected provider configuration', () => {
  const turnkeyEnvironment = {
    DEPOSIT_EVM_PROVIDER: 'turnkey',
    TURNKEY_ORGANIZATION_ID: 'org-id',
    TURNKEY_WALLET_ID: 'wallet-id',
    TURNKEY_EXPECTED_ETH_ADDRESS: '0x1111111111111111111111111111111111111111',
    TURNKEY_API_PUBLIC_KEY: 'public-key',
    TURNKEY_API_PRIVATE_KEY: 'private-key',
  };
  const turnkeyOptions = getDepositOptions(turnkeyEnvironment)
    .flatMap(group => group.options);
  assert.equal(
    turnkeyOptions.filter(option => ['ethereum', 'arbitrum', 'bsc'].includes(option.networkCode))
      .every(option => option.addressReady),
    true
  );
  assert.equal(
    getDepositOptions({ DEPOSIT_EVM_PROVIDER: 'turnkey' })
      .flatMap(group => group.options)
      .filter(option => ['ethereum', 'arbitrum', 'bsc'].includes(option.networkCode))
      .some(option => option.addressReady),
    false
  );
  assert.equal(
    getDepositOptions({
      ...turnkeyEnvironment,
      VERCEL: '1',
    }).flatMap(group => group.options).some(option => option.addressReady),
    false
  );
  assert.equal(
    getDepositOptions({
      ...turnkeyEnvironment,
      NODE_ENV: 'production',
    }).flatMap(group => group.options).some(option => option.addressReady),
    false
  );
});

test('derives Turnkey EVM deposit accounts and verifies the known first address', async () => {
  const expectedAddress = '0x1111111111111111111111111111111111111111';
  const targetAddress = '0x2222222222222222222222222222222222222222';
  const env = {
    TURNKEY_ORGANIZATION_ID: 'org-id',
    TURNKEY_WALLET_ID: 'wallet-id',
    TURNKEY_EXPECTED_ETH_ADDRESS: expectedAddress,
    TURNKEY_API_PUBLIC_KEY: 'public-key',
    TURNKEY_API_PRIVATE_KEY: 'private-key',
  };
  const created = [];
  const apiClient = {
    getWalletAccounts: async ({ organizationId, walletId }) => {
      assert.equal(organizationId, 'org-id');
      assert.equal(walletId, 'wallet-id');
      return {
        accounts: [{
          path: "m/44'/60'/0'/0/0",
          address: expectedAddress,
        }],
      };
    },
    createWalletAccounts: async request => {
      created.push(request);
      assert.equal(request.organizationId, 'org-id');
      return { addresses: [targetAddress] };
    },
  };

  assert.equal(await deriveTurnkeyEvmAddress(0, env, apiClient), expectedAddress);
  assert.equal(await deriveTurnkeyEvmAddress(7, env, apiClient), targetAddress);
  assert.equal(created.length, 1);
  assert.equal(created[0].accounts[0].path, "m/44'/60'/0'/0/7");
  assert.equal(created[0].accounts[0].curve, 'CURVE_SECP256K1');
  assert.equal(created[0].accounts[0].addressFormat, 'ADDRESS_FORMAT_ETHEREUM');
});

test('refuses to derive Turnkey deposit addresses when the known address does not match', async () => {
  await assert.rejects(deriveTurnkeyEvmAddress(1, {
    TURNKEY_ORGANIZATION_ID: 'org-id',
    TURNKEY_WALLET_ID: 'wallet-id',
    TURNKEY_EXPECTED_ETH_ADDRESS: '0x1111111111111111111111111111111111111111',
    TURNKEY_API_PUBLIC_KEY: 'public-key',
    TURNKEY_API_PRIVATE_KEY: 'private-key',
  }, {
    getWalletAccounts: async () => ({
      accounts: [{
        path: "m/44'/60'/0'/0/0",
        address: '0x2222222222222222222222222222222222222222',
      }],
    }),
    createWalletAccounts: async () => {
      throw new Error('Should not create an account before verifying the wallet.');
    },
  }), /does not match TURNKEY_EXPECTED_ETH_ADDRESS/);
});

test('hashes account passwords with a per-password salt and verifies them safely', async () => {
  const password = 'correct horse battery staple 123';
  const credentials = await createPasswordHash(password);
  assert.notEqual(credentials.salt, credentials.hash);
  assert.equal(await verifyPassword(password, credentials.salt, credentials.hash), true);
  assert.equal(await verifyPassword('incorrect password', credentials.salt, credentials.hash), false);
});

test('lists BTC, ETH, USDC, and USDT only on requested supported networks', () => {
  const groups = getShieldzSupportedPaymentGroups();
  const options = groups.flatMap(group => group.options);
  const assets = new Set(options.map(option => option.asset));

  assert.deepEqual([...assets].sort(), ['BTC', 'ETH', 'USDC', 'USDT']);
  assert.deepEqual(options.map(({ asset, network }) => `${asset}:${network}`).sort(), [
    'BTC:Bitcoin',
    'ETH:Arbitrum',
    'ETH:Ethereum',
    'USDC:Arbitrum',
    'USDC:BNB Chain',
    'USDC:Ethereum',
    'USDT:Arbitrum',
    'USDT:BNB Chain',
    'USDT:Ethereum',
    'USDT:Tron',
  ]);
  assert.equal(options.length, 10);
  assert.equal(options.some(option => option.asset === 'BTC' && option.network === 'Bitcoin'), true);
  assert.equal(options.some(option => option.asset === 'ETH' && option.network === 'Ethereum'), true);
  assert.equal(options.some(option => option.asset === 'USDT' && option.network === 'Tron'), true);
  assert.equal(options.some(option => option.network === 'Base'), false);
  assert.equal(options.some(option => option.network === 'Optimism'), false);
  assert.equal(options.some(option => option.network === 'Polygon'), false);
  assert.equal(options.some(option => option.label === 'USDT · TRC20 (Tron)'), true);
  assert.equal(options.some(option => option.label === 'USDC · BEP20 (BNB Chain)'), true);
});

test('derives distinct BTC addresses from an account xpub without exposing private keys', () => {
  const account = bip32.fromSeed(Buffer.alloc(32, 7)).derivePath("m/84'/0'/0'");
  const previous = process.env.BTC_ACCOUNT_XPUB;
  process.env.BTC_ACCOUNT_XPUB = account.neutered().toBase58();
  try {
    const first = deriveSecpAddress('BTC', 'bitcoin', 0);
    const second = deriveSecpAddress('BTC', 'bitcoin', 1);
    assert.match(first, /^bc1q/);
    assert.match(second, /^bc1q/);
    assert.notEqual(first, second);
  } finally {
    if (previous === undefined) delete process.env.BTC_ACCOUNT_XPUB;
    else process.env.BTC_ACCOUNT_XPUB = previous;
  }
});

test('derives EVM and Tron deposit addresses from public account keys', () => {
  const evmAccount = bip32.fromSeed(Buffer.alloc(32, 8)).derivePath("m/44'/60'/0'");
  const tronAccount = bip32.fromSeed(Buffer.alloc(32, 9)).derivePath("m/44'/195'/0'");
  const previousEvm = process.env.EVM_ACCOUNT_XPUB;
  const previousTron = process.env.TRON_ACCOUNT_XPUB;
  process.env.EVM_ACCOUNT_XPUB = evmAccount.neutered().toBase58();
  process.env.TRON_ACCOUNT_XPUB = tronAccount.neutered().toBase58();
  try {
    const ethereum = deriveSecpAddress('ETH', 'ethereum', 0);
    const bnb = deriveSecpAddress('BNB', 'bsc', 0);
    const tron = deriveSecpAddress('USDT', 'tron', 0);
    assert.match(ethereum, /^0x[0-9a-fA-F]{40}$/);
    assert.equal(bnb, ethereum);
    assert.match(tron, /^T[1-9A-HJ-NP-Za-km-z]{33}$/);
    assert.notEqual(tron, deriveSecpAddress('USDT', 'tron', 1));
  } finally {
    if (previousEvm === undefined) delete process.env.EVM_ACCOUNT_XPUB;
    else process.env.EVM_ACCOUNT_XPUB = previousEvm;
    if (previousTron === undefined) delete process.env.TRON_ACCOUNT_XPUB;
    else process.env.TRON_ACCOUNT_XPUB = previousTron;
  }
});

test('registers accounts and allocates distinct, user-scoped deposit addresses', async t => {
  const previous = {
    BTC_ACCOUNT_XPUB: process.env.BTC_ACCOUNT_XPUB,
    EVM_ACCOUNT_XPUB: process.env.EVM_ACCOUNT_XPUB,
    TRON_ACCOUNT_XPUB: process.env.TRON_ACCOUNT_XPUB,
    NODE_ENV: process.env.NODE_ENV,
  };
  const btcAccount = bip32.fromSeed(Buffer.alloc(32, 17)).derivePath("m/84'/0'/0'");
  const evmAccount = bip32.fromSeed(Buffer.alloc(32, 18)).derivePath("m/44'/60'/0'");
  const tronAccount = bip32.fromSeed(Buffer.alloc(32, 19)).derivePath("m/44'/195'/0'");
  process.env.BTC_ACCOUNT_XPUB = btcAccount.neutered().toBase58();
  process.env.EVM_ACCOUNT_XPUB = evmAccount.neutered().toBase58();
  process.env.TRON_ACCOUNT_XPUB = tronAccount.neutered().toBase58();
  process.env.NODE_ENV = 'test';

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, { cookie, ...options } = {}) => fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'content-type': 'application/json' } : {}),
      ...(options.method === 'POST' ? { origin: baseUrl } : {}),
      ...(cookie ? { cookie } : {}),
      ...options.headers,
    },
  });

  const unauthenticated = await request('/api/deposits/address', {
    method: 'POST',
    body: JSON.stringify({ asset: 'BTC', network: 'Bitcoin' }),
  });
  assert.equal(unauthenticated.status, 401);

  const registration = await request('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      email: 'Customer@example.com',
      name: 'Customer One',
      password: 'a secure password 123',
      passwordConfirmation: 'a secure password 123',
    }),
  });
  assert.equal(registration.status, 201);
  const cookie = registration.headers.get('set-cookie').split(';')[0];

  const missingAmount = await request('/api/deposits/address', {
    method: 'POST',
    cookie,
    body: JSON.stringify({ asset: 'ETH', network: 'Ethereum' }),
  });
  assert.equal(missingAmount.status, 400);

  process.env.NODE_ENV = 'production';
  const productionDisabled = await request('/api/deposits/address', {
    method: 'POST',
    cookie,
    body: JSON.stringify({
      asset: 'ETH',
      network: 'Ethereum',
      amountUsdCents: 5000,
    }),
  });
  process.env.NODE_ENV = 'test';
  assert.equal(productionDisabled.status, 503);
  assert.match((await productionDisabled.json()).error, /disabled in production/);

  const createAddress = async (asset, network, amountUsdCents) => {
    const response = await request('/api/deposits/address', {
      method: 'POST',
      cookie,
      body: JSON.stringify({ asset, network, amountUsdCents }),
    });
    assert.equal(response.status, 201);
    return response.json();
  };
  const ethereum = await createAddress('ETH', 'Ethereum', 125050);
  const arbitrum = await createAddress('ETH', 'Arbitrum', 2500);
  assert.match(ethereum.address, /^0x[0-9a-fA-F]{40}$/);
  assert.notEqual(ethereum.address, arbitrum.address);
  assert.equal(ethereum.amountUsdCents, 125050);
  assert.equal(ethereum.monitoringReady, false);
  const ethereumDetails = await request(`/api/deposits/address/${ethereum.id}`, { cookie });
  assert.equal(ethereumDetails.status, 200);
  assert.equal((await ethereumDetails.json()).address, ethereum.address);

  const secondRegistration = await request('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      email: 'second@example.com',
      name: 'Customer Two',
      password: 'another secure password 123',
      passwordConfirmation: 'another secure password 123',
    }),
  });
  const secondCookie = secondRegistration.headers.get('set-cookie').split(';')[0];
  const crossAccountLookup = await request(`/api/deposits/address/${ethereum.id}`, {
    cookie: secondCookie,
  });
  assert.equal(crossAccountLookup.status, 404);
});

test('validates Solana public addresses', () => {
  assert.equal(isValidSolanaAddress('11111111111111111111111111111111'), true);
  assert.equal(isValidSolanaAddress('not-an-address'), false);
});

test('creates a Shieldz invoice using the merchant account settlement', async () => {
  let requestUrl;
  let requestOptions;
  const invoice = await createShieldzInvoice(1250, {
    env: {
      SHIELDZ_API_KEY: 'sk_test_example',
    },
    fetchImpl: async (url, options) => {
      requestUrl = url;
      requestOptions = options;
      return {
        ok: true,
        json: async () => ({
          id: 'invoice-123',
          amount_usd_cents: 1250,
          status: 'pending',
          pay_url: 'https://shieldz.cash/pay/invoice-123',
          expires_at: 1750000000000,
          settlement: { asset: 'BASE.USDC', chain: 'BASE' },
        }),
      };
    },
  });

  assert.equal(requestUrl, 'https://shieldz.cash/api/v1/invoices');
  assert.equal(requestOptions.headers.authorization, 'Bearer sk_test_example');
  const body = JSON.parse(requestOptions.body);
  assert.equal(body.amount_usd_cents, 1250);
  assert.equal(body.settlement, undefined);
  assert.equal(invoice.invoiceId, 'invoice-123');
  assert.equal(invoice.payUrl, 'https://shieldz.cash/pay/invoice-123');
  assert.deepEqual(invoice.settlement, {
    asset: 'USDC',
    network: 'base',
    label: 'USDC on Base',
  });
  assert.equal(invoice.expiresAt, 1750000000000);
});

test('rejects an invalid Shieldz checkout URL', async () => {
  await assert.rejects(createShieldzInvoice(100, {
    env: {
      SHIELDZ_API_KEY: 'sk_test_example',
    },
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({
        id: 'invoice-123',
        amount_usd_cents: 100,
        status: 'pending',
        pay_url: 'https://attacker.example/pay/invoice-123',
      }),
    }),
  }), /unexpected checkout URL/);
});

test('enforces Shieldz invoice amount limits', async () => {
  await assert.rejects(createShieldzInvoice(99), /between.*100,000/);
  await assert.rejects(createShieldzInvoice(10_000_001), /between.*100,000/);
});

test('retrieves and validates Shieldz invoice status', async () => {
  let requestUrl;
  const invoice = await getShieldzInvoice('invoice-123', {
    env: { SHIELDZ_API_KEY: 'sk_test_example' },
    fetchImpl: async url => {
      requestUrl = url;
      return {
        ok: true,
        json: async () => ({
          id: 'invoice-123',
          amount_usd_cents: 1250,
          status: 'paid',
          expires_at: 1750000000000,
        }),
      };
    },
  });

  assert.equal(requestUrl, 'https://shieldz.cash/api/v1/invoices/invoice-123');
  assert.deepEqual(invoice, {
    status: 'paid',
    amountUsdCents: 1250,
    expiresAt: 1750000000000,
  });
});
