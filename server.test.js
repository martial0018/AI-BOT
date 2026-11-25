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
const {
  getMonitorConfiguration,
  parseSepoliaPayload,
  transferTopic,
  verifyQuickNodeSignature,
} = require('./deposit-monitor');
const testDataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptovault-test-'));
process.env.DATABASE_PATH = path.join(testDataDirectory, 'deposits.sqlite');
const {
  app,
  createShieldzInvoice,
  getShieldzInvoice,
  isShieldzApiConfigured,
  getShieldzSupportedPaymentGroups,
  getDepositOptions,
  createDepositAddress,
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

  assert.equal(options.length, 13);
  assert.equal(options.filter(option => option.addressReady).length, 10);
  assert.equal(options.filter(option => option.network === 'Sepolia')
    .every(option => !option.addressReady), true);
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
    turnkeyOptions.filter(option => option.network !== 'Sepolia'
      && ['ethereum', 'arbitrum', 'bsc'].includes(option.networkCode))
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
  const sepoliaEnvironment = {
    ...turnkeyEnvironment,
    SEPOLIA_RPC_URL: 'https://sepolia.example',
    QUICKNODE_STREAMS_SECRET: 'test-secret',
    SEPOLIA_CONFIRMATIONS: '12',
    SEPOLIA_DEPOSITS_ENABLED: 'true',
    SEPOLIA_USDC_CONTRACT: '0x1111111111111111111111111111111111111111',
  };
  const sepoliaOptions = getDepositOptions(sepoliaEnvironment)
    .flatMap(group => group.options)
    .filter(option => option.network === 'Sepolia');
  assert.equal(sepoliaOptions.find(option => option.asset === 'ETH').addressReady, true);
  assert.equal(sepoliaOptions.find(option => option.asset === 'USDC').addressReady, true);
  assert.equal(sepoliaOptions.find(option => option.asset === 'USDT').addressReady, false);
  assert.equal(getDepositOptions({
    ...sepoliaEnvironment,
    VERCEL: '1',
    SEPOLIA_DEPOSITS_ENABLED: 'false',
  }).flatMap(group => group.options).some(option => option.network === 'Sepolia'
    && option.addressReady), false);
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

test('requires a Sepolia RPC, QuickNode signature secret, and valid confirmation count', () => {
  assert.deepEqual(getMonitorConfiguration({}).missing, [
    'SEPOLIA_RPC_URL',
    'QUICKNODE_STREAMS_SECRET',
    'SEPOLIA_CONFIRMATIONS',
  ]);
  const configured = getMonitorConfiguration({
    SEPOLIA_RPC_URL: 'https://sepolia.example',
    QUICKNODE_STREAMS_SECRET: 'test-secret',
    SEPOLIA_CONFIRMATIONS: '12',
    SEPOLIA_USDC_CONTRACT: '0x1111111111111111111111111111111111111111',
  });
  assert.equal(configured.configured, true);
  assert.equal(configured.confirmations, 12);
  assert.deepEqual(configured.tokens, {
    USDC: '0x1111111111111111111111111111111111111111',
  });
  assert.equal(getMonitorConfiguration({
    SEPOLIA_RPC_URL: 'https://sepolia.example',
    QUICKNODE_STREAMS_SECRET: 'test-secret',
    SEPOLIA_CONFIRMATIONS: '0',
    SEPOLIA_USDT_CONTRACT: 'not-an-address',
  }).configured, false);
  assert.equal(getMonitorConfiguration({
    SEPOLIA_RPC_URL: 'http://remote.example',
    QUICKNODE_STREAMS_SECRET: 'test-secret',
    SEPOLIA_CONFIRMATIONS: '12',
  }).configured, false);
});

test('validates QuickNode Streams HMAC, timestamp, and nonce format', () => {
  const crypto = require('node:crypto');
  const secret = 'test-stream-secret';
  const nonce = 'nonce-value-123';
  const timestamp = String(Date.now());
  const body = '{"chainId":"0xaa36a7","logs":[],"transactions":[]}';
  const signature = crypto.createHmac('sha256', secret)
    .update(nonce + timestamp + body)
    .digest('hex');
  const signed = { secret, nonce, timestamp, signature, body };

  assert.equal(verifyQuickNodeSignature(signed), true);
  assert.equal(verifyQuickNodeSignature({ ...signed, body: `${body} ` }), false);
  assert.equal(verifyQuickNodeSignature({
    ...signed,
    timestamp: String(Date.now() - 10 * 60 * 1000),
  }), false);
  assert.equal(verifyQuickNodeSignature({ ...signed, nonce: 'bad' }), false);
});

test('accepts only well-formed Sepolia transfer payloads', () => {
  const transferLog = {
    address: '0x1111111111111111111111111111111111111111',
    topics: [
      transferTopic,
      `0x${'0'.repeat(24)}${'2'.repeat(40)}`,
      `0x${'0'.repeat(24)}${'3'.repeat(40)}`,
    ],
    data: `0x${'0'.repeat(63)}1`,
    transactionHash: `0x${'4'.repeat(64)}`,
    blockHash: `0x${'5'.repeat(64)}`,
    blockNumber: '0x10',
    logIndex: '0x0',
  };
  assert.deepEqual(parseSepoliaPayload({
    chainId: '0xaa36a7',
    logs: [transferLog],
    transactions: [],
  }).logs, [transferLog]);
  assert.throws(() => parseSepoliaPayload({
    chainId: '0x1',
    logs: [transferLog],
    transactions: [],
  }), /Only Ethereum Sepolia/);
  assert.throws(() => parseSepoliaPayload({
    chainId: 11155111,
    logs: [{ ...transferLog, topics: [transferTopic] }],
    transactions: [],
  }), /Invalid ERC-20 transfer log/);
});

test('authenticates QuickNode deliveries and acknowledges event replays once', async t => {
  const crypto = require('node:crypto');
  const names = [
    'SEPOLIA_RPC_URL',
    'QUICKNODE_STREAMS_SECRET',
    'SEPOLIA_CONFIRMATIONS',
    'SEPOLIA_USDC_CONTRACT',
    'SEPOLIA_USDT_CONTRACT',
  ];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  const previousFetch = global.fetch;
  process.env.SEPOLIA_RPC_URL = 'https://sepolia.example';
  process.env.QUICKNODE_STREAMS_SECRET = 'test-stream-secret';
  process.env.SEPOLIA_CONFIRMATIONS = '2';
  delete process.env.SEPOLIA_USDC_CONTRACT;
  delete process.env.SEPOLIA_USDT_CONTRACT;
  const rpcMethods = [];
  global.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    rpcMethods.push(request.method);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: '2.0',
        id: request.id,
        result: request.method === 'eth_chainId' ? '0xaa36a7' : '0x100',
      }),
    };
  };

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  t.after(() => {
    global.fetch = previousFetch;
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  const body = JSON.stringify({ chainId: '0xaa36a7', logs: [], transactions: [] });
  const nonce = 'unit-test-nonce-123';
  const timestamp = String(Date.now());
  const signature = crypto.createHmac('sha256', process.env.QUICKNODE_STREAMS_SECRET)
    .update(nonce + timestamp + body)
    .digest('hex');
  const url = `http://127.0.0.1:${server.address().port}/api/monitor/quicknode`;
  const request = () => previousFetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-qn-nonce': nonce,
      'x-qn-timestamp': timestamp,
      'x-qn-signature': signature,
    },
    body,
  });

  const accepted = await request();
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).transfersEnabled, false);
  assert.deepEqual(rpcMethods, ['eth_chainId', 'eth_blockNumber']);
  const duplicate = await request();
  assert.equal(duplicate.status, 200);
  assert.deepEqual(await duplicate.json(), { accepted: true, duplicate: true });
  assert.deepEqual(rpcMethods, ['eth_chainId', 'eth_blockNumber']);
});

test('credits confirmed Sepolia events to a separate ledger and reverses reorged events', async t => {
  const crypto = require('node:crypto');
  const names = [
    'SEPOLIA_RPC_URL',
    'QUICKNODE_STREAMS_SECRET',
    'SEPOLIA_CONFIRMATIONS',
    'SEPOLIA_USDC_CONTRACT',
    'SEPOLIA_USDT_CONTRACT',
    'SEPOLIA_DEPOSITS_ENABLED',
    'EVM_ACCOUNT_XPUB',
    'NODE_ENV',
    'VERCEL',
  ];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  const previousFetch = global.fetch;
  const account = bip32.fromSeed(Buffer.alloc(32, 61)).derivePath("m/44'/60'/0'");
  process.env.SEPOLIA_RPC_URL = 'https://sepolia.example';
  process.env.QUICKNODE_STREAMS_SECRET = 'test-stream-secret';
  process.env.SEPOLIA_CONFIRMATIONS = '2';
  process.env.EVM_ACCOUNT_XPUB = account.neutered().toBase58();
  const usdcContract = '0x1111111111111111111111111111111111111111';
  process.env.SEPOLIA_USDC_CONTRACT = usdcContract;
  process.env.SEPOLIA_DEPOSITS_ENABLED = 'true';
  process.env.NODE_ENV = 'test';
  delete process.env.SEPOLIA_USDT_CONTRACT;

  const transactionHash = `0x${'a'.repeat(64)}`;
  const usdcTransactionHash = `0x${'c'.repeat(64)}`;
  const blockHash = `0x${'b'.repeat(64)}`;
  const blockNumber = '0x10';
  let deposit;
  let usdcDeposit;
  const usdcLog = {
    address: usdcContract,
    topics: [
      transferTopic,
      `0x${'0'.repeat(24)}${'2'.repeat(40)}`,
      `0x${'0'.repeat(24)}${'3'.repeat(40)}`,
    ],
    data: `0x${'0'.repeat(63)}a`,
    transactionHash: usdcTransactionHash,
    blockHash,
    blockNumber,
    logIndex: '0x0',
  };
  global.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    const results = {
      eth_chainId: '0xaa36a7',
      eth_blockNumber: '0x12',
      eth_getTransactionReceipt: {
        transactionHash: request.params[0],
        status: '0x1',
        blockHash,
        blockNumber,
        logs: request.params[0] === usdcTransactionHash ? [usdcLog] : [],
      },
      eth_getTransactionByHash: {
        hash: transactionHash,
        to: deposit.address,
        value: '0xde0b6b3a7640000',
        blockHash,
        blockNumber,
      },
    };
    return {
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: '2.0', id: request.id, result: results[request.method] }),
    };
  };

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  t.after(() => {
    global.fetch = previousFetch;
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const registration = await previousFetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: baseUrl,
    },
    body: JSON.stringify({
      email: 'monitor-test@example.com',
      name: 'Monitor Test',
      password: 'a secure password 123',
      passwordConfirmation: 'a secure password 123',
    }),
  });
  assert.equal(registration.status, 201);
  const user = (await registration.json()).user;
  const cookie = registration.headers.get('set-cookie').split(';')[0];
  process.env.NODE_ENV = 'production';
  process.env.VERCEL = '1';
  const productionSepoliaDeposit = await previousFetch(`${baseUrl}/api/deposits/address`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: baseUrl,
      cookie,
    },
    body: JSON.stringify({
      asset: 'ETH',
      network: 'Sepolia',
      amountUsdCents: 5000,
    }),
  });
  process.env.NODE_ENV = 'test';
  if (previous.VERCEL === undefined) delete process.env.VERCEL;
  else process.env.VERCEL = previous.VERCEL;
  assert.equal(productionSepoliaDeposit.status, 201);
  assert.equal((await productionSepoliaDeposit.json()).monitoringReady, true);
  deposit = await createDepositAddress({
    userId: user.id,
    asset: 'ETH',
    network: 'Sepolia',
  });
  usdcDeposit = await createDepositAddress({
    userId: user.id,
    asset: 'USDC',
    network: 'Sepolia',
  });
  usdcLog.topics[2] =
    `0x${'0'.repeat(24)}${usdcDeposit.address.slice(2).toLowerCase()}`;
  const body = JSON.stringify({
    chainId: '0xaa36a7',
    logs: [usdcLog],
    transactions: [{
      hash: transactionHash,
      to: deposit.address,
      value: '0xde0b6b3a7640000',
      blockHash,
      blockNumber,
    }],
  });
  const nonce = 'native-deposit-nonce-1';
  const timestamp = String(Date.now());
  const signature = crypto.createHmac('sha256', process.env.QUICKNODE_STREAMS_SECRET)
    .update(nonce + timestamp + body)
    .digest('hex');
  const monitored = await previousFetch(`${baseUrl}/api/monitor/quicknode`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-qn-nonce': nonce,
      'x-qn-timestamp': timestamp,
      'x-qn-signature': signature,
    },
    body,
  });
  assert.equal(monitored.status, 200);
  const response = await monitored.json();
  assert.deepEqual(response.recorded.map(event => event.asset).sort(), ['ETH', 'USDC']);
  const nativeEvent = response.recorded.find(event => event.asset === 'ETH');
  const tokenEvent = response.recorded.find(event => event.asset === 'USDC');
  assert.equal(nativeEvent.amountBaseUnits, '1000000000000000000');
  assert.equal(nativeEvent.status, 'confirmed');
  assert.equal(tokenEvent.amountBaseUnits, '10');
  assert.equal(tokenEvent.status, 'confirmed');
  assert.equal(response.transfersEnabled, false);

  const details = await previousFetch(`${baseUrl}/api/deposits/address/${deposit.id}`, {
    headers: { cookie },
  });
  assert.equal(details.status, 200);
  const detailsBody = await details.json();
  assert.equal(detailsBody.productionBalanceCredited, false);
  assert.equal(detailsBody.observedTestnetEvents.length, 1);
  assert.equal(detailsBody.observedTestnetEvents[0].status, 'confirmed');
  assert.equal(detailsBody.testnetLedgerEntries[0].status, 'credited');
  const tokenDetails = await previousFetch(
    `${baseUrl}/api/deposits/address/${usdcDeposit.id}`,
    { headers: { cookie } }
  );
  assert.equal(tokenDetails.status, 200);
  const tokenDetailsBody = await tokenDetails.json();
  assert.equal(tokenDetailsBody.productionBalanceCredited, false);
  assert.equal(tokenDetailsBody.observedTestnetEvents[0].asset, 'USDC');
  assert.equal(tokenDetailsBody.testnetLedgerEntries[0].status, 'credited');

  const ledgerResponse = await previousFetch(`${baseUrl}/api/deposits/testnet-ledger`, {
    headers: { cookie },
  });
  assert.equal(ledgerResponse.status, 200);
  const ledger = await ledgerResponse.json();
  assert.deepEqual(ledger.balances, [
    { asset: 'ETH', amountBaseUnits: '1000000000000000000' },
    { asset: 'USDC', amountBaseUnits: '10' },
  ]);
  assert.equal(ledger.productionBalanceCredited, false);
  assert.equal(ledger.transfersEnabled, false);

  const replayNonce = 'native-deposit-nonce-2';
  const replayTimestamp = String(Date.now());
  const replaySignature = crypto.createHmac('sha256', process.env.QUICKNODE_STREAMS_SECRET)
    .update(replayNonce + replayTimestamp + body)
    .digest('hex');
  const replayedEvent = await previousFetch(`${baseUrl}/api/monitor/quicknode`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-qn-nonce': replayNonce,
      'x-qn-timestamp': replayTimestamp,
      'x-qn-signature': replaySignature,
    },
    body,
  });
  assert.equal(replayedEvent.status, 200);
  assert.equal((await replayedEvent.json()).recorded.length, 2);
  const unchangedLedger = await previousFetch(`${baseUrl}/api/deposits/testnet-ledger`, {
    headers: { cookie },
  });
  assert.deepEqual((await unchangedLedger.json()).balances, ledger.balances);

  const removedLog = { ...usdcLog, removed: true };
  const reorgBody = JSON.stringify({
    chainId: '0xaa36a7',
    logs: [removedLog],
    transactions: [],
  });
  const reorgNonce = 'native-deposit-nonce-3';
  const reorgTimestamp = String(Date.now());
  const reorgSignature = crypto.createHmac('sha256', process.env.QUICKNODE_STREAMS_SECRET)
    .update(reorgNonce + reorgTimestamp + reorgBody)
    .digest('hex');
  const reorged = await previousFetch(`${baseUrl}/api/monitor/quicknode`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-qn-nonce': reorgNonce,
      'x-qn-timestamp': reorgTimestamp,
      'x-qn-signature': reorgSignature,
    },
    body: reorgBody,
  });
  assert.equal(reorged.status, 200);
  const afterReorg = await previousFetch(`${baseUrl}/api/deposits/testnet-ledger`, {
    headers: { cookie },
  });
  assert.deepEqual((await afterReorg.json()).balances, [
    { asset: 'ETH', amountBaseUnits: '1000000000000000000' },
  ]);
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
  const sepoliaDisabled = await request('/api/deposits/address', {
    method: 'POST',
    cookie,
    body: JSON.stringify({
      asset: 'ETH',
      network: 'Sepolia',
      amountUsdCents: 5000,
    }),
  });
  process.env.NODE_ENV = 'test';
  assert.equal(productionDisabled.status, 503);
  assert.match((await productionDisabled.json()).error, /disabled in production/);
  assert.equal(sepoliaDisabled.status, 503);
  assert.match((await sepoliaDisabled.json()).error, /SEPOLIA_DEPOSITS_ENABLED=true/);

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
