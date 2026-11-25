const { isAddress } = require('ethers');

const ethereumPath = index => `m/44'/60'/0'/0/${index}`;

function getTurnkeyConfiguration(env = process.env) {
  const required = [
    'TURNKEY_ORGANIZATION_ID',
    'TURNKEY_WALLET_ID',
    'TURNKEY_EXPECTED_ETH_ADDRESS',
    'TURNKEY_API_PUBLIC_KEY',
    'TURNKEY_API_PRIVATE_KEY',
  ];
  const missing = required.filter(name => !env[name]?.trim());
  if (env.TURNKEY_EXPECTED_ETH_ADDRESS?.trim()
    && !isAddress(env.TURNKEY_EXPECTED_ETH_ADDRESS.trim())) {
    missing.push('TURNKEY_EXPECTED_ETH_ADDRESS');
  }
  return {
    configured: missing.length === 0,
    missing: [...new Set(missing)],
  };
}

function createTurnkeyApiClient(env = process.env) {
  const configuration = getTurnkeyConfiguration(env);
  if (!configuration.configured) {
    throw new Error(`Configure ${configuration.missing[0]} before creating Turnkey deposit addresses.`);
  }

  const { Turnkey } = require('@turnkey/sdk-server');
  return new Turnkey({
    apiBaseUrl: 'https://api.turnkey.com',
    apiPublicKey: env.TURNKEY_API_PUBLIC_KEY.trim(),
    apiPrivateKey: env.TURNKEY_API_PRIVATE_KEY.trim(),
    defaultOrganizationId: env.TURNKEY_ORGANIZATION_ID.trim(),
  }).apiClient();
}

function requireEthereumAddress(address) {
  if (typeof address !== 'string' || !isAddress(address)) {
    throw new Error('Turnkey returned an invalid Ethereum account address.');
  }
  return address;
}

async function deriveTurnkeyEvmAddress(index, env = process.env, apiClient) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
    throw new Error('Invalid deposit address index');
  }

  const configuration = getTurnkeyConfiguration(env);
  if (!configuration.configured) {
    throw new Error(`Configure ${configuration.missing[0]} before creating Turnkey deposit addresses.`);
  }

  const client = apiClient || createTurnkeyApiClient(env);
  const organizationId = env.TURNKEY_ORGANIZATION_ID.trim();
  const walletId = env.TURNKEY_WALLET_ID.trim();
  const accountsResult = await client.getWalletAccounts({ organizationId, walletId });
  if (!Array.isArray(accountsResult?.accounts)) {
    throw new Error('Turnkey returned an invalid wallet account list.');
  }

  const firstPath = ethereumPath(0);
  let firstAccount = accountsResult.accounts.find(account => account.path === firstPath);
  if (!firstAccount) {
    const result = await client.createWalletAccounts({
      organizationId,
      walletId,
      accounts: [{
        curve: 'CURVE_SECP256K1',
        pathFormat: 'PATH_FORMAT_BIP32',
        path: firstPath,
        addressFormat: 'ADDRESS_FORMAT_ETHEREUM',
      }],
    });
    const address = requireEthereumAddress(result?.addresses?.[0]);
    firstAccount = { path: firstPath, address };
  }

  const expectedAddress = env.TURNKEY_EXPECTED_ETH_ADDRESS.trim();
  const verifiedFirstAddress = requireEthereumAddress(firstAccount.address);
  if (verifiedFirstAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
    throw new Error('Turnkey account 0 does not match TURNKEY_EXPECTED_ETH_ADDRESS.');
  }
  if (index === 0) return verifiedFirstAddress;

  const targetPath = ethereumPath(index);
  const existingAccount = accountsResult.accounts.find(account => account.path === targetPath);
  if (existingAccount) return requireEthereumAddress(existingAccount.address);

  const result = await client.createWalletAccounts({
    organizationId,
    walletId,
    accounts: [{
      curve: 'CURVE_SECP256K1',
      pathFormat: 'PATH_FORMAT_BIP32',
      path: targetPath,
      addressFormat: 'ADDRESS_FORMAT_ETHEREUM',
    }],
  });
  return requireEthereumAddress(result?.addresses?.[0]);
}

module.exports = {
  createTurnkeyApiClient,
  deriveTurnkeyEvmAddress,
  getTurnkeyConfiguration,
};
