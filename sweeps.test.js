const test = require('node:test');
const assert = require('node:assert/strict');
const { getSweepReadiness, planSweepEvents, sweepDestinations } = require('./sweeps');

test('sweeping stays disabled until monitor, signer, destinations, and confirmations are configured', () => {
  const readiness = getSweepReadiness({});
  assert.equal(readiness.configured, false);
  assert.equal(readiness.mode, 'disabled');
  assert.ok(readiness.missing.includes('CHAIN_MONITOR_URL'));
  assert.ok(readiness.missing.includes('SWEEP_SIGNER_TOKEN'));
  assert.ok(readiness.missing.includes('SWEEP_DESTINATION_USDT_TRON'));
  assert.ok(readiness.missing.includes('SWEEP_CONFIRMATIONS_ETHEREUM'));
});

test('reports configuration only when every required setting is non-empty', () => {
  const env = {
    CHAIN_MONITOR_URL: 'https://monitor.example',
    CHAIN_MONITOR_TOKEN: 'monitor-token',
    SWEEP_SIGNER_URL: 'https://signer.example',
    SWEEP_SIGNER_TOKEN: 'signer-token',
    SWEEP_CONFIRMATIONS_BITCOIN: '3',
    SWEEP_CONFIRMATIONS_ETHEREUM: '12',
    SWEEP_CONFIRMATIONS_TRON: '20',
    SWEEP_CONFIRMATIONS_SOLANA: '32',
    SWEEP_CONFIRMATIONS_BSC: '15',
  };
  for (const [, , setting] of sweepDestinations) env[setting] = 'public-receive-address';

  assert.deepEqual(getSweepReadiness(env), {
    configured: true,
    mode: 'configured-not-enabled',
    missing: [],
  });
  env.SWEEP_DESTINATION_BTC_BITCOIN = '   ';
  assert.equal(getSweepReadiness(env).configured, false);
});

test('dry-run planner waits for confirmations and never enables transfers', () => {
  const event = {
    txId: 'test-transaction',
    asset: 'ETH',
    network: 'ethereum',
    amountBaseUnits: '1000000',
    confirmations: 11,
  };
  const env = {
    SWEEP_DESTINATION_ETH_ETHEREUM: '0x0000000000000000000000000000000000000001',
    SWEEP_CONFIRMATIONS_ETHEREUM: '12',
  };

  assert.deepEqual(planSweepEvents([event], env), [{
    txId: event.txId,
    asset: 'ETH',
    network: 'ethereum',
    status: 'waiting-confirmations',
    confirmations: 11,
    confirmationThreshold: 12,
  }]);

  const [ready] = planSweepEvents([{ ...event, confirmations: 12 }], env);
  assert.equal(ready.status, 'dry-run-ready');
  assert.equal(ready.destination, env.SWEEP_DESTINATION_ETH_ETHEREUM);
  assert.equal(ready.transfersEnabled, false);
});

test('dry-run planner blocks malformed events and invalid destinations', () => {
  const [invalidEvent] = planSweepEvents([{
    txId: 'test-transaction',
    asset: 'ETH',
    network: 'ethereum',
    amountBaseUnits: '1.2',
    confirmations: 12,
  }]);
  assert.equal(invalidEvent.status, 'blocked');

  const [invalidDestination] = planSweepEvents([{
    txId: 'test-transaction',
    asset: 'ETH',
    network: 'ethereum',
    amountBaseUnits: '1000000',
    confirmations: 12,
  }], {
    SWEEP_DESTINATION_ETH_ETHEREUM: 'not-an-address',
    SWEEP_CONFIRMATIONS_ETHEREUM: '12',
  });
  assert.equal(invalidDestination.status, 'blocked');
});
