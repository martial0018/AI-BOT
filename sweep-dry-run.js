require('dotenv').config();

const fs = require('node:fs/promises');
const { planSweepEvents } = require('./sweeps');

async function main() {
  const inputPath = process.argv[2];
  if (!inputPath || process.argv.includes('--help')) {
    console.log('Usage: npm run sweep:dry-run -- <normalized-deposit-events.json>');
    console.log('Input format: {"deposits":[{"txId":"...","asset":"ETH","network":"ethereum","amountBaseUnits":"1000000","confirmations":12}]}');
    console.log('This command only plans; it never signs or broadcasts transactions.');
    return;
  }

  const contents = await fs.readFile(inputPath, 'utf8');
  const input = JSON.parse(contents.replace(/^\uFEFF/, ''));
  const plans = planSweepEvents(input.deposits);
  console.log(JSON.stringify({
    mode: 'dry-run-only',
    transfersEnabled: false,
    plans,
  }, null, 2));
}

main().catch(error => {
  console.error(`Sweep dry run failed: ${error.message}`);
  process.exitCode = 1;
});
