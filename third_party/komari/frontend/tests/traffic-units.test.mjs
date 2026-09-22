import assert from 'node:assert/strict';
import test from 'node:test';
import { formatTrafficBytes, parseTrafficBytes } from '../src/utils/trafficUnits.ts';

test('provider quota and direction totals retain decimal GB', () => {
  assert.equal(parseTrafficBytes('500 GB'), 500_000_000_000);
  assert.equal(parseTrafficBytes('2,000 GB'), 2_000_000_000_000);
  assert.equal(parseTrafficBytes('3.3 TB'), 3_300_000_000_000);
  assert.equal(formatTrafficBytes(80_280_000_000), '80.28 GB');
  assert.equal(formatTrafficBytes(2_000_000_000_000), '2.00 TB');
  assert.equal(parseTrafficBytes('1 GiB'), 1_073_741_824);
});

test('invalid values cannot execute expressions or overflow', () => {
  for (const input of ['1*1024GB', 'Infinity', '-1 GB', 'alert(1)', '999999999 PB']) {
    assert.equal(parseTrafficBytes(input), 0);
  }
  assert.equal(formatTrafficBytes(NaN), '-');
  assert.equal(formatTrafficBytes(0), '0 B');
});
