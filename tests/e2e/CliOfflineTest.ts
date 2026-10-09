import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runCli } from '../support/cli.js';
import { tempDir, TEST_DIGEST_HEX } from '../support/fixtures.js';

const TIMEOUT = 30_000;

describe('unicity-timestamp (offline)', () => {
  let cwd: string;

  beforeAll(async () => {
    cwd = await tempDir('timestamp-cli-e2e-');
  });

  it(
    'prints help and version',
    async () => {
      const [help, version] = await Promise.all([runCli(['--help'], { cwd }), runCli(['--version'], { cwd })]);
      expect(help.code).toBe(0);
      expect(help.stdout).toContain('stamp');
      expect(help.stdout).toContain('verify');
      expect(version.code).toBe(0);
      expect(version.stdout.trim()).toEqual('0.1.0');
    },
    TIMEOUT,
  );

  it(
    'exits 2 on usage errors before touching the network',
    async () => {
      const cases: string[][] = [
        ['stamp', 'not-a-digest', '--api-key', 'sk_x'],
        ['stamp', TEST_DIGEST_HEX, '--file', 'x', '--api-key', 'sk_x'],
        ['stamp', '--api-key', 'sk_x'],
        ['stamp', TEST_DIGEST_HEX],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--sign'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--network', 'devnet'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--gateway', 'http://127.0.0.1:9'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--timeout', '0'],
        ['verify', '/nonexistent.cbor'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--dotenv', '/nonexistent.env'],
        ['nonsense'],
      ];
      const results = await Promise.all(cases.map((args) => runCli(args, { cwd })));
      results.forEach((result, index) => {
        expect({ args: cases[index], code: result.code }).toEqual({ args: cases[index], code: 2 });
        expect(result.stderr).not.toEqual('');
      });
    },
    TIMEOUT,
  );

  it(
    'loads env files but lets the environment win',
    async () => {
      const envFile = path.join(cwd, 'custom.env');
      await writeFile(envFile, 'UNICITY_NETWORK=devnet\n');
      const dotenvDir = await tempDir('timestamp-cli-dotenv-');
      await writeFile(path.join(dotenvDir, '.env'), 'UNICITY_NETWORK=devnet\n');
      const args = [
        'stamp',
        TEST_DIGEST_HEX,
        '--api-key',
        'sk_x',
        '--gateway',
        'http://127.0.0.1:9',
        '--dotenv',
        envFile,
      ];

      const [fromFile, fromEnv, fromDefault] = await Promise.all([
        runCli(args, { cwd }),
        runCli(args, { cwd, env: { UNICITY_NETWORK: 'testnet2' } }),
        runCli(['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x'], { cwd: dotenvDir }),
      ]);
      expect(fromFile.code).toBe(2);
      expect(fromFile.stderr).toContain("Unknown network 'devnet'");
      expect(fromEnv.code).toBe(2);
      expect(fromEnv.stderr).toContain('plain HTTP');
      expect(fromDefault.code).toBe(2);
      expect(fromDefault.stderr).toContain("Unknown network 'devnet'");
    },
    TIMEOUT,
  );

  it(
    'reports files that are not tokens with exit 1',
    async () => {
      const garbage = path.join(cwd, 'garbage.cbor');
      await writeFile(garbage, 'definitely not cbor');
      const [verify, fromStdin, inspect] = await Promise.all([
        runCli(['verify', garbage], { cwd }),
        runCli(['verify', '-', '--json'], { cwd, input: 'deadbeef' }),
        runCli(['inspect', garbage], { cwd }),
      ]);
      expect(verify.code).toBe(1);
      expect(verify.stdout).toContain('FAIL: not a token');
      expect(fromStdin.code).toBe(1);
      expect(JSON.parse(fromStdin.stdout)).toMatchObject({ command: 'verify', status: 'FAIL' });
      expect(inspect.code).toBe(1);
    },
    TIMEOUT,
  );

  it(
    'generates keys with mode 0600 and refuses to overwrite',
    async () => {
      const keyFile = path.join(cwd, 'my.key');
      const first = await runCli(['keygen', '--out', keyFile], { cwd });
      expect(first.code).toBe(0);
      expect(first.stdout).toContain('Public key');
      const key = (await readFile(keyFile, 'utf8')).trim();
      expect(key).toMatch(/^[0-9a-f]{64}$/);
      expect((await stat(keyFile)).mode & 0o777).toBe(0o600);

      const second = await runCli(['keygen', '--out', keyFile], { cwd });
      expect(second.code).toBe(2);
      expect(second.stderr).toContain('Refusing to overwrite');

      const forced = await runCli(['keygen', '--out', keyFile, '--force', '--json'], { cwd });
      expect(forced.code).toBe(0);
      expect(JSON.parse(forced.stdout)).toMatchObject({ command: 'keygen', out: keyFile });
      expect((await readFile(keyFile, 'utf8')).trim()).not.toEqual(key);

      const piped = await runCli(['keygen', '--out', '-'], { cwd });
      expect(piped.code).toBe(0);
      expect(piped.stdout.trim()).toMatch(/^[0-9a-f]{64}$/);
      expect(piped.stderr).toEqual('');
    },
    TIMEOUT,
  );

  it(
    'verifies the committed fixtures offline',
    async () => {
      const fixtures = path.resolve('tests/fixtures');
      const anonymous = path.join(fixtures, 'testnet2-anonymous.cbor');
      const tampered = path.join(cwd, 'tampered.cbor');
      const bytes = new Uint8Array(await readFile(anonymous));
      bytes[bytes.length - 1] ^= 0x01;
      await writeFile(tampered, bytes);

      const [anonymousResult, signedResult, mismatch, wrongNetwork, tamperedResult, inspected] = await Promise.all([
        runCli(['verify', anonymous, '--json'], { cwd }),
        runCli(['verify', path.join(fixtures, 'testnet2-signed.cbor'), '--json'], { cwd }),
        runCli(['verify', anonymous, '--hash', TEST_DIGEST_HEX], { cwd }),
        runCli(['verify', anonymous, '--network', 'mainnet'], { cwd }),
        runCli(['verify', tampered], { cwd }),
        runCli(['inspect', anonymous, '--json'], { cwd }),
      ]);

      for (const [result, signed] of [
        [anonymousResult, false],
        [signedResult, true],
      ] as const) {
        expect(result.code).toBe(0);
        const json = JSON.parse(result.stdout) as { network: { name: string }; signer: string | null; status: string };
        expect(json.status).toEqual('OK');
        expect(json.network.name).toEqual('testnet2');
        expect(json.signer !== null).toBe(signed);
      }
      expect(mismatch.code).toBe(1);
      expect(mismatch.stdout).toContain('Hash mismatch');
      expect(wrongNetwork.code).toBe(1);
      expect(wrongNetwork.stdout).toContain('network 4 but the trust base is for network 1');
      expect(tamperedResult.code).toBe(1);
      expect(inspected.code).toBe(0);
      expect(JSON.parse(inspected.stdout)).toMatchObject({ command: 'inspect', network: { id: 4 }, verified: false });
    },
    TIMEOUT,
  );
});
