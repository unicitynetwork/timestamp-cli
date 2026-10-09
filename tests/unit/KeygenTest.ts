import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { ICommandContext } from '../../src/commands/context.js';
import { runKeygen } from '../../src/commands/keygen.js';
import { tempDir } from '../support/fixtures.js';

function context(): ICommandContext {
  return {
    interrupt: new AbortController().signal,
    json: false,
    stderr: { write: (): boolean => true },
    stdin: process.stdin,
    stdout: { write: (): boolean => true },
  };
}

// `writeFile`'s mode is masked by the process umask, so a umask covering owner
// bits would otherwise produce a key file at 0200 or 0000 -- unreadable by the
// signing path that needs it -- while the summary still reported 0600.
describe('runKeygen under a umask that masks owner bits', () => {
  let directory: string;
  let previousUmask: number;

  beforeEach(async () => {
    directory = await tempDir('timestamp-cli-umask-');
    previousUmask = process.umask(0o477);
  });

  afterEach(() => {
    process.umask(previousUmask);
  });

  it('still creates a readable 0600 key', async () => {
    const out = path.join(directory, 'fresh.key');
    await runKeygen({ out }, context());
    expect((await stat(out)).mode & 0o777).toBe(0o600);
    expect((await readFile(out, 'utf8')).trim()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('still creates a readable 0600 key when replacing an existing file', async () => {
    const out = path.join(directory, 'existing.key');
    await writeFile(out, 'placeholder\n', { mode: 0o644 });
    await runKeygen({ force: true, out }, context());
    expect((await stat(out)).mode & 0o777).toBe(0o600);
    expect((await readFile(out, 'utf8')).trim()).toMatch(/^[0-9a-f]{64}$/);
  });
});
