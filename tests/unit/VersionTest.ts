import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { VERSION } from '../../src/version.js';

describe('VERSION', () => {
  it('matches package.json', async () => {
    const manifest = JSON.parse(await readFile(path.resolve('package.json'), 'utf8')) as { version: string };
    expect(VERSION).toEqual(manifest.version);
  });
});
