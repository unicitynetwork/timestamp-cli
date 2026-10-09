import { chmod, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import { EXIT_OK } from '../errors.js';
import { keygenJson, keygenText, toJsonLine } from '../output.js';

export interface IKeygenFlags {
  readonly force?: boolean;
  readonly out?: string;
}

const DEFAULT_KEY_FILE = 'unicity-timestamp.key';

/**
 * `keygen`: write a fresh secp256k1 private key as 64 hex characters, mode 0600.
 * An existing file is left alone unless `--force`; the EEXIST from `wx` is
 * rendered by the shared error mapping.
 *
 * @param {IKeygenFlags} flags Command flags.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code.
 */
export async function runKeygen(flags: IKeygenFlags, context: ICommandContext): Promise<number> {
  const privateKey = SigningService.generatePrivateKey();
  const hex = HexConverter.encode(privateKey);

  if (flags.out === '-') {
    context.stdout.write(`${hex}\n`);
    return EXIT_OK;
  }

  const out = path.resolve(flags.out ?? DEFAULT_KEY_FILE);
  await writeFile(out, `${hex}\n`, { flag: flags.force ? 'w' : 'wx', mode: 0o600 });
  // `mode` above only applies when the file is created, so a `--force` overwrite
  // would leave a private key at whatever permissions the old file had while the
  // summary below claims 0600.
  await chmod(out, 0o600);

  const publicKey = HexConverter.encode(new SigningService(privateKey).publicKey);
  context.stdout.write(context.json ? toJsonLine(keygenJson(out, publicKey)) : `${keygenText(out, publicKey)}\n`);
  return EXIT_OK;
}
