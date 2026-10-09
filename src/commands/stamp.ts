import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { ICommandContext } from './context.js';
import { IStampFlags, resolveStampConfig } from '../config.js';
import { EXIT_OK } from '../errors.js';
import { describeToken, stamp } from '../lib/TimestampClient.js';
import { stampJson, stampText, toJsonLine, warningLine } from '../output.js';

/**
 * `stamp`: certify a digest, write the token, print the summary.
 *
 * @param {string} [digestArgument] Positional digest.
 * @param {IStampFlags} flags Command flags.
 * @param {ICommandContext} context Streams and interrupt signal.
 * @returns {Promise<number>} Exit code.
 */
export async function runStamp(
  digestArgument: string | undefined,
  flags: IStampFlags,
  context: ICommandContext,
): Promise<number> {
  const config = await resolveStampConfig(digestArgument, flags);

  const token = await stamp(config.digest, config.network, config.apiKey, {
    allowInsecureTransport: config.allowInsecure,
    onWarning: (message): void => {
      context.stderr.write(warningLine(message));
    },
    signal: context.interrupt,
    signer: config.signer,
    timeoutMs: config.timeoutMs,
  });

  const bytes = token.toCBOR();
  const out = config.out === '-' ? null : path.resolve(config.out);
  if (out === null) {
    context.stdout.write(bytes);
  } else {
    await writeFile(out, bytes, { flag: config.force ? 'w' : 'wx' });
  }

  const summary = out === null ? context.stderr : context.stdout;
  const description = describeToken(token);
  summary.write(
    context.json
      ? toJsonLine(stampJson(description, config.network.gatewayUrl, out, bytes))
      : `${stampText(description, config.network.gatewayUrl, out)}\n`,
  );
  return EXIT_OK;
}
