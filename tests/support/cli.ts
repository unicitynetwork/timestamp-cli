import { spawn } from 'node:child_process';
import path from 'node:path';
import { text } from 'node:stream/consumers';

export interface ICliResult {
  readonly code: number;
  readonly stderr: string;
  readonly stdout: string;
}

export interface ICliOptions {
  readonly cwd: string;
  readonly env?: Record<string, string>;
  readonly input?: Uint8Array | string;
}

/** Built entry point; `npm test` builds first through the pretest script. */
const CLI_PATH = path.resolve('lib/cli.js');

/**
 * Run the built CLI as a child process with a minimal environment, so the
 * developer's shell and .env do not leak into the command under test.
 */
export function runCli(args: string[], options: ICliOptions): Promise<ICliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: options.cwd,
      env: { HOME: process.env.HOME ?? '', PATH: process.env.PATH ?? '', ...options.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout = text(child.stdout);
    const stderr = text(child.stderr);
    child.on('error', reject);
    child.on('close', (code) => {
      void Promise.all([stdout, stderr]).then(
        ([out, err]) => resolve({ code: code ?? -1, stderr: err, stdout: out }),
        reject,
      );
    });
    child.stdin.end(options.input);
  });
}
