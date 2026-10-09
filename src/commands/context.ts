import { IWriter } from '../output.js';

/** What every command gets from the entry point. */
export interface ICommandContext {
  /** Fires on SIGINT. */
  readonly interrupt: AbortSignal;
  readonly json: boolean;
  readonly stderr: IWriter;
  readonly stdin: NodeJS.ReadableStream;
  readonly stdout: IWriter;
}
