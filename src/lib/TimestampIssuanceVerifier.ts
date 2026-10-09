import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import type { ITokenIssuanceVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/ITokenIssuanceVerifier.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { TIMESTAMP_RECIPIENT_ENCODED, TIMESTAMP_TOKEN_TYPE } from './constants.js';
import { errorMessage } from './errors.js';
import { NO_PAYLOAD_MESSAGE, TimestampPayload } from './TimestampPayload.js';

/**
 * Issuance policy for the timestamp token type. Registered with the SDK's
 * fail-closed {@link TokenIssuanceVerifierService}, so it runs as part of
 * `token.verify` and `Token.mint` for every token of
 * {@link TIMESTAMP_TOKEN_TYPE}, and every other type is rejected.
 *
 * Rules, in order: the recipient is the timestamp burn predicate, there is no
 * mint justification, a payload is present, it decodes (which includes the
 * signer key being a valid curve point), and its signature verifies. Each rule
 * is a child result so a failure names the rule that tripped. The verifier
 * never throws.
 */
export class TimestampIssuanceVerifier implements ITokenIssuanceVerifier {
  public static readonly RULE = 'TimestampIssuanceVerification';

  /**
   * @returns {TokenType} The timestamp token type.
   */
  public get tokenType(): TokenType {
    return TIMESTAMP_TOKEN_TYPE;
  }

  private static check(rule: string, ok: boolean, failureMessage: string): VerificationResult<VerificationStatus> {
    return new VerificationResult(rule, ok ? VerificationStatus.OK : VerificationStatus.FAIL, ok ? '' : failureMessage);
  }

  private static async payloadRules(data: Uint8Array): Promise<VerificationResult<VerificationStatus>[]> {
    let payload: TimestampPayload;
    try {
      payload = TimestampPayload.fromCBOR(data);
    } catch (error) {
      return [TimestampIssuanceVerifier.check('PayloadDecodes', false, errorMessage(error))];
    }
    return [
      TimestampIssuanceVerifier.check('PayloadDecodes', true, ''),
      TimestampIssuanceVerifier.check(
        'SignatureValid',
        await payload.verifySignature(),
        'Payload signature does not verify for the signer.',
      ),
    ];
  }

  /**
   * @inheritDoc
   */
  public async verify(transaction: CertifiedMintTransaction): Promise<VerificationResult<VerificationStatus>> {
    let results: VerificationResult<VerificationStatus>[];
    try {
      const data = transaction.data;
      results = [
        TimestampIssuanceVerifier.check(
          'RecipientIsTimestampBurn',
          EncodedPredicate.equals(transaction.recipient, TIMESTAMP_RECIPIENT_ENCODED),
          'Recipient is not the timestamp burn predicate.',
        ),
        TimestampIssuanceVerifier.check(
          'NoMintJustification',
          transaction.justification === null,
          'Timestamp tokens carry no mint justification.',
        ),
        TimestampIssuanceVerifier.check('PayloadPresent', data !== null, NO_PAYLOAD_MESSAGE),
        ...(data === null ? [] : await TimestampIssuanceVerifier.payloadRules(data)),
      ];
    } catch (error) {
      results = [TimestampIssuanceVerifier.check('Unexpected', false, errorMessage(error))];
    }

    const firstFailure = results.find((result) => result.status !== VerificationStatus.OK);
    return VerificationResult.fromResults(TimestampIssuanceVerifier.RULE, results, firstFailure?.message ?? '');
  }
}
