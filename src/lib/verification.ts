import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { VerifiedSealCache } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/VerifiedSealCache.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { PredicateVerifierService } from '@unicitylabs/state-transition-sdk/lib/predicate/verification/PredicateVerifierService.js';
import { MintJustificationVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';

import { TimestampIssuanceVerifier } from './TimestampIssuanceVerifier.js';

/**
 * The SDK's documented production wiring: secp256k1 seal signatures, verified seals memoised.
 *
 * @returns {UnicityCertificateVerifier} Certificate verifier.
 */
export function createUnicityCertificateVerifier(): UnicityCertificateVerifier {
  return new UnicityCertificateVerifier(
    new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), new VerifiedSealCache(256)),
  );
}

/**
 * Verification context that accepts timestamp tokens and nothing else. The
 * issuance registry stays fail-closed, so any other token type is rejected.
 *
 * @param {RootTrustBase} trustBase Trust base of the network the token belongs to.
 * @returns {VerificationContext} Context for `token.verify` and `Token.mint`.
 */
export function createVerificationContext(trustBase: RootTrustBase): VerificationContext {
  return new VerificationContext(
    trustBase,
    PredicateVerifierService.create(),
    createUnicityCertificateVerifier(),
    new MintJustificationVerifierService(),
    new TokenIssuanceVerifierService(true).register(new TimestampIssuanceVerifier()),
  );
}
