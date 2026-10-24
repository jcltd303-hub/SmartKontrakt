# Ethereum signatures for hackers and auditors

This note is a practical digest of the article [Ethereum Signatures for Hackers and Auditors 101](https://medium.com/coinmonks/ethereum-signatures-for-hackers-and-auditors-101-4da766cd6344).

It is relevant to any audit workflow that verifies off-chain signatures, permits, account abstraction, or typed approvals in EVM contracts.

## The core idea

Ethereum signatures are not magic. They are just ECDSA signatures over a specific hash of a message, and the contract later recovers the signer with `ecrecover` or a library such as OpenZeppelin's `ECDSA` helper.

The dangerous part is not the math; it is the message format and replay surface.

A wallet can sign any payload. If the contract accepts a signature without checking:

- the exact signing domain,
- the exact call target or function semantics,
- the nonce or deadline,
- the signer identity,
- the chain ID,

then the signature may be reused, replayed, or abused in ways the user never intended.

## 1) Raw message signing is unsafe by default

When a wallet uses `eth_sign`, the app usually signs the raw byte string exactly as supplied. This is convenient for client-side signing, but it is not structured and often not domain-bound.

The classic Ethereum message prefix is:

```solidity
keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", len(message), message))
```

This prefix is meant to prevent cross-protocol confusion. It makes the signed payload look like an Ethereum message rather than a raw bytestring, but it still does not provide strong semantic meaning for a contract.

Why it matters:

- A user may sign an arbitrary string that turns into a malicious function call.
- The same payload may be replayable in a different context.
- There is no clear typed schema or domain separator unless the app does one explicitly.

This is why auditors treat raw message signing as a potential red flag unless the application is intentionally designed around it.

## 2) EIP-712: typed data with domain separation

`eth_signTypedData` / EIP-712 is much safer than signing a naked string. It hashes a structured object with:

- domain separators,
- type schemas,
- values for each field,
- a chain ID and contract address when relevant.

The hash pattern is conceptually:

```solidity
keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
```

The domain separator includes fields like:

- `name`
- `version`
- `chainId`
- `verifyingContract`
- `salt` (sometimes)

This matters because the same signer cannot accidentally reuse a signature across unrelated contracts or chains if the domain differs.

### Example: permit-style approval

A permit signature commonly includes:

- `owner`
- `spender`
- `value`
- `nonce`
- `deadline`

The contract then verifies:

```solidity
require(block.timestamp <= deadline, "expired");
require(nonce == usedNonce[owner] + 1, "bad nonce");
require(recovered == owner, "bad sig");
```

This pattern is powerful because the signature is bound to a specific token, spender, owner, amount, deadline, and chain context.

## 3) Why replay protection matters

The biggest signature vulnerabilities are not always “broken ECDSA.” They are often “valid signature, wrong context.”

Common controls include:

- `nonce` per signer to prevent replay of the same signed approval,
- `deadline` so old signatures expire,
- `chainId` in the domain to keep signatures off-chain chain-specific,
- `verifyingContract` to bind the signature to the exact contract,
- strict `owner` and `spender` checks before state mutation.

Without these, a contract may accept signatures that are mathematically valid but semantically dangerous.

## 4) False assumptions that attackers exploit

The article is especially useful because it highlights the usual mistakes:

- assuming all signatures are equivalent,
- forgetting that the application’s own message format matters,
- not validating domain and chain binding,
- reusing signatures across different contracts,
- allowing `s` malleability or unchecked `v` values,
- trusting off-chain user intent without making the contract enforce it.

In practice, many “signature bugs” are actually message design bugs.

## 5) Ecrecover and the contract side

From the Solidity side, the wallet signs something and the contract does:

```solidity
bytes32 digest = keccak256(...);
(address recovered, ECDSA.RecoverError err, bytes32 r, bytes32 s, uint8 v) = ecrecover(digest);
```

The contract must then validate:

- recovered address is not zero,
- recovered address is the expected owner,
- signature is not reused in another context,
- `v` and low-s values are handled correctly,
- `nonce` and `deadline` are checked as designed.

Libraries like OpenZeppelin `ECDSA` help, but they do not replace protocol-specific validation logic.

## 6) Malleability and signature normalization

ECDSA signatures are malleable in a few ways. The signature `(r, s)` can sometimes be transformed into another valid signature with the same public key. This is why a secure implementation often enforces canonical `s` values:

- use the lower-half `s` unless the protocol explicitly allows the higher half,
- reject duplicate or ambiguous signatures,
- ensure the business logic is invariant to signature format quirks.

This is a classic audit area: a contract may accept an “equivalent” signature and interpret it as a new authorization even though the underlying user intent was not the expected one.

## 7) Audit checklist for signatures

When reviewing a contract or wallet flow, auditors should check:

- Is the message structured with EIP-712 or an equivalent format?
- Is the domain separator unique to the intended contract and chain?
- Is a nonce, deadline, or expiry enforced?
- Is the recovered signer checked against exactly the privileged owner or role holder?
- Is the signature bound to the exact function or approval being executed?
- Is replay protection present across all entry points?
- Are malformed or duplicated signatures rejected deterministically?
- Does the code explicitly guard against low/high `s` value ambiguity?

This is the real “security model” behind Ethereum signatures: the hash, domain, protocol rules, and replay prevention are inseparable.

## 8) SmartKontrakt relevance

This repo’s audit tooling is particularly sensitive to signature semantics because it reasons about contract behaviors, approvals, and exploit patterns. In that context, signature checks are a common source of findings when:

- approvals are not domain-bound, 
- nonces are missing or reused,
- typed data is not enforced,
- `permit` or meta-tx flows are validated against the wrong signer,
- replay across chains is possible because the chain ID or contract address was not included in the hash.

For contract auditors, the most important lesson is simple:

A valid signature is not automatically a valid authorization.

The protocol must encode the signer’s intent, the contract context, the chain context, and the expiry/replay protections in the signed payload itself.

## References

- The original article: [Ethereum Signatures for Hackers and Auditors 101](https://medium.com/coinmonks/ethereum-signatures-for-hackers-and-auditors-101-4da766cd6344)
- EIP-712: [Ethereum Improvement Proposal 712](https://eips.ethereum.org/EIPS/eip-712)
- EIP-2612: [Permit](https://eips.ethereum.org/EIPS/eip-2612)
- OpenZeppelin ECDSA docs: [OpenZeppelin ECDSA](https://docs.openzeppelin.com/contracts/5.x/api/utils#ECDSA)

---

This note is intentionally written as a practical audit reference, not a replacement for the underlying protocol specs or a formal code review of any specific contract.

