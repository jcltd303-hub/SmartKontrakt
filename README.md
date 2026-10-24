# SmartKontrakt

Ethereum signature fundamentals for auditors and exploit reviewers are summarized in [docs/ethereum-signatures.md](docs/ethereum-signatures.md).

The digest covers the practical review angles behind Ethereum message signing, EIP-712 typed data, replay protection, nonce handling, domain separation, and the common contract-level issues that make otherwise valid signatures unsafe.

## Signature audit note

The article [Ethereum Signatures for Hackers and Auditors 101](https://medium.com/coinmonks/ethereum-signatures-for-hackers-and-auditors-101-4da766cd6344) is especially relevant to audit work in this repo because it focuses on the difference between:

- a mathematically valid signature,
- a semantically valid authorization,
- and a safe, replay-resistant contract flow.

The full digest is in the documentation folder so it stays close to the repo’s audit and PoC materials.

## Related docs

- [docs/ethereum-signatures.md](docs/ethereum-signatures.md)
- [docs/smart-poc.md](docs/smart-poc.md)
- [FOUNDRY_POC.md](FOUNDRY_POC.md)

