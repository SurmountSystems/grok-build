# Address & payment request UX

## Rule (non-negotiable)

**Whenever the UI shows a payment endpoint of any type, it must offer:**

1. **Full string** (address, BOLT11, BOLT12 offer when present, Cashu token only
   in controlled reveal flows).
2. **QR code** encoding the same string (or BIP21 URI when we show on-chain with
   amount).
3. **Copy to clipboard** affordance (one keystroke / button; confirm toast).

No address-only monospaced dump without QR+copy in interactive TUI flows.

## Types

| Type | QR payload | Clipboard | Explorer / extra |
|------|------------|-----------|------------------|
| On-chain address | address or `bitcoin:<addr>` BIP21 | address or BIP21 | link receive addr on mempool.space |
| On-chain with amount | BIP21 with `amount` | BIP21 preferred | same |
| BOLT11 invoice | raw bolt11 bech | bolt11 | optional decode summary (amount, expiry) |
| BOLT12 offer | offer bech (when not deferred) | offer |, |
| txid (status) | optional QR of explorer URL | txid and/or URL | **required** mempool.space tx link |
| npub | npub bech | npub | not a payment method; still QR+copy if shown |
| Cashu token | avoid ambient QR of large tokens in scrollback | copy in secure modal | treat as bearer secret |

## BIP21

When suggesting a deposit amount, prefer:

```text
bitcoin:<address>?amount=<btc>&label=Grok%20OSS%20Routstr
```

QR encodes the BIP21 URI; clipboard can offer “URI” vs “address only.”

## mempool.space links

| Network | Address | Transaction |
|---------|---------|-------------|
| mainnet | `https://mempool.space/address/{addr}` | `https://mempool.space/tx/{txid}` |
| signet | `https://mempool.space/signet/address/…` | `https://mempool.space/signet/tx/…` |
| testnet | `https://mempool.space/testnet/address/…` | `…/testnet/tx/…` |

Configurable base later for private explorers.

## TUI notes

- QR: terminal-friendly (`qrcode` crate or existing deps); ASCII/Unicode QR in
  pane; degrade to “copy + open URL” if terminal too narrow.
- Copy: use existing Grok clipboard helpers (`xai-grok-shared` / pager paths).
- Don’t leave bolt11/Cashu in permanent scrollback without redaction policy.

## Watchers (display)

Address watchers show:

- pending txids (each with link + copy),
- confirmation count,
- amount received,

without spamming mempool.space (see FUNDING_FLOW rate limits).
