# Type-03 deposit `globalIndex`

Conceal `get_raw_transactions_by_heights` sets `output_indexes[i] = 0` for
`txout_to_deposit_key` outputs. Those outputs are not in the type-02 global
index list. A type-03 withdraw vin uses the same `outputIndex: 0`.

`0` is a sentinel, not a unique chain index. Identity is create `txHash` +
one-time key. Withdraw matching: one row (amount, and `gi` only when `gi > 0`).
Do not mark every stored `txhash:0` spent from a single vin.

Web-wallet: `Wallet.addWithdrawal` (amount + index, first match only).
