# Type-03 deposit `globalIndex`

conceal-core `Blockchain::pushTransaction` appends a deposit
(`MultisignatureOutput`) to `m_multisignatureOutputs[amount]` and stores that
list's prior size in `m_global_output_indexes[i]`.
`get_raw_transactions_by_heights` returns those values as `output_indexes`.
A withdraw vin's `outputIndex` is the same index:
`getMultisigOutputReference` resolves `(amount, outputIndex)`.

`0` is the first deposit of that exact atomic amount. The same index number
can exist for a different amount.

Withdraw match is one row: `amount` and `globalIndex === outputIndex`.
Do not mark every deposit that shares an index number. The empty-hash spent
marker `:0` is omitted: every amount's first deposit is index `0`.

Web-wallet: `Wallet.addWithdrawal` (amount + `globalOutputIndex`).
