# `/sendrawtransaction` status

Source of truth in conceal-core (sibling checkout):

- Handler: `conceal-core/src/Rpc/RpcServer.cpp` — `RpcServer::on_send_raw_tx`
- Wire types: `conceal-core/src/Rpc/CoreRpcServerCommandsDefinitions.h` —
  `COMMAND_RPC_SEND_RAW_TX` (`request.tx_as_hex`, `response.status` only);
  `CORE_RPC_STATUS_OK` (`"OK"`), `CORE_RPC_STATUS_BUSY` (`"BUSY"`, unused here)
- Busy gate: `RpcServer::processRequest` — HTTP 500 body `Core is busy` when
  `!allowBusyCore && !isCoreReady()` (`/sendrawtransaction` has `allowBusyCore = false`)
- Already-known tx: `conceal-core/src/CryptoNoteCore/Core.cpp` — `core::add_new_tx`
- Relay / fee policy: `conceal-core/src/CryptoNoteCore/TransactionPool.cpp` —
  `tx_memory_pool::add_tx` (`m_should_be_relayed`)

The handler returns JSON `{ status }` only. There is no `reason` field today
(the SDK still accepts one for a future core). The request has no `do_not_relay`
field (clients may send it; the daemon ignores unknown members).

## Status values

| Status | Set in conceal-core when |
| --- | --- |
| `OK` | `CORE_RPC_STATUS_OK` after accept + relay (`m_should_be_relayed`) |
| `Failed` | Bad hex, `handle_incoming_tx` failure, or `m_verification_failed` (double-spend detail is log-only) |
| `Too big` | Blob exceeds `transactionMaxSize()` |
| `Not relayed` | Accept path but `!m_should_be_relayed` — usually already in pool/chain (`add_new_tx`), recently-deleted ignore, or local accept without gossip (v8+ fee policy: relay when `fee == 1000` or fusion / withdraw / TTL). Not a hard rejection, not proof of peer relay. |

## SDK contract

`DaemonClient.sendRawTransaction` resolves with `{ status, reason? }` for every
answered submit (including `Failed` / `Too big` / `Not relayed`). It throws only
on empty hex, timeout, network/HTTP errors, or a malformed body.

Hosts must branch on `status`. Do not sniff error message text.

## Outbound queue mapping (deprecated)

| Result | Queue action |
| --- | --- |
| `OK` or `Not relayed` | `broadcast` — stop resubmitting; keep key-image reservation until the host `remove()`s after mine. |
| `Failed`, `Too big`, or unknown status | `failed` / `rejected` (never `conflict` — RPC has no spend detail). |
| Thrown transport error | Transient retry until `maxAttempts`. |
