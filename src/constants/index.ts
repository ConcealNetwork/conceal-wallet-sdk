// Copyright (c) 2026 Conceal Network, Conceal Devs
// SPDX-License-Identifier: MIT

/** Chain / consensus scalars — single source of truth for the SDK and wallet apps. */

export * from "./blockchain";
export {
  FUSION_TX_MAX_INPUT_COUNT,
  FUSION_TX_MAX_SIZE,
  FUSION_TX_MIN_IN_OUT_COUNT_RATIO,
  FUSION_TX_MIN_INPUT_COUNT,
  isPrettyAmount,
  MAX_FUSION_OUTPUTS,
  NUM_BUCKETS,
  OPTIMIZE_OUTPUTS,
  OPTIMIZE_THRESHOLD,
  PRETTY_AMOUNTS,
} from "./fusion-const";
export * from "./message-const";
export * from "./tx-const";
