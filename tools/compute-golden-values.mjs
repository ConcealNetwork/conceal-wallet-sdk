// Compute golden values for conceal-next-wallet/tests/interest.test.ts
import { calculateDepositInterest } from "../dist/index.js";

const M = 1_000_000;
const LOCK = 999_999_999;

function interest(amount, term, lockHeight) {
  return calculateDepositInterest({ amount, term, lockHeight });
}

// V3 monthly
console.log("=== V3 path — monthly term ===");
console.log("tier 1:");
console.log("  1000*M, 21900, LOCK =", interest(1000 * M, 21900, LOCK));
console.log("  1000*M, 21900*12, LOCK =", interest(1000 * M, 21900 * 12, LOCK));
console.log("  1000*M, 21900*24, LOCK =", interest(1000 * M, 21900 * 24, LOCK));
console.log("  9999*M, 21900*6, LOCK =", interest(9999 * M, 21900 * 6, LOCK));
console.log("  5467*M, 21900*6, LOCK =", interest(5467 * M, 21900 * 6, LOCK));

console.log("tier 2:");
console.log("  10000*M, 21900, LOCK =", interest(10000 * M, 21900, LOCK));
console.log("  15000*M, 21900*12, LOCK =", interest(15000 * M, 21900 * 12, LOCK));
console.log("  19999*M, 21900*3, LOCK =", interest(19999 * M, 21900 * 3, LOCK));

console.log("tier 3:");
console.log("  20000*M, 21900, LOCK =", interest(20000 * M, 21900, LOCK));
console.log("  50000*M, 21900*12, LOCK =", interest(50000 * M, 21900 * 12, LOCK));

console.log("routes to V3 just above DEPOSIT_HEIGHT_V3:");
console.log("  1000*M, 21900, 413401 =", interest(1000 * M, 21900, 413_401));

console.log("\n=== V2 investment path ===");
console.log("  1000*M, 64800, LOCK =", interest(1000 * M, 64800, LOCK));
console.log("  200000*M, 64800*2, LOCK =", interest(200000 * M, 64800 * 2, LOCK));
console.log("  2500000*M, 64800*4, LOCK =", interest(2500000 * M, 64800 * 4, LOCK));

console.log("\n=== V2 weekly path ===");
console.log("  1000*M, 5040, LOCK =", interest(1000 * M, 5040, LOCK));
console.log("  1000*M, 5040*10, LOCK =", interest(1000 * M, 5040 * 10, LOCK));
console.log("  50000*M, 5040*4, LOCK =", interest(50000 * M, 5040 * 4, LOCK));

console.log("\n=== Legacy V1 path ===");
const amount = 1_000_000;
const term = 5041;
console.log("  V1 amount=1M, term=5041:");
console.log("    lockHeight=10000:", interest(amount, term, 10_000));
console.log("    lockHeight=12750:", interest(amount, term, 12_750));
console.log("    lockHeight=12751:", interest(amount, term, 12_751));
console.log("    lockHeight=20000:", interest(amount, term, 20_000));
console.log("    lockHeight=1:", interest(amount, term, 1));
console.log("  Large deposit:", interest(90_000_000_011_909, 1_200_002, 1));
