/**
 * Strike policy — revoke a node after repeated denials.
 *
 * A denied agent that keeps probing the same wall is either broken or hostile.
 * After N strikes the node is cascade-revoked and the parent can see why on the
 * ledger. Off unless a policy is attached.
 */

export type StrikeMode = "same_scope" | "total";

export interface StrikePolicyInit {
  /** A policy is only attached when wanted; `false` disarms without detaching. */
  enabled?: boolean;
  /** Strikes before revocation. */
  n?: number;
  /** `same_scope`: N denials of ONE scope. `total`: N denials across any scope. */
  mode?: StrikeMode;
}

export class StrikePolicy {
  readonly enabled: boolean;
  readonly n: number;
  readonly mode: StrikeMode;

  constructor(init: StrikePolicyInit = {}) {
    this.enabled = init.enabled ?? true;
    this.n = init.n ?? 3;
    this.mode = init.mode ?? "same_scope";
    if (this.mode !== "same_scope" && this.mode !== "total") {
      throw new Error("mode must be 'same_scope' or 'total'");
    }
    if (this.n < 1) throw new Error("n must be >= 1");
  }

  key(nodeId: string, scope: string): string {
    return this.mode === "same_scope" ? `${nodeId} ${scope}` : `${nodeId} *`;
  }
}
