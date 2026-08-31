/**
 * version.ts — the package version, as its own leaf module.
 *
 * guard.ts needs this (to attribute a guard-supplied `adapter.version` on a bare `check()` with
 * no wrapper — see the "Execution binding" section of guard.ts's module doc comment) and is
 * itself imported BY index.ts, so index.ts cannot be the source: `guard.ts -> index.ts ->
 * guard.ts` would be circular. A one-constant leaf module has nothing to be circular with.
 */
export const VERSION = "0.5.0";
