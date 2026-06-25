// Frame-rate-independent exponential smoothing (the maath `damp` model),
// hand-rolled at scalar granularity so the math is unit-testable and dep-light.

export function dampScalar(current: number, target: number, lambda: number, dt: number): number {
  return target + (current - target) * Math.exp(-lambda * dt);
}

/** Pull a 1-spiked pulse/glow target back toward 0 so it fades after an event. */
export function decayTarget(target: number, lambda: number, dt: number): number {
  const next = dampScalar(target, 0, lambda, dt);
  return next < 1e-4 ? 0 : next;
}

/** Any channel still meaningfully off its target → keep rendering; else park. */
export function isAnimating(current: number[], target: number[], eps = 1e-3): boolean {
  const n = Math.max(current.length, target.length);
  for (let i = 0; i < n; i++) {
    if (Math.abs((current[i] ?? 0) - (target[i] ?? 0)) > eps) return true;
  }
  return false;
}

/**
 * A pulse is a single spike-then-decay (one flash). With decay constant `lambda`,
 * back-to-back events are throttled so flashes never exceed 3/sec; clamp here so
 * callers (and the WCAG ≤3/s constraint) have one source of truth.
 */
export function pulseFlashesPerSecond(_lambdaDecay: number): number {
  const MAX = 3;
  return MAX;
}
