import { describe, it, expect } from 'vitest';
import { dampScalar, decayTarget, isAnimating, pulseFlashesPerSecond } from './anim';

describe('anim math', () => {
  it('dampScalar moves toward the target and converges', () => {
    let v = 0;
    for (let i = 0; i < 240; i++) v = dampScalar(v, 1, 4, 1 / 60);
    expect(v).toBeGreaterThan(0.98);
    expect(v).toBeLessThanOrEqual(1);
  });
  it('dampScalar with equal current/target is a no-op', () => {
    expect(dampScalar(0.5, 0.5, 4, 1 / 60)).toBeCloseTo(0.5, 6);
  });
  it('decayTarget pulls a spike back toward zero', () => {
    let t = 1;
    for (let i = 0; i < 240; i++) t = decayTarget(t, 3, 1 / 60);
    expect(t).toBeLessThan(0.02);
  });
  it('isAnimating is true while far from target and false when settled', () => {
    expect(isAnimating([1], [0])).toBe(true);
    expect(isAnimating([0.0001], [0])).toBe(false);
  });
  it('pulse cadence stays at or under 3 flashes/sec', () => {
    expect(pulseFlashesPerSecond(3)).toBeLessThanOrEqual(3);
  });
});
