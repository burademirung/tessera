import { describe, it, expect } from 'vitest';
import { decideRenderMode } from './capability';

const base = { reducedMotion: false, saveData: false, webgl: true, gpuTier: 3, cores: 8 };

describe('decideRenderMode', () => {
  it('uses full webgl on a capable device', () => {
    expect(decideRenderMode(base)).toBe('webgl-full');
  });
  it('uses webgl-lite on a mid GPU', () => {
    expect(decideRenderMode({ ...base, gpuTier: 2 })).toBe('webgl-lite');
  });
  it('falls back to svg with no webgl', () => {
    expect(decideRenderMode({ ...base, webgl: false })).toBe('svg');
  });
  it('falls back to svg on tier 1 or low cores', () => {
    expect(decideRenderMode({ ...base, gpuTier: 1 })).toBe('svg');
    expect(decideRenderMode({ ...base, cores: 2 })).toBe('svg');
  });
  it('falls back to poster on reduced-motion or save-data', () => {
    expect(decideRenderMode({ ...base, reducedMotion: true })).toBe('poster');
    expect(decideRenderMode({ ...base, saveData: true })).toBe('poster');
  });
});
