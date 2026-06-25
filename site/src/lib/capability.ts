export type RenderMode = 'poster' | 'svg' | 'webgl-lite' | 'webgl-full';

export interface CapabilityInputs {
  reducedMotion: boolean;
  saveData: boolean;
  webgl: boolean;
  gpuTier: number; // 0..3 from detect-gpu
  cores: number;
}

// Precedence: accessibility/data-saving wins, then capability tiers.
export function decideRenderMode(i: CapabilityInputs): RenderMode {
  if (i.reducedMotion || i.saveData) return 'poster';
  if (!i.webgl || i.gpuTier <= 1 || i.cores < 4) return 'svg';
  if (i.gpuTier === 2) return 'webgl-lite';
  return 'webgl-full';
}

function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas');
    return !!(c.getContext('webgl2') || c.getContext('webgl'));
  } catch {
    return false;
  }
}

export async function readCapabilities(opts: {
  getGpuTier: () => Promise<number>;
}): Promise<CapabilityInputs> {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const conn = (navigator as unknown as { connection?: { saveData?: boolean } }).connection;
  const saveData = Boolean(conn?.saveData);
  const cores = navigator.hardwareConcurrency ?? 4;
  const webgl = hasWebGL();
  const gpuTier = webgl ? await opts.getGpuTier() : 0;
  return { reducedMotion, saveData, webgl, gpuTier, cores };
}
