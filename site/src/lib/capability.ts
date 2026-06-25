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

/**
 * Synchronous initial render mode, resolved BEFORE the async capability check.
 * Finding #3: reduced-motion / Save-Data clients must render the stable poster
 * from the first paint — initializing to `'svg'` made them flash the animated SVG
 * before the async decision swapped to poster. Reading the two accessibility/data
 * signals synchronously lets the island mount straight into `'poster'`; everyone
 * else still starts on the accessible `'svg'` baseline until the GPU tier lands.
 * SSR-safe: returns `'svg'` when `window`/`navigator` are unavailable.
 */
export function initialRenderMode(): RenderMode {
  if (typeof window === 'undefined' || typeof navigator === 'undefined') return 'svg';
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  const conn = (navigator as unknown as { connection?: { saveData?: boolean } }).connection;
  const saveData = Boolean(conn?.saveData);
  return reducedMotion || saveData ? 'poster' : 'svg';
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
