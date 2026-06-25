import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { FlowGraphSvg } from './FlowGraphSvg';
import { decideRenderMode, readCapabilities, type RenderMode } from '../lib/capability';

const FlowGraph3D = lazy(() => import('./FlowGraph3D'));

export function IdentityGraph({ posterSrc }: { posterSrc: string }) {
  // Baseline before hydration/capability check: the accessible SVG.
  const [mode, setMode] = useState<RenderMode>('svg');
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        setVisible(true);
        io.disconnect();
      }
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!visible) return;
    let cancelled = false;
    (async () => {
      const caps = await readCapabilities({
        getGpuTier: async () => {
          const { getGPUTier } = await import('@pmndrs/detect-gpu');
          const t = await getGPUTier();
          return t.tier ?? 0;
        },
      });
      if (!cancelled) setMode(decideRenderMode(caps));
    })();
    return () => { cancelled = true; };
  }, [visible]);

  return (
    <div ref={ref} style={{ width: '100%', aspectRatio: '800 / 420' }}>
      {mode === 'poster' && (
        <img src={posterSrc} alt="Identity flow graph (static)" width={800} height={420} style={{ width: '100%', height: 'auto' }} />
      )}
      {mode === 'svg' && <FlowGraphSvg title="Identity flow graph" />}
      {(mode === 'webgl-full' || mode === 'webgl-lite') && (
        <Suspense fallback={<FlowGraphSvg title="Identity flow graph" />}>
          <FlowGraph3D lite={mode === 'webgl-lite'} />
        </Suspense>
      )}
    </div>
  );
}
