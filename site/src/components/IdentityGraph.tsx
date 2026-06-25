import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { FlowGraphSvg } from './FlowGraphSvg';
import { TelemetryTable } from './TelemetryTable';
import {
  decideRenderMode,
  initialRenderMode,
  readCapabilities,
  type RenderMode,
} from '../lib/capability';
import { useTelemetrySource } from '../lib/useTelemetrySource';
import { useTelemetryStore } from '../lib/telemetry-store';

const FlowGraph3D = lazy(() => import('./FlowGraph3D'));

export function IdentityGraph({ posterSrc }: { posterSrc: string }) {
  // Finding #3: resolve reduced-motion / Save-Data SYNCHRONOUSLY so those clients
  // mount straight into the stable poster (no SVG→poster flash). Everyone else
  // starts on the accessible `svg` baseline until the async capability check lands.
  const [mode, setMode] = useState<RenderMode>(initialRenderMode);
  // `decided` flips true only after the capability check resolves. We MUST NOT
  // open an EventSource on the pre-decision baseline — a reduced-motion/Save-Data
  // client (which resolves to `poster`) would otherwise briefly open a stream.
  const [decided, setDecided] = useState(false);
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const paused = useTelemetryStore((s) => s.paused);
  const setPaused = useTelemetryStore((s) => s.setPaused);

  const live =
    decided && (mode === 'svg' || mode === 'webgl-lite' || mode === 'webgl-full');
  // Stream only AFTER the capability decision, in live modes, while not paused.
  // Poster (reduced-motion / Save-Data) never reaches `live` → never opens a source.
  useTelemetrySource({ enabled: live && !paused });

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
      if (!cancelled) {
        setMode(decideRenderMode(caps));
        setDecided(true); // unblocks the EventSource gate (only now, post-decision)
      }
    })();
    return () => { cancelled = true; };
  }, [visible]);

  return (
    <div ref={ref} style={{ width: '100%' }}>
      {/* Reserve the LCP region via aspect-ratio so render-mode swaps are CLS 0. */}
      <div style={{ width: '100%', aspectRatio: '800 / 420' }}>
        {mode === 'poster' && (
          <img
            src={posterSrc}
            alt="Identity flow graph (static)"
            width={800}
            height={420}
            style={{ width: '100%', height: 'auto' }}
          />
        )}
        {mode === 'svg' && <FlowGraphSvg title="Identity flow graph" />}
        {(mode === 'webgl-full' || mode === 'webgl-lite') && (
          <Suspense fallback={<FlowGraphSvg title="Identity flow graph" />}>
            <FlowGraph3D lite={mode === 'webgl-lite'} live />
          </Suspense>
        )}
      </div>
      {/* Live controls + data table render BELOW the reserved box (no CLS impact). */}
      {live && (
        <div
          style={{
            display: 'flex',
            gap: 'var(--space-2)',
            alignItems: 'center',
            marginTop: 'var(--space-2)',
          }}
        >
          <button type="button" onClick={() => setPaused(!paused)} aria-pressed={paused}>
            {paused ? 'Resume live telemetry' : 'Pause live telemetry'}
          </button>
        </div>
      )}
      {live && <TelemetryTable />}
    </div>
  );
}
