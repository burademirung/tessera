# Premium Light 3D Reference Site: Astro + R3F on Cloudflare Pages (2024–2026)

## 1. Astro
Zero client JS by default; islands hydrate in isolation. Directives: `client:load` (immediate), `client:idle` ({timeout}), `client:visible` ({rootMargin} — for resource-intensive), `client:only="react"` (**skips SSR**, but hydrates **immediately** — not deferred), `slot="fallback"` placeholder. WebGL needs browser APIs → canvas must be client-only. **Cloudflare Pages supported** (static = no adapter, best perf; SSR via `@astrojs/cloudflare`). `<Image>` (`priority` → eager+sync+fetchpriority high; responsive `layout`). View Transitions = `<ClientRouter>`; `transition:persist` moves DOM node (incl. live canvas).
**Us:** marketing/content fully static (zero JS); graph = one `client:only="react"` island, but **gate `<Canvas>` mount behind own IntersectionObserver** (client:only is eager); `priority` poster `<Image>` in `slot="fallback"` = LCP; `<ClientRouter>` + `transition:persist` to keep WebGL/SSE across nav.

## 2. R3F performance
On-demand `frameloop="demand"` + `invalidate()` (requests one frame, not immediate). Instancing: `InstancedMesh` / drei `<Instances>`/`<Instance>` (hundreds of thousands, one draw call), `<Merged>`. Reuse geometry/material via `useMemo` (never `new` in render/useFrame). drei: `<Bvh>` (fast picking), `<PerformanceMonitor>` (onIncline/onDecline), `<AdaptiveDpr>`, `<Detailed>` LOD, `<Preload all>`. **Never setState per frame** — mutate refs in useFrame; toggle `visible` over mount/unmount; zero allocations (reuse one Vector3); use `delta`. Disposal auto on unmount; `dispose={null}` on shared geometry/material. `React.lazy` + `<Suspense>` to split Three.js out of initial bundle. `dpr={[1,2]}` + PerformanceMonitor adaptive.
**Us:** all node types + edges via `<Instances>` shared useMemo geometry/material; **edge pulse = shader uniform mutated in useFrame** (no React state); `frameloop="demand"`, invalidate only while a pulse animates then park; lazy + Preload + Bvh + PerformanceMonitor + AdaptiveDpr + dpr[1,2]; `dispose={null}`.

## 3. Live SSE → 3D without re-render
Never setState per event/frame. zustand transient (`subscribe` → ref, read in useFrame). Smooth via `MathUtils.lerp`/`maath` `damp3` (refresh-rate independent, interruptible)/react-spring imperative. SSE `EventSource` one-way, auto-reconnect (`retry`/`Last-Event-ID`); prefer over WebSocket for read-only telemetry.
**Us:** one EventSource at island level; `onmessage` writes target intensity/emissive into zustand/ref (no setState); useFrame `damp3`/`dampC` toward targets; React re-renders only on structural changes.

## 4. Accessibility (WCAG 2.2 AA)
Canvas invisible to AT (MDN). Provide fallback inside `<canvas>`, `role="img"`+aria-label, and a real data `<table>`. `prefers-reduced-motion` handled in CSS **and** JS loop (`matchMedia`). SC: 1.1.1 (text alt), 1.4.1 (not color alone), 1.4.3 (contrast ≥4.5:1 — critical on light), 2.1.1 (keyboard), 2.2.2 (pausable >5s), 2.3.1 (≤3 flashes/s).
**Us:** a **semantic SVG/HTML graph = source of truth** (keyboard, ARIA, table) that doubles as reduced-motion alt **and** low-end fallback (one artifact). Canvas `role="img"` + decorative duplicate `aria-hidden`; node types icon+label not color; visible Pause; pulse ≤3/s.

## 5. Premium light design
Typography as brand (one variable font, modular/clamp fluid, measure 45–85ch); 8pt grid + generous whitespace (reads luxurious); restrained color (near-white bg + charcoal text + **one accent** on primary/active); depth without darkness (soft-shadow elevation, light glassmorphism); motion ease-out (`cubic-bezier(0.4,0,0.2,1)`) ~150–360ms; 3D premium when purposeful/informational vs gimmicky; avoid templated look (custom tokens, crafted microstates).
**Us:** `#FAFAFB` bg, `#1A1A1F` text, one accent only on live edges + CTA so pulses read as signal; soft-shadow light panels; single variable font, 8pt scale, generous whitespace; ease-out ~240ms.

## 6. Lighthouse / CWV
LCP ≤2.5s — **canvas is NOT an LCP candidate** → poster `<img>` is LCP. INP ≤200ms (replaced FID) — break up/defer/worker Three.js init (consider `@react-three/offscreen`). CLS ≤0.1 — reserve canvas via `aspect-ratio`. With static Astro + lazy R3F + poster LCP, **≥95 achievable**; risk = Three.js bundle → code-split.

## 7. Low-end fallback ladder
`@pmndrs/detect-gpu` tiers + `hardwareConcurrency`/`deviceMemory`; clamp DPR; honor Save-Data/`prefers-reduced-data`; branch on WebGL context failure.
Tier 3 → full WebGL (dpr 1,2); Tier 2 → reduced/dpr 1.5; Tier 0–1/no-WebGL/low-mem → **2D SVG graph (SSE-fed)** = same a11y artifact; Save-Data/reduced-motion/context-loss → static poster.
**Big win: a11y fallback (SVG) = low-end fallback = reduced-motion alt — build once.**

## Loading architecture
Static Astro page (zero JS) + inline `priority` poster = LCP, canvas box reserved by `aspect-ratio`. `<IdentityGraph client:only transition:persist>` → don't mount Canvas immediately → capability gate (reduced-motion/Save-Data/detect-gpu/cores/WebGL) → decision tree to poster / SVG / reduced-WebGL / full-WebGL. Inside WebGL: Suspense→lazy(Graph), Preload/Bvh/PerformanceMonitor/AdaptiveDpr, Instances shared geometry, one EventSource→ref→useFrame damp, invalidate only while animating, always-present ARIA SVG + Pause.
