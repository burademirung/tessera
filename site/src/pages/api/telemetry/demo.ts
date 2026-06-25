import type { APIRoute } from 'astro';

export const prerender = false;

// Triggers the edge engine's demo flow, which emits a cascade of TelemetryEvents
// onto the Queue → DO → SSE. Uses the EDGE service binding when present.
export const POST: APIRoute = async () => {
  // Astro v6 removed `locals.runtime.env`; bindings come from the worker module.
  // Imported lazily so unit/static contexts without the cloudflare runtime keep
  // working — a missing EDGE binding just no-ops into the 202 below.
  let env: Record<string, any> | undefined;
  try {
    ({ env } = (await import('cloudflare:workers')) as { env: Record<string, any> });
  } catch {
    env = undefined;
  }
  const edge = env?.EDGE;
  try {
    if (edge?.fetch) {
      await edge.fetch('https://edge/demo/run', { method: 'POST' });
    } else if (env?.EDGE_URL) {
      await fetch(`${env.EDGE_URL}/demo/run`, { method: 'POST' });
    }
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: String(err) }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ ok: true }), {
    status: 202,
    headers: { 'Content-Type': 'application/json' },
  });
};
