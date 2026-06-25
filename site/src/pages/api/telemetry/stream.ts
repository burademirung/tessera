import type { APIRoute } from 'astro';
import { frameEvent, retryDirective, comment } from '../../../lib/sse-frame';
import { parseTelemetryEvent, type TelemetryEvent } from '../../../lib/telemetry-event';

export const prerender = false;

// Reads the telemetry Durable Object via the runtime binding `TELEMETRY_DO`.
// The DO exposes GET /subscribe?lastEventId=... returning a text/event-stream.
export const GET: APIRoute = async ({ request, locals }) => {
  const env = (locals as { runtime?: { env?: Record<string, any> } }).runtime?.env;
  const lastEventId = request.headers.get('Last-Event-ID') ?? '';
  const encoder = new TextEncoder();

  // Held so the stream's `cancel` (client disconnect) can tear down the upstream
  // DO reader — otherwise the subscription leaks for the life of the Worker.
  let upstreamReader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      controller.enqueue(encoder.encode(retryDirective(3000)));

      // Subscribe to the DO fan-out (single-writer aggregator).
      const doBinding = env?.TELEMETRY_DO;
      if (!doBinding) {
        // No binding (e.g. local static preview) — keep the stream open & idle.
        controller.enqueue(encoder.encode(comment('no telemetry binding')));
        return;
      }
      const id = doBinding.idFromName('global');
      const stub = doBinding.get(id);
      const upstream = await stub.fetch(
        `https://do/subscribe?lastEventId=${encodeURIComponent(lastEventId)}`,
        { headers: { Accept: 'text/event-stream' } },
      );

      const reader = upstream.body!.getReader();
      upstreamReader = reader;
      const pump = async (): Promise<void> => {
        try {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            return;
          }
          controller.enqueue(value);
          return pump();
        } catch {
          // Client gone / reader cancelled — stop pumping.
        }
      };
      void pump();
    },
    cancel() {
      // Client disconnected: release the upstream DO subscription.
      void upstreamReader?.cancel();
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    },
  });
};

// Exported for the route's own typing; the DO already validates on write,
// the client re-validates on read via parseTelemetryEvent.
export function reframe(json: string): string | null {
  const ev: TelemetryEvent | null = parseTelemetryEvent(json);
  return ev ? frameEvent(ev) : null;
}
