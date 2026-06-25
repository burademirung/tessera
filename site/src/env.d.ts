/// <reference types="astro/client" />

// The Cloudflare adapter exposes worker bindings via this virtual module at
// build/runtime (Astro v6 replaced `Astro.locals.runtime.env`). Declared loosely
// here so `astro check` resolves it; the real module supplies the typed bindings.
declare module 'cloudflare:workers' {
  export const env: Record<string, unknown>;
}
