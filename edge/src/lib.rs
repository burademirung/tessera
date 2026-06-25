pub mod jwt;
pub mod util;

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use worker::*;

    #[event(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    #[event(fetch)]
    async fn fetch(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
        Response::ok("lifecycle-edge: ok")
    }
}
