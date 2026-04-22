//! OpenTelemetry initialisation and W3C TraceContext propagation helpers.
//!
//! # Modes
//!
//! | `endpoint` passed to [`init`]  | Behaviour                                          |
//! |--------------------------------|----------------------------------------------------|
//! | `""` (empty) or not called     | **Local mode** — plain `tracing_subscriber::fmt`   |
//! |                                | subscriber.  Spans honour `RUST_LOG`; zero network |
//! |                                | overhead, no queue, no retries.                    |
//! | `"https://otel.adviser.com"`   | **OTLP mode** — batch exporter to the collector.   |
//! |                                | If the endpoint is temporarily unreachable the SDK |
//! |                                | retries silently and drops spans after the retry   |
//! |                                | budget is exhausted — the app is never blocked.    |
//!
//! # Feature gate
//! Everything in this module is compiled only when `--features telemetry` is
//! active.  The public surface compiles to no-ops otherwise, so callers never
//! need `#[cfg(feature = "telemetry")]` guards.

#[cfg(feature = "telemetry")]
mod inner {
    use anyhow::Result;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{
        runtime,
        trace::{RandomIdGenerator, Sampler},
        Resource,
    };
    use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
    use std::cell::RefCell;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    // ── Thread-local traceparent ──────────────────────────────────────────────

    thread_local! {
        static ACTIVE_TRACEPARENT: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub fn set_active_traceparent(traceparent: String) {
        ACTIVE_TRACEPARENT.with(|cell| *cell.borrow_mut() = Some(traceparent));
    }

    pub fn clear_active_traceparent() {
        ACTIVE_TRACEPARENT.with(|cell| *cell.borrow_mut() = None);
    }

    pub fn take_active_traceparent() -> Option<String> {
        ACTIVE_TRACEPARENT.with(|cell| cell.borrow_mut().take())
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise the tracing subscriber.
    ///
    /// Pass an empty string (or call the no-arg wrapper) for **local mode**:
    /// spans are logged to stderr according to `RUST_LOG` with zero network
    /// overhead.  Pass a non-empty OTLP HTTP endpoint for export mode.
    pub fn init(endpoint: &str) -> Result<()> {
        if endpoint.is_empty() {
            init_local()
        } else {
            init_otlp(endpoint)
        }
    }

    /// Local mode: plain fmt subscriber, no OTel layer, no network.
    fn init_local() -> Result<()> {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()
            .map_err(|e| anyhow::anyhow!("tracing subscriber install failed: {e}"))
    }

    /// OTLP mode: batch-export spans to an HTTP collector endpoint.
    fn init_otlp(endpoint: &str) -> Result<()> {
        let export_url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
        eprintln!("[p43::telemetry] OTLP mode — exporting to {export_url}");

        let resource = Resource::new(vec![opentelemetry::KeyValue::new(SERVICE_NAME, "p43")]);

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(export_url)
            .build()
            .map_err(|e| {
                eprintln!("[p43::telemetry] exporter build failed: {e}");
                e
            })?;
        eprintln!("[p43::telemetry] exporter built OK");

        let provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_batch_exporter(exporter, runtime::Tokio)
            .with_sampler(Sampler::AlwaysOn)
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(provider.clone());
        eprintln!("[p43::telemetry] global tracer provider set");

        // OTel layer has NO EnvFilter — all spans reach the collector regardless
        // of RUST_LOG.  A separate fmt layer is gated by RUST_LOG for local
        // debugging (defaults to off when the env var is not set).
        let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("p43"));

        let fmt_layer = tracing_subscriber::fmt::layer().with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        );

        let result = tracing_subscriber::registry()
            .with(otel_layer)
            .with(fmt_layer)
            .try_init()
            .map_err(|e| anyhow::anyhow!("tracing subscriber install failed: {e}"));
        eprintln!(
            "[p43::telemetry] subscriber init: {:?}",
            result.as_ref().map(|_| "ok").map_err(|e| e.to_string())
        );
        result
    }

    pub fn shutdown() {
        opentelemetry::global::shutdown_tracer_provider();
    }
}

// ── Public API (no-ops when feature is off) ───────────────────────────────────

/// Initialise tracing.
///
/// - `endpoint = ""` → local fmt subscriber, zero network overhead.
/// - `endpoint = "https://…"` → OTLP export to that collector.
///
/// No-op when compiled without `--features telemetry`.
#[allow(unused_variables)]
pub fn init(endpoint: &str) -> anyhow::Result<()> {
    #[cfg(feature = "telemetry")]
    return inner::init(endpoint);
    #[cfg(not(feature = "telemetry"))]
    Ok(())
}

/// Convenience alias — initialise in local mode with zero config.
pub fn init_local() -> anyhow::Result<()> {
    init("")
}

/// Flush pending spans and shut down the OTel provider.
/// No-op without `telemetry` feature or when in local mode.
pub fn shutdown() {
    #[cfg(feature = "telemetry")]
    inner::shutdown();
}

/// Set the W3C `traceparent` for the current thread.
/// No-op without `telemetry` feature.
#[allow(unused_variables)]
pub fn set_active_traceparent(traceparent: String) {
    #[cfg(feature = "telemetry")]
    inner::set_active_traceparent(traceparent);
}

/// Clear the stored traceparent.  No-op without `telemetry` feature.
pub fn clear_active_traceparent() {
    #[cfg(feature = "telemetry")]
    inner::clear_active_traceparent();
}

/// Take (remove and return) the stored traceparent.
pub fn take_active_traceparent() -> Option<String> {
    #[cfg(feature = "telemetry")]
    return inner::take_active_traceparent();
    #[cfg(not(feature = "telemetry"))]
    None
}
