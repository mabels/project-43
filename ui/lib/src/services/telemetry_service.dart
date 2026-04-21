import 'package:opentelemetry/api.dart' as otel;
import 'package:opentelemetry/sdk.dart' as otel_sdk;

import '../rust/api/simple.dart' as bridge;

extension on otel.SpanContext {
  /// Serialise as a W3C `traceparent` header: `00-<traceId>-<spanId>-<flags>`.
  ///
  /// `traceFlags` is an int in 0.18.x — just format it directly.
  String get traceparent {
    final flags = traceFlags.toRadixString(16).padLeft(2, '0');
    return '00-$traceId-$spanId-$flags';
  }
}

/// Singleton OpenTelemetry service.
///
/// ## Modes
///
/// | `endpoint` passed to [init]   | Behaviour                                         |
/// |-------------------------------|---------------------------------------------------|
/// | `null` or `""`                | **Local / no-op** — no Dart tracer is installed,  |
/// |                               | no network.  Rust falls back to fmt/RUST_LOG.     |
/// | `"https://otel.adviser.com"`  | **OTLP** — export to the cluster OTel Collector   |
/// |                               | via `CollectorExporter` (protobuf over HTTP).     |
///
/// ## Usage
/// ```dart
/// await TelemetryService.instance.init(endpoint: 'https://otel.adviser.com');
///
/// final keys = await TelemetryService.instance.wrapFfiCall(
///   spanName: 'ui.listKeys',
///   call: () => bridge.listKeys(),
/// );
/// ```
class TelemetryService {
  TelemetryService._();

  static final TelemetryService instance = TelemetryService._();

  otel.Tracer? _tracer;     // null in local/noop mode
  bool _otlpActive = false; // true only when a real exporter is running
  bool _initialised = false;

  // ── Init ────────────────────────────────────────────────────────────────────

  /// Initialise telemetry.  Safe to call once at startup.
  ///
  /// - [endpoint] `null` or `""` → local/no-op (no network, no Dart tracer).
  /// - [endpoint] non-empty URL → OTLP export via `CollectorExporter`.
  Future<void> init({String? endpoint}) async {
    if (_initialised) return;
    _initialised = true;

    final ep = (endpoint ?? '').trim();

    if (ep.isEmpty) {
      // Local mode: leave _tracer null so wrapFfiCall passes through directly.
      // Tell Rust to use fmt subscriber (RUST_LOG controls verbosity).
      try {
        await bridge.initTelemetry(endpoint: '');
      } catch (_) {}
      return;
    }

    // OTLP mode: export spans to the cluster collector.
    final exporter = otel_sdk.CollectorExporter(
      Uri.parse('$ep/v1/traces'),
    );

    final provider = otel_sdk.TracerProviderBase(
      processors: [otel_sdk.BatchSpanProcessor(exporter)],
      resource: otel_sdk.Resource(
        [otel.Attribute.fromString('service.name', 'p43-ui')],
      ),
    );

    otel.registerGlobalTracerProvider(provider);
    _tracer = otel.globalTracerProvider.getTracer('p43-ui');
    _otlpActive = true;

    // Initialise Rust side with the same endpoint.
    try {
      await bridge.initTelemetry(endpoint: ep);
    } catch (e) {
      // Telemetry is best-effort — never crash the app over it.
      // ignore: avoid_print
      print('[TelemetryService] Rust init warning: $e');
    }
  }

  /// Flush and shut down — call on app exit.
  Future<void> shutdown() async {
    if (!_otlpActive) return;
    try {
      await bridge.shutdownTelemetry();
    } catch (_) {}
  }

  // ── Span helpers ─────────────────────────────────────────────────────────────

  /// Run [call] inside a Dart span named [spanName].
  ///
  /// When in OTLP mode the span context is propagated to Rust via
  /// [bridge.setActiveTraceparent] so that Rust `#[tracing::instrument]` spans
  /// become children of this Dart span in Grafana.
  ///
  /// In local/no-op mode the FFI call runs normally with no overhead.
  Future<T> wrapFfiCall<T>({
    required String spanName,
    required Future<T> Function() call,
    List<otel.Attribute> attributes = const [],
  }) async {
    final tracer = _tracer;
    if (tracer == null) return call();

    final span = tracer.startSpan(spanName, attributes: attributes);
    final ctx = otel.contextWithSpan(otel.Context.current, span);

    // Only inject the traceparent when the span context is real — noop spans
    // have an invalid context (all-zero IDs) that would confuse the Rust side.
    final bool shouldPropagate =
        _otlpActive && span.spanContext.isValid;

    final token = otel.Context.attach(ctx);
    try {
      if (shouldPropagate) {
        await bridge.setActiveTraceparent(
          traceparent: span.spanContext.traceparent,
        );
      }
      return await call();
    } catch (e, st) {
      span
        ..setStatus(otel.StatusCode.error, e.toString())
        ..recordException(e, stackTrace: st);
      rethrow;
    } finally {
      if (shouldPropagate) await bridge.clearActiveTraceparent();
      span.end();
      otel.Context.detach(token);
    }
  }

  /// Start a Dart-only span (no FFI call involved).
  ///
  /// Returns `null` in local/noop mode — callers should handle that gracefully.
  otel.Span? startSpan(
    String name, {
    List<otel.Attribute> attributes = const [],
  }) =>
      _tracer?.startSpan(name, attributes: attributes);
}
