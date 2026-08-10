// ── Request status ────────────────────────────────────────────────────────────

enum RequestStatus { pending, responding, done, error }

// ── Request entry ─────────────────────────────────────────────────────────────

class RequestEntry {
  RequestEntry({
    required this.type,
    required this.requestId,
    required this.description,
    required this.fingerprint,
    required this.status,
    this.keyName,
    this.keyAlgo,
    this.cardIdents = const [],
    this.errorMessage,
    this.sourceLabel = '',
    this.sourceDeviceId = '',
    this.meta = const {},
    this.certMeta = const {},
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  final String type;
  final String requestId;
  final String? description;
  final String? fingerprint;
  final String? keyName;
  final String? keyAlgo;
  final List<String> cardIdents;
  final RequestStatus status;
  final String? errorMessage;

  /// Label from the sender's bus certificate (empty for unauthenticated requests).
  final String sourceLabel;

  /// Stable device identifier from the sender's bus certificate.
  final String sourceDeviceId;

  /// Live device snapshot collected at request time on the agent side.
  final Map<String, String> meta;

  /// Registration-time snapshot from the device's cert (empty for uncertified devices).
  final Map<String, String> certMeta;

  /// Wall-clock time when this entry was created.
  final DateTime timestamp;

  /// Convenience: hostname from meta, or empty string.
  String get hostname => meta['hostname'] ?? '';

  /// Convenience: first IP address found in meta, or empty string.
  String get primaryIp {
    for (final entry in meta.entries) {
      if (entry.key.startsWith('net.') && entry.key.endsWith('.ip')) {
        return entry.value;
      }
    }
    return '';
  }

  RequestEntry copyWith({
    RequestStatus? status,
    String? keyName,
    String? keyAlgo,
    List<String>? cardIdents,
    String? errorMessage,
    String? sourceLabel,
    String? sourceDeviceId,
  }) => RequestEntry(
    type: type,
    requestId: requestId,
    description: description,
    fingerprint: fingerprint,
    status: status ?? this.status,
    keyName: keyName ?? this.keyName,
    keyAlgo: keyAlgo ?? this.keyAlgo,
    cardIdents: cardIdents ?? this.cardIdents,
    errorMessage: errorMessage ?? this.errorMessage,
    sourceLabel: sourceLabel ?? this.sourceLabel,
    sourceDeviceId: sourceDeviceId ?? this.sourceDeviceId,
    meta: meta,
    certMeta: certMeta,
    timestamp: timestamp,
  );
}
