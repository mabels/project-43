// ── Request status ────────────────────────────────────────────────────────────

enum RequestStatus { pending, responding, done, error }

// ── Request entry ─────────────────────────────────────────────────────────────

class RequestEntry {
  const RequestEntry({
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
  });

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
  );
}
