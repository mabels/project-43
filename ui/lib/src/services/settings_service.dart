import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'package:path_provider/path_provider.dart';

// ── Model ─────────────────────────────────────────────────────────────────────

class AgentSettings {
  const AgentSettings({
    this.autoApproveWhenCached = false,
    this.cacheDecryptedKey = false,
    this.cacheTimeoutMinutes = 15,
    this.notifyOnSignRequest = true,
    this.otelEndpoint = '',
    this.deviceCertTtlDays = 180,
    this.defaultKeyFingerprint,
  });

  /// When `true` and credentials for the requested key are cached, sign
  /// requests are approved automatically without showing an approval tile.
  ///
  /// When biometric approval is added, this flag will also gate whether a
  /// biometric prompt is shown (true → biometric, false → passphrase dialog).
  final bool autoApproveWhenCached;

  /// When `true`, the decrypted Ed25519 keypair is cached in memory after the
  /// first passphrase-based sign.  Subsequent auto-approve signs skip the
  /// expensive KDF (~9 s on a Mac) entirely, completing in microseconds.
  ///
  /// Security trade-off: the private key bytes live in process memory for the
  /// session.  Disable to re-run the KDF on every sign (slower but no
  /// in-memory key material).
  final bool cacheDecryptedKey;

  /// How many minutes after the last successful sign the in-memory credential
  /// caches are automatically cleared.  `null` means the caches never expire
  /// on their own (they are still cleared on screen-lock / app background).
  final int? cacheTimeoutMinutes;

  /// When `true`, a system notification is shown for every incoming sign
  /// request (pending or auto-approved).  Useful so the phone vibrates /
  /// banners appear even when the app is in the background.
  final bool notifyOnSignRequest;

  /// OpenTelemetry collector endpoint.
  ///
  /// Empty string (default) → local/no-op mode: spans are never exported and
  /// no network connection is attempted.  Set to a URL (e.g.
  /// `https://otel.adviser.com`) to export traces to the cluster collector.
  /// Changes take effect on the next app launch.
  final String otelEndpoint;

  /// How many days a device certificate is valid after being issued.
  ///
  /// Defaults to 180 days (≈ 6 months).  Set to 0 to issue certificates with
  /// no expiry (not recommended for production use).
  final int deviceCertTtlDays;

  /// Fingerprint of the key that is pre-selected in unlock / credential dialogs.
  /// `null` means use the first available key.
  final String? defaultKeyFingerprint;

  AgentSettings copyWith({
    bool? autoApproveWhenCached,
    bool? cacheDecryptedKey,
    Object? cacheTimeoutMinutes = _sentinel,
    bool? notifyOnSignRequest,
    String? otelEndpoint,
    int? deviceCertTtlDays,
    Object? defaultKeyFingerprint = _sentinel,
  }) =>
      AgentSettings(
        autoApproveWhenCached:
            autoApproveWhenCached ?? this.autoApproveWhenCached,
        cacheDecryptedKey: cacheDecryptedKey ?? this.cacheDecryptedKey,
        cacheTimeoutMinutes: cacheTimeoutMinutes == _sentinel
            ? this.cacheTimeoutMinutes
            : cacheTimeoutMinutes as int?,
        notifyOnSignRequest: notifyOnSignRequest ?? this.notifyOnSignRequest,
        otelEndpoint: otelEndpoint ?? this.otelEndpoint,
        deviceCertTtlDays: deviceCertTtlDays ?? this.deviceCertTtlDays,
        defaultKeyFingerprint: defaultKeyFingerprint == _sentinel
            ? this.defaultKeyFingerprint
            : defaultKeyFingerprint as String?,
      );

  Map<String, dynamic> toJson() => {
        'autoApproveWhenCached': autoApproveWhenCached,
        'cacheDecryptedKey': cacheDecryptedKey,
        'cacheTimeoutMinutes': cacheTimeoutMinutes,
        'notifyOnSignRequest': notifyOnSignRequest,
        'otelEndpoint': otelEndpoint,
        'deviceCertTtlDays': deviceCertTtlDays,
        'defaultKeyFingerprint': defaultKeyFingerprint,
      };

  factory AgentSettings.fromJson(Map<String, dynamic> json) => AgentSettings(
        autoApproveWhenCached:
            json['autoApproveWhenCached'] as bool? ?? false,
        cacheDecryptedKey: json['cacheDecryptedKey'] as bool? ?? false,
        cacheTimeoutMinutes: json['cacheTimeoutMinutes'] as int? ?? 15,
        notifyOnSignRequest: json['notifyOnSignRequest'] as bool? ?? true,
        otelEndpoint: json['otelEndpoint'] as String? ?? '',
        deviceCertTtlDays: json['deviceCertTtlDays'] as int? ?? 180,
        defaultKeyFingerprint:
            json['defaultKeyFingerprint'] as String?,
      );
}

// Sentinel used to distinguish "not passed" from explicit null in copyWith.
const Object _sentinel = Object();

// ── Service ───────────────────────────────────────────────────────────────────

/// Singleton that loads/persists app settings to `settings.json` in the
/// application support directory.
///
/// Call [load] once at startup (before `runApp`), then read [settings] from
/// anywhere.  Widgets that need to rebuild on changes should listen via
/// [ListenableBuilder] or [AnimatedBuilder].
class SettingsService extends ChangeNotifier {
  SettingsService._();

  static final SettingsService instance = SettingsService._();

  AgentSettings _settings = const AgentSettings();
  AgentSettings get settings => _settings;

  File? _file;
  Timer? _cacheTimer;

  Future<void> load() async {
    final dir = await getApplicationSupportDirectory();
    _file = File('${dir.path}/settings.json');
    if (_file!.existsSync()) {
      try {
        final raw = await _file!.readAsString();
        _settings = AgentSettings.fromJson(
          jsonDecode(raw) as Map<String, dynamic>,
        );
      } catch (_) {
        // Corrupt file — fall back to defaults.
      }
    }
    // Sync Rust caches with the persisted settings on startup.
    mxSetCacheKeyEnabled(enabled: _settings.cacheDecryptedKey);
    _syncCacheTimeout(_settings.cacheTimeoutMinutes);
    notifyListeners();
  }

  Future<void> save(AgentSettings updated) async {
    final prev = _settings;
    _settings = updated;
    notifyListeners();
    if (updated.cacheDecryptedKey != prev.cacheDecryptedKey) {
      mxSetCacheKeyEnabled(enabled: updated.cacheDecryptedKey);
    }
    if (updated.cacheTimeoutMinutes != prev.cacheTimeoutMinutes) {
      _syncCacheTimeout(updated.cacheTimeoutMinutes);
      // Restart the Dart-side timer so the new value takes effect immediately.
      if (_cacheTimer?.isActive == true) {
        resetCacheTimer();
      }
    }
    await _file?.writeAsString(jsonEncode(_settings.toJson()));
  }

  /// Sync the credential cache timeout to Rust.
  void _syncCacheTimeout(int? minutes) {
    final secs = (minutes != null && minutes > 0) ? minutes * 60 : 0;
    credentialCacheSetTimeout(timeoutSecs: BigInt.from(secs));
  }

  /// Call after every successful sign to (re)start the session timeout.
  ///
  /// If [AgentSettings.cacheTimeoutMinutes] is `null` no timer is started and
  /// the caches live until the screen locks or the app is killed.
  void resetCacheTimer() {
    _cacheTimer?.cancel();
    final minutes = _settings.cacheTimeoutMinutes;
    if (minutes != null && minutes > 0) {
      _cacheTimer = Timer(Duration(minutes: minutes), _onCacheExpired);
    }
  }

  /// Lock the session and purge all in-memory credentials immediately.
  ///
  /// Call on screen-lock / app-background events and from the global lock button.
  void invalidateCache() {
    _cacheTimer?.cancel();
    _cacheTimer = null;
    lockAll();
  }

  void _onCacheExpired() {
    _cacheTimer = null;
    lockAll();
  }

  @override
  void dispose() {
    _cacheTimer?.cancel();
    super.dispose();
  }
}
