import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

// ── Biometric entry (metadata only, no secret) ────────────────────────────────

/// Metadata for a single saved biometric entry.  The actual credential value
/// is never exposed without a biometric prompt.
class BiometricEntry {
  const BiometricEntry({required this.fingerprint, required this.isCard});

  /// OpenPGP hex fingerprint of the key this entry belongs to.
  final String fingerprint;

  /// True when the saved credential is a YubiKey PIN; false for a passphrase.
  final bool isCard;
}

// ── Saved credential ──────────────────────────────────────────────────────────

/// A credential retrieved from secure storage after successful biometric auth.
class SavedCredential {
  const SavedCredential({
    required this.isCard,
    required this.fingerprint,
    required this.credential,
  });

  /// True when the credential is a YubiKey PIN; false for a soft-key passphrase.
  final bool isCard;

  /// OpenPGP hex fingerprint of the key this credential belongs to.
  final String fingerprint;

  /// The actual PIN or passphrase string.
  final String credential;
}

// ── BiometricService ──────────────────────────────────────────────────────────

/// Singleton that wraps [LocalAuthentication] + [FlutterSecureStorage].
///
/// Credentials are stored under two keys per fingerprint:
///   `biometric_<fp>_credential`  — the PIN or passphrase
///   `biometric_<fp>_type`        — "card" | "soft"
///
/// Writing requires no authentication; reading is gated by [authenticate].
/// Items are accessible only when the device is unlocked
/// ([KeychainAccessibility.whenPasscodeSetThisDeviceOnly] on Apple,
/// EncryptedSharedPreferences on Android).
class BiometricService {
  BiometricService._();
  static final BiometricService instance = BiometricService._();

  final LocalAuthentication _auth = LocalAuthentication();

  // iOS:   passcode              = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
  // macOS: unlocked_this_device  = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  //   macOS runs without app-sandbox so items go into the default user keychain;
  //   no keychain-access-groups entitlement is required.
  static const FlutterSecureStorage _storage = FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.passcode),
    mOptions: MacOsOptions(
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
    aOptions: AndroidOptions(),
  );

  // ── Key helpers ─────────────────────────────────────────────────────────────

  static String _credKey(String fp) => 'biometric_${fp}_credential';
  static String _typeKey(String fp) => 'biometric_${fp}_type';

  // ── Availability ─────────────────────────────────────────────────────────────

  /// Returns true when the device supports biometrics or device PIN/passcode.
  ///
  /// This covers Face ID, Touch ID, fingerprint, and device PIN fallback.
  Future<bool> isAvailable() async {
    try {
      return await _auth.canCheckBiometrics || await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  /// Returns a human-readable label for the available authenticator,
  /// e.g. "Face ID", "Touch ID", or "device PIN".
  Future<String> availableMethodLabel() async {
    try {
      final types = await _auth.getAvailableBiometrics();
      if (types.contains(BiometricType.face)) return 'Face ID';
      if (types.contains(BiometricType.fingerprint)) return 'Touch ID';
      if (types.contains(BiometricType.iris)) return 'Iris';
    } catch (_) {}
    return 'device PIN';
  }

  // ── Storage ──────────────────────────────────────────────────────────────────

  /// Returns true when a credential is saved for [fingerprint].
  Future<bool> hasSaved(String fingerprint) async {
    try {
      final v = await _storage.read(key: _credKey(fingerprint));
      return v != null;
    } catch (_) {
      return false;
    }
  }

  /// Persist [credential] for [fingerprint].  No auth required on write.
  Future<void> save({
    required String fingerprint,
    required bool isCard,
    required String credential,
  }) async {
    await _storage.write(key: _credKey(fingerprint), value: credential);
    await _storage.write(
      key: _typeKey(fingerprint),
      value: isCard ? 'card' : 'soft',
    );
  }

  /// Delete the saved credential for [fingerprint].
  Future<void> delete(String fingerprint) async {
    await _storage.delete(key: _credKey(fingerprint));
    await _storage.delete(key: _typeKey(fingerprint));
  }

  /// Return all fingerprints that currently have saved credentials.
  Future<List<String>> savedFingerprints() async {
    try {
      final all = await _storage.readAll();
      return all.keys
          .where((k) => k.startsWith('biometric_') && k.endsWith('_credential'))
          .map(
            (k) => k.substring(
              'biometric_'.length,
              k.length - '_credential'.length,
            ),
          )
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Return all saved entries as (fingerprint, isCard) pairs — no credential
  /// values, no authentication required.  Safe to call from a settings screen.
  Future<List<BiometricEntry>> savedEntries() async {
    try {
      final all = await _storage.readAll();
      return all.keys
          .where((k) => k.startsWith('biometric_') && k.endsWith('_credential'))
          .map((k) {
            final fp = k.substring(
              'biometric_'.length,
              k.length - '_credential'.length,
            );
            final type = all['biometric_${fp}_type'];
            return BiometricEntry(fingerprint: fp, isCard: type == 'card');
          })
          .toList();
    } catch (_) {
      return [];
    }
  }

  // ── Authentication ────────────────────────────────────────────────────────────

  /// Prompt the user (Face ID / Touch ID / device PIN) and on success return
  /// the saved credential for [fingerprint].
  ///
  /// Returns null if:
  ///   - no credential is saved for this fingerprint
  ///   - the auth prompt is cancelled or fails
  ///   - biometrics are unavailable
  Future<SavedCredential?> authenticate(
    String fingerprint, {
    String reason = 'Unlock p43 session',
  }) async {
    try {
      final ok = await _auth.authenticate(
        localizedReason: reason,
        biometricOnly: false,
      );
      if (!ok) return null;
      final cred = await _storage.read(key: _credKey(fingerprint));
      if (cred == null) return null;
      final type = await _storage.read(key: _typeKey(fingerprint));
      return SavedCredential(
        isCard: type == 'card',
        fingerprint: fingerprint,
        credential: cred,
      );
    } catch (_) {
      return null;
    }
  }
}
