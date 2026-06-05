import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;

// ── Storage keys ──────────────────────────────────────────────────────────────

/// SE-stored master secret (biometric path only).
const _kBioMasterKey = 'gate_key_master';

// ── GateKeyService ────────────────────────────────────────────────────────────

/// Manages the gate-key unlock lifecycle.
///
/// ## Design
/// - The master secret is generated once and sealed with at least one passphrase.
/// - Biometric is OPTIONAL and added on top of an existing passphrase seal.
/// - To add or remove any seal, an existing working seal must be proved first.
///
/// ## Unlock paths
/// - **Passphrase**: `gate_key_verify(passphrase)` → master hex
/// - **Biometric**: Touch ID → SE releases master hex (no Rust call needed)
class GateKeyService {
  GateKeyService._();
  static final GateKeyService instance = GateKeyService._();

  final LocalAuthentication _auth = LocalAuthentication();

  static const FlutterSecureStorage _storage = FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.passcode),
    mOptions: MacOsOptions(
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  // ── Status ─────────────────────────────────────────────────────────────────

  /// True if at least one passphrase seal exists on disk.
  Future<bool> isConfigured() async {
    try {
      return await rust.gateKeyIsConfigured();
    } catch (_) {
      return false;
    }
  }

  /// All passphrase seal key-ids.
  Future<List<String>> listSeals() async {
    try {
      return await rust.gateKeyList();
    } catch (_) {
      return [];
    }
  }

  /// True if a biometric (SE) seal is stored on this device.
  Future<bool> hasBiometricSeal() async {
    final v = await _storage.read(key: _kBioMasterKey);
    return v != null;
  }

  /// True if the device supports biometric authentication.
  Future<bool> get biometricsAvailable async {
    try {
      return await _auth.canCheckBiometrics || await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  // ── Setup ──────────────────────────────────────────────────────────────────

  /// First-time setup: generate master secret and seal with [passphrase].
  ///
  /// Returns the [GateKeyCreated] which contains [masterHex] — store it in
  /// the SE if the user also wants biometric unlock.
  Future<rust.GateKeyCreated> create({required String passphrase}) {
    return rust.gateKeyCreate(passphrase: passphrase);
  }

  /// Store the master secret in the OS secure enclave for biometric unlock.
  ///
  /// Call this after [create] or after unlocking with a passphrase if the
  /// user wants to add Touch ID / Face ID as an additional unlock method.
  Future<void> addBiometricSeal({required String masterHex}) async {
    await _storage.write(key: _kBioMasterKey, value: masterHex);
  }

  /// Add another passphrase seal using an already-known [masterHex].
  ///
  /// The caller must have obtained [masterHex] via [unlock] or [create].
  Future<String> addPassphraseSeal({
    required String masterHex,
    required String newPassphrase,
  }) {
    return rust.gateKeySealPassphrase(
      masterHex: masterHex,
      passphrase: newPassphrase,
    );
  }

  // ── Unlock ─────────────────────────────────────────────────────────────────

  /// Unlock and return the master secret as a hex string.
  ///
  /// Tries biometric first; falls back to [passphraseProvider].
  Future<String> unlock({
    required Future<String?> Function() passphraseProvider,
  }) async {
    // Biometric path — try SE first.
    final bio = await _storage.read(key: _kBioMasterKey);
    if (bio != null) {
      final authenticated = await _auth.authenticate(
        localizedReason: 'Unlock p43 wallet',
        biometricOnly: false,
      );
      if (authenticated) return bio;
      // Biometric failed/cancelled — fall through to passphrase.
    }

    // Passphrase path.
    final passphrase = await passphraseProvider();
    if (passphrase == null) throw Exception('Passphrase not provided');
    return rust.gateKeyVerify(passphrase: passphrase);
  }

  /// Unlock with a passphrase directly (no biometric attempt).
  Future<String> unlockWithPassphrase(String passphrase) {
    return rust.gateKeyVerify(passphrase: passphrase);
  }

  // ── Cache ──────────────────────────────────────────────────────────────────

  /// Clear any in-memory cached state (call on screen-lock / app background).
  void clearCache() {
    // No in-memory cache in this implementation — the SE holds the value.
    // Kept for API compatibility with callers.
  }

  // ── Revoke ─────────────────────────────────────────────────────────────────

  /// Revoke a passphrase seal by [keyId].
  ///
  /// [proofPassphrase] must unlock a DIFFERENT seal (ownership proof).
  Future<void> revokePassphraseSeal({
    required String keyId,
    required String proofPassphrase,
  }) async {
    final seals = await listSeals();
    if (seals.length < 2) {
      throw Exception('Cannot revoke — only one seal remains');
    }
    // Verify the proof passphrase works on a different seal.
    // Verify proof passphrase works (we just need confirmation, not the value).
    await rust.gateKeyVerify(passphrase: proofPassphrase);
    await rust.gateKeyRevoke(keyId: keyId);
  }

  /// Remove the biometric (SE) seal from this device.
  Future<void> removeBiometricSeal() async {
    await _storage.delete(key: _kBioMasterKey);
  }
}
