import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;
import '../../services/biometric_service.dart';
import '../../services/settings_service.dart';

// ── Authority status / init tile ──────────────────────────────────────────────

class AuthorityStatusTile extends StatefulWidget {
  const AuthorityStatusTile({super.key});

  @override
  State<AuthorityStatusTile> createState() => _AuthorityStatusTileState();
}

class _AuthorityStatusTileState extends State<AuthorityStatusTile> {
  bool? _hasAuthority;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    try {
      final has = await rust.busHasAuthority();
      if (mounted) setState(() => _hasAuthority = has);
    } catch (_) {
      if (mounted) setState(() => _hasAuthority = false);
    }
  }

  Future<void> _init() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await rust.busInitAuthority();
      if (mounted) {
        setState(() {
          _hasAuthority = true;
          _busy = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _busy = false;
        });
      }
    }
  }

  void _showInitConfirm() {
    showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'Initialise Bus Authority',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        content: const Text(
          'A new Ed25519 + X25519 authority keypair will be generated and '
          'encrypted to all currently imported keys.\n\n'
          'Any device that already trusts the old authority will need to be '
          're-registered.',
          style: TextStyle(fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFF0A84FF),
            ),
            child: const Text('Initialise'),
          ),
        ],
      ),
    ).then((confirmed) {
      if (confirmed == true) _init();
    });
  }

  @override
  Widget build(BuildContext context) {
    final initialised = _hasAuthority ?? false;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ListTile(
          tileColor: const Color(0xFF2C2C2E),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 16,
            vertical: 4,
          ),
          leading: Icon(
            initialised ? Icons.verified_user_outlined : Icons.shield_outlined,
            color: initialised
                ? const Color(0xFF30D158)
                : const Color(0xFF8E8E93),
            size: 20,
          ),
          title: Text(
            initialised ? 'Authority initialised' : 'Authority not initialised',
            style: const TextStyle(fontSize: 15),
          ),
          subtitle: Text(
            initialised
                ? 'Ed25519 keypair sealed to your imported keys.'
                : 'Tap to generate the authority keypair.',
            style: TextStyle(
              fontSize: 12,
              color: initialised
                  ? const Color(0xFF30D158)
                  : const Color(0xFF8E8E93),
            ),
          ),
          trailing: _busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : (!initialised
                    ? FilledButton(
                        onPressed: _showInitConfirm,
                        style: FilledButton.styleFrom(
                          backgroundColor: const Color(0xFF0A84FF),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 6,
                          ),
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        ),
                        child: const Text(
                          'Init',
                          style: TextStyle(fontSize: 13),
                        ),
                      )
                    : null),
          onTap: !initialised && !_busy ? _showInitConfirm : null,
        ),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: Text(
              _error!,
              style: const TextStyle(fontSize: 11, color: Color(0xFFFF453A)),
            ),
          ),
      ],
    );
  }
}

// ── Authority reseal tile ─────────────────────────────────────────────────────

class AuthorityResealTile extends StatefulWidget {
  const AuthorityResealTile({super.key});

  @override
  State<AuthorityResealTile> createState() => _AuthorityResealTileState();
}

class _AuthorityResealTileState extends State<AuthorityResealTile> {
  int _unsealedCount = 0;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      final missing = await rust.busAuthorityKeysNotSealed();
      if (mounted) setState(() => _unsealedCount = missing.length);
    } catch (_) {
      // Non-fatal — just don't show the badge.
    }
  }

  void _openSheet() {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => _AuthorityResealSheet(onChanged: _refresh),
    );
  }

  @override
  Widget build(BuildContext context) {
    final hasUnsealed = _unsealedCount > 0;
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: Icon(
        Icons.lock_reset_outlined,
        color: hasUnsealed ? const Color(0xFFFF9F0A) : const Color(0xFF0A84FF),
        size: 20,
      ),
      title: const Text('Manage sealed keys', style: TextStyle(fontSize: 15)),
      subtitle: hasUnsealed
          ? Text(
              '$_unsealedCount key${_unsealedCount == 1 ? '' : 's'} not yet sealed.',
              style: const TextStyle(fontSize: 12, color: Color(0xFFFF9F0A)),
            )
          : const Text(
              'Add, seal, or revoke keys from the authority.',
              style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
            ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (hasUnsealed)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: const Color(0xFFFF9F0A),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                '$_unsealedCount',
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: Colors.black,
                ),
              ),
            ),
          const SizedBox(width: 4),
          const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
        ],
      ),
      onTap: _openSheet,
    );
  }
}

// ── Reseal sheet ──────────────────────────────────────────────────────────────

class _AuthorityResealSheet extends StatefulWidget {
  const _AuthorityResealSheet({required this.onChanged});
  final VoidCallback onChanged;

  @override
  State<_AuthorityResealSheet> createState() => _AuthorityResealSheetState();
}

class _AuthorityResealSheetState extends State<_AuthorityResealSheet> {
  List<rust.KeySealStatus>? _statuses;
  String? _loadError;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final s = await rust.busAuthorityKeySealStatus();
      if (mounted) {
        setState(() {
          _statuses = s;
          _loadError = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() => _loadError = e.toString());
    }
  }

  /// Perform a reseal operation, then reload.
  /// Throws on failure so the calling dialog can show the error inline.
  Future<void> _reseal({
    required String action, // 'seal_all' | 'exclude:<fp>'
    required bool useCard,
    required String? unlockFingerprint,
    required String? pin,
    required String? passphrase,
  }) async {
    if (action == 'seal_all') {
      await rust.busResealAuthority(
        useCard: useCard,
        unlockFingerprint: unlockFingerprint,
        pin: pin,
        passphrase: passphrase,
      );
    } else if (action.startsWith('exclude:')) {
      final fp = action.substring('exclude:'.length);
      await rust.busResealAuthorityExcluding(
        excludeFingerprint: fp,
        useCard: useCard,
        unlockFingerprint: unlockFingerprint,
        pin: pin,
        passphrase: passphrase,
      );
    }
    await _load();
    widget.onChanged();
  }

  void _showUnlockDialog({
    required String title,
    required String description,
    required Color confirmColor,
    required String confirmLabel,
    required String action,
    required List<rust.KeySealStatus> sealedKeys,
    bool isDestructive = false,
  }) {
    showDialog<void>(
      context: context,
      builder: (ctx) => _UnlockDialog(
        title: title,
        description: description,
        confirmColor: confirmColor,
        confirmLabel: confirmLabel,
        sealedKeys: sealedKeys,
        isDestructive: isDestructive,
        onConfirm: (useCard, fp, pin, pass) => _reseal(
          action: action,
          useCard: useCard,
          unlockFingerprint: fp,
          pin: pin,
          passphrase: pass,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      minChildSize: 0.4,
      maxChildSize: 0.92,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Color(0xFF1C1C1E),
          borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
        ),
        child: Column(
          children: [
            // Handle
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: Container(
                width: 36,
                height: 4,
                decoration: BoxDecoration(
                  color: cs.onSurface.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            // Header
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: Row(
                children: [
                  const Icon(
                    Icons.lock_reset_outlined,
                    size: 20,
                    color: Color(0xFF0A84FF),
                  ),
                  const SizedBox(width: 10),
                  const Text(
                    'Manage Sealed Keys',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                  ),
                  const Spacer(),
                  if (_statuses == null && _loadError == null)
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                ],
              ),
            ),
            const Divider(height: 1),
            // Body
            Expanded(child: _buildBody(ctrl, cs)),
          ],
        ),
      ),
    );
  }

  Widget _buildBody(ScrollController ctrl, ColorScheme cs) {
    if (_loadError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            _loadError!,
            style: const TextStyle(color: Color(0xFFFF453A), fontSize: 13),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    if (_statuses == null) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_statuses!.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'No authority initialised yet.\nUse "Initialise" first.',
            style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    final sealedKeys = _statuses!
        .where((s) => s.isSealed)
        .toList(growable: false);

    return ListView(
      controller: ctrl,
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
      children: [
        const _SheetSectionLabel('KEYS'),
        const SizedBox(height: 8),
        ..._statuses!.map(
          (s) => _KeySealRow(
            status: s,
            canRemove: sealedKeys.length > 1,
            onSeal: sealedKeys.isEmpty
                ? null
                : () => _showUnlockDialog(
                    title: 'Seal to all keys',
                    description:
                        'Unlock the authority, then re-seal it to '
                        'include all currently imported keys.',
                    confirmColor: const Color(0xFF0A84FF),
                    confirmLabel: 'Seal all',
                    action: 'seal_all',
                    sealedKeys: sealedKeys,
                  ),
            onRemove: () => _showUnlockDialog(
              title: 'Remove key from authority',
              description:
                  'This key will no longer be able to unlock the '
                  'authority. Use this if the key was compromised.\n\n'
                  'Unlock with a different key to confirm.',
              confirmColor: const Color(0xFFFF453A),
              confirmLabel: 'Remove',
              action: 'exclude:${s.fingerprint}',
              sealedKeys: sealedKeys
                  .where((k) => k.fingerprint != s.fingerprint)
                  .toList(growable: false),
              isDestructive: true,
            ),
          ),
        ),
        if (_statuses!.any((s) => !s.isSealed) && sealedKeys.isNotEmpty) ...[
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: () => _showUnlockDialog(
              title: 'Seal to all keys',
              description:
                  'Unlock the authority, then re-seal it to include '
                  'all currently imported keys.',
              confirmColor: const Color(0xFF0A84FF),
              confirmLabel: 'Seal all',
              action: 'seal_all',
              sealedKeys: sealedKeys,
            ),
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFF0A84FF),
              minimumSize: const Size.fromHeight(44),
            ),
            icon: const Icon(Icons.lock_outlined, size: 16),
            label: const Text('Seal all unsealed keys'),
          ),
        ],
      ],
    );
  }
}

// ── Key seal row ──────────────────────────────────────────────────────────────

class _KeySealRow extends StatelessWidget {
  const _KeySealRow({
    required this.status,
    required this.canRemove,
    required this.onSeal,
    required this.onRemove,
  });

  final rust.KeySealStatus status;
  final bool canRemove;
  final VoidCallback? onSeal;
  final VoidCallback onRemove;

  @override
  Widget build(BuildContext context) {
    final sealed = status.isSealed;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF2C2C2E),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: sealed
              ? const Color(0xFF3A3A3C)
              : const Color(0xFFFF9F0A).withValues(alpha: 0.6),
        ),
      ),
      child: Row(
        children: [
          Icon(
            sealed ? Icons.lock_outlined : Icons.lock_open_outlined,
            size: 18,
            color: sealed ? const Color(0xFF30D158) : const Color(0xFFFF9F0A),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  status.uid,
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  status.fingerprint.length > 16
                      ? '${status.fingerprint.substring(0, 16)}…'
                      : status.fingerprint,
                  style: const TextStyle(
                    fontSize: 10,
                    fontFamily: 'monospace',
                    color: Color(0xFF8E8E93),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          if (!sealed)
            TextButton(
              onPressed: onSeal,
              style: TextButton.styleFrom(
                foregroundColor: const Color(0xFF0A84FF),
                visualDensity: VisualDensity.compact,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
              ),
              child: const Text('Seal', style: TextStyle(fontSize: 13)),
            )
          else if (canRemove)
            TextButton(
              onPressed: onRemove,
              style: TextButton.styleFrom(
                foregroundColor: const Color(0xFFFF453A),
                visualDensity: VisualDensity.compact,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
              ),
              child: const Text('Remove', style: TextStyle(fontSize: 13)),
            )
          else
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 10),
              child: Text(
                'last key',
                style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
              ),
            ),
        ],
      ),
    );
  }
}

// ── Sheet section label ───────────────────────────────────────────────────────

class _SheetSectionLabel extends StatelessWidget {
  const _SheetSectionLabel(this.label);
  final String label;

  @override
  Widget build(BuildContext context) {
    return Text(
      label,
      style: const TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w600,
        color: Color(0xFF8E8E93),
        letterSpacing: 0.5,
      ),
    );
  }
}

// ── Unlock dialog ─────────────────────────────────────────────────────────────

class _UnlockDialog extends StatefulWidget {
  const _UnlockDialog({
    required this.title,
    required this.description,
    required this.confirmColor,
    required this.confirmLabel,
    required this.sealedKeys,
    required this.onConfirm,
    this.isDestructive = false,
    this.onSaveCredential,
  });

  final String title;
  final String description;
  final Color confirmColor;
  final String confirmLabel;
  final List<rust.KeySealStatus> sealedKeys;
  final bool isDestructive;
  final Future<void> Function(
    bool useCard,
    String? fingerprint,
    String? pin,
    String? passphrase,
  )
  onConfirm;

  /// When non-null, a "Save with biometrics" checkbox is shown.
  /// Called after a successful [onConfirm] with the selected key's details
  /// and the credential the user entered, so the caller can persist it.
  final Future<void> Function(
    bool isCard,
    String fingerprint,
    String credential,
  )?
  onSaveCredential;

  @override
  State<_UnlockDialog> createState() => _UnlockDialogState();
}

class _UnlockDialogState extends State<_UnlockDialog> {
  String? _selectedFp;
  final _credCtrl = TextEditingController();
  bool _obscure = true;
  Timer? _obscureTimer;
  bool _busy = false;
  String? _error;

  // ── Biometrics save toggle ─────────────────────────────────────────────────
  bool _biometricsAvailable = false;
  bool _saveBiometrics = false;
  String _biometricLabel = 'biometrics';

  @override
  void initState() {
    super.initState();
    if (widget.sealedKeys.isNotEmpty) {
      // Pre-select the user's default key when it is available in this set.
      final dfp = SettingsService.instance.settings.defaultKeyFingerprint;
      final hasDefault =
          dfp != null && widget.sealedKeys.any((k) => k.fingerprint == dfp);
      _selectedFp = hasDefault ? dfp : widget.sealedKeys.first.fingerprint;
    }
    if (widget.onSaveCredential != null) _checkBiometrics();
  }

  Future<void> _checkBiometrics() async {
    final available = await BiometricService.instance.isAvailable();
    final label = await BiometricService.instance.availableMethodLabel();
    if (mounted) {
      setState(() {
        _biometricsAvailable = available;
        _biometricLabel = label;
      });
    }
  }

  @override
  void dispose() {
    _obscureTimer?.cancel();
    _credCtrl.dispose();
    super.dispose();
  }

  /// Toggle visibility.  Revealing starts a 10 s auto-hide timer; hiding or
  /// any action (submit, key switch) cancels it and restores obscured state.
  void _toggleObscure() {
    _obscureTimer?.cancel();
    if (_obscure) {
      setState(() => _obscure = false);
      _obscureTimer = Timer(const Duration(seconds: 10), () {
        if (mounted) setState(() => _obscure = true);
      });
    } else {
      _obscureTimer = null;
      setState(() => _obscure = true);
    }
  }

  void _resetObscure() {
    _obscureTimer?.cancel();
    _obscureTimer = null;
    if (mounted && !_obscure) setState(() => _obscure = true);
  }

  rust.KeySealStatus? get _selectedKey => _selectedFp == null
      ? null
      : widget.sealedKeys
            .where((k) => k.fingerprint == _selectedFp)
            .firstOrNull;

  bool get _isCard => _selectedKey?.hasCard ?? false;

  @override
  Widget build(BuildContext context) {
    final credLabel = _isCard ? 'YubiKey PIN' : 'Passphrase';
    return AlertDialog(
      backgroundColor: const Color(0xFF2C2C2E),
      title: Row(
        children: [
          Expanded(
            child: Text(
              widget.title,
              style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
            ),
          ),
          if (_busy) ...[
            const SizedBox(width: 10),
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          ],
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.description,
              style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            ),
            const SizedBox(height: 16),
            const Text(
              'Unlock with',
              style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
            ),
            const SizedBox(height: 4),
            Container(
              decoration: BoxDecoration(
                color: const Color(0xFF1C1C1E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF3A3A3C)),
              ),
              child: Column(
                children: [
                  for (var i = 0; i < widget.sealedKeys.length; i++) ...[
                    if (i > 0)
                      const Divider(height: 1, indent: 12, endIndent: 12),
                    _KeyPickerRow(
                      status: widget.sealedKeys[i],
                      selected: _selectedFp == widget.sealedKeys[i].fingerprint,
                      enabled: !_busy,
                      onTap: _busy
                          ? null
                          : () {
                              _obscureTimer?.cancel();
                              _obscureTimer = null;
                              setState(() {
                                _selectedFp = widget.sealedKeys[i].fingerprint;
                                _credCtrl.clear();
                                _error = null;
                                _obscure = true;
                              });
                            },
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 12),
            Text(
              credLabel,
              style: const TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
            ),
            const SizedBox(height: 4),
            TextField(
              key: ValueKey(_isCard),
              controller: _credCtrl,
              obscureText: _obscure,
              autofocus: true,
              enabled: !_busy,
              style: const TextStyle(fontSize: 14),
              keyboardType: _isCard ? TextInputType.number : TextInputType.text,
              decoration: InputDecoration(
                hintText: '••••••',
                hintStyle: const TextStyle(color: Color(0xFF8E8E93)),
                filled: true,
                fillColor: const Color(0xFF1C1C1E),
                border: const OutlineInputBorder(borderSide: BorderSide.none),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 8,
                ),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscure
                        ? Icons.visibility_outlined
                        : Icons.visibility_off_outlined,
                    size: 18,
                    color: const Color(0xFF8E8E93),
                  ),
                  onPressed: _busy ? null : _toggleObscure,
                ),
              ),
              onSubmitted: _busy
                  ? null
                  : (_) {
                      _resetObscure();
                      _submit();
                    },
            ),
            // ── Save with biometrics ────────────────────────────────────
            if (widget.onSaveCredential != null && _biometricsAvailable) ...[
              const SizedBox(height: 10),
              GestureDetector(
                onTap: _busy
                    ? null
                    : () => setState(() => _saveBiometrics = !_saveBiometrics),
                child: Row(
                  children: [
                    SizedBox(
                      width: 20,
                      height: 20,
                      child: Checkbox(
                        value: _saveBiometrics,
                        onChanged: _busy
                            ? null
                            : (v) =>
                                  setState(() => _saveBiometrics = v ?? false),
                        materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        visualDensity: VisualDensity.compact,
                        activeColor: const Color(0xFF0A84FF),
                        side: const BorderSide(color: Color(0xFF8E8E93)),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'Save with $_biometricLabel',
                      style: const TextStyle(
                        fontSize: 13,
                        color: Color(0xFFE5E5EA),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            // ── Inline error ────────────────────────────────────────────
            if (_error != null) ...[
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF3A0A0A),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFFF453A)),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.error_outline,
                      size: 14,
                      color: Color(0xFFFF453A),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _error!,
                        style: const TextStyle(
                          fontSize: 12,
                          color: Color(0xFFFF453A),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _busy ? null : _submit,
          style: FilledButton.styleFrom(backgroundColor: widget.confirmColor),
          child: Text(widget.confirmLabel),
        ),
      ],
    );
  }

  Future<void> _submit() async {
    _resetObscure();
    final cred = _credCtrl.text.isEmpty ? null : _credCtrl.text;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.onConfirm(
        _isCard,
        _selectedFp, // always pass fingerprint — Rust needs it to look up card AID idents for the credential cache
        _isCard ? cred : null,
        _isCard ? null : cred,
      );
      // Persist credential in secure storage if the user opted in.
      if (_saveBiometrics &&
          widget.onSaveCredential != null &&
          _selectedFp != null &&
          cred != null) {
        await widget.onSaveCredential!(_isCard, _selectedFp!, cred);
      }
      if (mounted) Navigator.pop(context);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = e.toString();
        });
      }
    }
  }
}

// ── Key picker row (inside unlock dialog) ─────────────────────────────────────

class _KeyPickerRow extends StatelessWidget {
  const _KeyPickerRow({
    required this.status,
    required this.selected,
    required this.enabled,
    required this.onTap,
  });

  final rust.KeySealStatus status;
  final bool selected;
  final bool enabled;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: enabled ? onTap : null,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        color: Colors.transparent,
        child: Row(
          children: [
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_off,
              size: 16,
              color: selected
                  ? const Color(0xFF0A84FF)
                  : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                status.uid,
                style: TextStyle(
                  fontSize: 13,
                  color: selected ? null : const Color(0xFF8E8E93),
                  fontWeight: selected ? FontWeight.w500 : FontWeight.normal,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Authority export tile ─────────────────────────────────────────────────────

class AuthorityExportTile extends StatefulWidget {
  const AuthorityExportTile({super.key});

  @override
  State<AuthorityExportTile> createState() => _AuthorityExportTileState();
}

class _AuthorityExportTileState extends State<AuthorityExportTile> {
  bool _busy = false;

  /// Serialise bundle: [4-byte BE len][keyEnc][4-byte BE len][pubCbor].
  List<int> _buildBundleBytes(rust.AuthorityKeyExport bundle) {
    final keyEnc = bundle.keyEnc;
    final pubCbor = bundle.pubCbor;
    return [
      (keyEnc.length >> 24) & 0xFF,
      (keyEnc.length >> 16) & 0xFF,
      (keyEnc.length >> 8) & 0xFF,
      keyEnc.length & 0xFF,
      ...keyEnc,
      (pubCbor.length >> 24) & 0xFF,
      (pubCbor.length >> 16) & 0xFF,
      (pubCbor.length >> 8) & 0xFF,
      pubCbor.length & 0xFF,
      ...pubCbor,
    ];
  }

  Future<void> _export() async {
    setState(() => _busy = true);
    late rust.AuthorityKeyExport bundle;
    try {
      bundle = await rust.busExportAuthority();
    } catch (e) {
      if (mounted) {
        setState(() => _busy = false);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Export failed: $e')));
      }
      return;
    }
    if (!mounted) return;
    setState(() => _busy = false);

    final rawBytes = _buildBundleBytes(bundle);
    final b64 = base64.encode(rawBytes);

    showDialog<void>(
      context: context,
      builder: (ctx) =>
          _AuthorityExportDialog(bundleB64: b64, rawBytes: rawBytes),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: const Icon(
        Icons.upload_file_outlined,
        color: Color(0xFF0A84FF),
        size: 20,
      ),
      title: const Text('Export authority key', style: TextStyle(fontSize: 15)),
      subtitle: const Text(
        'Encrypted key bundle — QR, copy, or save to file.',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: _busy
          ? const SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
      onTap: _busy ? null : _export,
    );
  }
}

// ── Authority export dialog ───────────────────────────────────────────────────

/// Max base64 length we'll attempt to render as a QR (alphanumeric capacity
/// of version 40 with M error-correction is 3391 chars; leave headroom).
const _kQrMaxLength = 2800;

class _AuthorityExportDialog extends StatelessWidget {
  const _AuthorityExportDialog({
    required this.bundleB64,
    required this.rawBytes,
  });

  final String bundleB64;
  final List<int> rawBytes;

  bool get _qrFits => bundleB64.length <= _kQrMaxLength;

  void _copy(BuildContext context) {
    Clipboard.setData(ClipboardData(text: bundleB64));
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('Bundle copied to clipboard')));
  }

  Future<void> _saveFile(BuildContext context) async {
    final savePath = await FilePicker.saveFile(
      dialogTitle: 'Save authority key bundle',
      fileName: 'p43-authority.bundle',
    );
    if (savePath == null) return;
    final file = File(savePath);
    await file.writeAsBytes(rawBytes, flush: true);
    if (context.mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Saved to $savePath')));
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF2C2C2E),
      title: const Text(
        'Authority Key Bundle',
        style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
      content: SizedBox(
        width: 300,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── QR or size warning ──────────────────────────────────
              if (_qrFits) ...[
                Center(
                  child: Container(
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    padding: const EdgeInsets.all(12),
                    child: QrImageView(
                      data: bundleB64,
                      version: QrVersions.auto,
                      size: 220,
                      errorCorrectionLevel: QrErrorCorrectLevel.M,
                    ),
                  ),
                ),
                const SizedBox(height: 10),
                const Center(
                  child: Text(
                    'Scan with p43 on another device to import the key.',
                    style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
                    textAlign: TextAlign.center,
                  ),
                ),
              ] else ...[
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF3A3A0A),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFFFF9F0A)),
                  ),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.info_outline,
                        size: 16,
                        color: Color(0xFFFF9F0A),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Bundle is ${bundleB64.length} chars — too large for QR. '
                          'Copy the text or save to file.',
                          style: const TextStyle(
                            fontSize: 12,
                            color: Color(0xFFFF9F0A),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 14),

              // ── Base64 text block ───────────────────────────────────
              const Text(
                'BASE64 BUNDLE',
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.w600,
                  color: Color(0xFF8E8E93),
                  letterSpacing: 0.5,
                ),
              ),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF1C1C1E),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF3A3A3C)),
                ),
                child: SelectableText(
                  bundleB64,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 9,
                    color: Color(0xFFAAAAAA),
                    height: 1.5,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton.icon(
          onPressed: () => _saveFile(context),
          icon: const Icon(Icons.save_alt, size: 16),
          label: const Text('Save file'),
        ),
        TextButton.icon(
          onPressed: () => _copy(context),
          icon: const Icon(Icons.copy, size: 16),
          label: const Text('Copy'),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

// ── Authority import tile ─────────────────────────────────────────────────────

class AuthorityImportTile extends StatelessWidget {
  const AuthorityImportTile({super.key});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: const Icon(
        Icons.download_for_offline_outlined,
        color: Color(0xFF0A84FF),
        size: 20,
      ),
      title: const Text('Import authority key', style: TextStyle(fontSize: 15)),
      subtitle: const Text(
        'Restore from a bundle — paste base64 or open file.',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: const Icon(
        Icons.chevron_right,
        size: 18,
        color: Color(0xFF8E8E93),
      ),
      onTap: () => showDialog<void>(
        context: context,
        builder: (ctx) => const _AuthorityImportDialog(),
      ),
    );
  }
}

// ── Authority import dialog ───────────────────────────────────────────────────

enum _ImportSource { paste, file }

class _AuthorityImportDialog extends StatefulWidget {
  const _AuthorityImportDialog();

  @override
  State<_AuthorityImportDialog> createState() => _AuthorityImportDialogState();
}

class _AuthorityImportDialogState extends State<_AuthorityImportDialog> {
  _ImportSource _source = _ImportSource.paste;

  final _pasteCtrl = TextEditingController();
  bool _pasteHasText = false;

  String? _fileName; // shown when a file has been picked
  Uint8List? _fileBytes;

  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _pasteCtrl.addListener(() {
      final has = _pasteCtrl.text.trim().isNotEmpty;
      if (has != _pasteHasText) setState(() => _pasteHasText = has);
    });
  }

  @override
  void dispose() {
    _pasteCtrl.dispose();
    super.dispose();
  }

  bool get _canImport =>
      _source == _ImportSource.paste ? _pasteHasText : _fileBytes != null;

  // ── Bundle parsing ──────────────────────────────────────────────────────

  /// Returns `(keyEnc, pubCbor)` or throws a descriptive string on bad data.
  (Uint8List, Uint8List) _parseBundle(Uint8List bytes) {
    if (bytes.length < 8) throw 'Bundle too short — invalid data.';

    final keyEncLen =
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    if (bytes.length < 4 + keyEncLen + 4) {
      throw 'Bundle truncated at keyEnc (need ${4 + keyEncLen + 4} bytes, '
          'got ${bytes.length}).';
    }
    final keyEnc = bytes.sublist(4, 4 + keyEncLen);

    final off = 4 + keyEncLen;
    final pubCborLen =
        (bytes[off] << 24) |
        (bytes[off + 1] << 16) |
        (bytes[off + 2] << 8) |
        bytes[off + 3];
    if (bytes.length < off + 4 + pubCborLen) {
      throw 'Bundle truncated at pubCbor (need ${off + 4 + pubCborLen} bytes, '
          'got ${bytes.length}).';
    }
    final pubCbor = bytes.sublist(off + 4, off + 4 + pubCborLen);

    return (keyEnc, pubCbor);
  }

  // ── File picker ─────────────────────────────────────────────────────────

  Future<void> _pickFile() async {
    final result = await FilePicker.pickFiles(
      type: FileType.any,
      dialogTitle: 'Open authority key bundle',
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    final picked = result.files.first;
    final bytes =
        picked.bytes ??
        (picked.path != null ? await File(picked.path!).readAsBytes() : null);
    if (bytes == null) {
      setState(() => _error = 'Could not read file.');
      return;
    }
    setState(() {
      _fileName = picked.name;
      _fileBytes = bytes;
      _error = null;
    });
  }

  // ── Import ──────────────────────────────────────────────────────────────

  Future<void> _doImport() async {
    setState(() {
      _busy = true;
      _error = null;
    });

    // Resolve raw bytes from active source.
    Uint8List raw;
    try {
      if (_source == _ImportSource.paste) {
        final text = _pasteCtrl.text.trim();
        raw = Uint8List.fromList(base64.decode(text));
      } else {
        raw = _fileBytes!;
      }
    } catch (e) {
      setState(() {
        _busy = false;
        _error = 'Could not decode bundle: $e';
      });
      return;
    }

    // Parse bundle.
    Uint8List keyEnc, pubCbor;
    try {
      (keyEnc, pubCbor) = _parseBundle(raw);
    } catch (e) {
      setState(() {
        _busy = false;
        _error = e.toString();
      });
      return;
    }

    // Validate that at least one local key can unlock this bundle.
    List<String> unlockableBy;
    try {
      unlockableBy = await rust.busAuthorityCheckImportable(keyEnc: keyEnc);
    } catch (e) {
      setState(() {
        _busy = false;
        _error = e.toString();
      });
      return;
    }
    setState(() => _busy = false);

    // Confirm before overwriting — show which keys can unlock.
    final confirmed = await showDialog<bool>(
      // ignore: use_build_context_synchronously
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'Import authority key?',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This will overwrite the current authority files. '
              'Make sure you have a backup first.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFF0A1F0A),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30D158)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(
                    children: [
                      Icon(
                        Icons.lock_open_outlined,
                        size: 14,
                        color: Color(0xFF30D158),
                      ),
                      SizedBox(width: 6),
                      Text(
                        'Unlockable by:',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: Color(0xFF30D158),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  ...unlockableBy.map(
                    (uid) => Padding(
                      padding: const EdgeInsets.only(top: 2),
                      child: Text(
                        uid,
                        style: const TextStyle(
                          fontSize: 12,
                          color: Color(0xFFE5E5EA),
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFFFF9F0A),
            ),
            child: const Text('Import'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() => _busy = true);
    try {
      await rust.busImportAuthority(keyEnc: keyEnc, pubCbor: pubCbor);
      if (mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('Authority key imported')));
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = e.toString();
        });
      }
    }
  }

  // ── Build ───────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF2C2C2E),
      title: const Text(
        'Import Authority Key',
        style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
      ),
      content: SizedBox(
        width: 320,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── Source toggle ───────────────────────────────────────
              Row(
                children: [
                  _ImportSourceToggle(
                    label: 'Paste',
                    icon: Icons.content_paste,
                    selected: _source == _ImportSource.paste,
                    onTap: () => setState(() {
                      _source = _ImportSource.paste;
                      _error = null;
                    }),
                  ),
                  const SizedBox(width: 8),
                  _ImportSourceToggle(
                    label: 'File',
                    icon: Icons.folder_open,
                    selected: _source == _ImportSource.file,
                    onTap: () => setState(() {
                      _source = _ImportSource.file;
                      _error = null;
                    }),
                  ),
                ],
              ),
              const SizedBox(height: 14),

              // ── Paste input ─────────────────────────────────────────
              if (_source == _ImportSource.paste) ...[
                TextField(
                  controller: _pasteCtrl,
                  maxLines: 6,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: Color(0xFFE5E5EA),
                    height: 1.5,
                  ),
                  decoration: InputDecoration(
                    hintText: 'Paste base64 bundle here…',
                    hintStyle: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: Color(0xFF48484A),
                    ),
                    filled: true,
                    fillColor: const Color(0xFF1C1C1E),
                    border: OutlineInputBorder(
                      borderSide: BorderSide(
                        color: _pasteHasText
                            ? const Color(0xFF30D158)
                            : const Color(0xFF3A3A3C),
                      ),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderSide: BorderSide(
                        color: _pasteHasText
                            ? const Color(0xFF30D158)
                            : const Color(0xFF3A3A3C),
                      ),
                    ),
                    focusedBorder: const OutlineInputBorder(
                      borderSide: BorderSide(
                        color: Color(0xFF0A84FF),
                        width: 1.5,
                      ),
                    ),
                    contentPadding: const EdgeInsets.all(12),
                    suffixIcon: _pasteHasText
                        ? IconButton(
                            icon: const Icon(
                              Icons.clear,
                              size: 16,
                              color: Color(0xFF8E8E93),
                            ),
                            onPressed: () => _pasteCtrl.clear(),
                          )
                        : null,
                  ),
                ),
              ],

              // ── File picker ─────────────────────────────────────────
              if (_source == _ImportSource.file) ...[
                GestureDetector(
                  onTap: _pickFile,
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 12,
                    ),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1C1C1E),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: _fileBytes != null
                            ? const Color(0xFF30D158)
                            : const Color(0xFF3A3A3C),
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          _fileBytes != null
                              ? Icons.check_circle_outline
                              : Icons.folder_open,
                          size: 18,
                          color: _fileBytes != null
                              ? const Color(0xFF30D158)
                              : const Color(0xFF8E8E93),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            _fileName ?? 'Browse for .bundle file…',
                            style: TextStyle(
                              fontSize: 13,
                              color: _fileBytes != null
                                  ? null
                                  : const Color(0xFF8E8E93),
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const Text(
                          'Browse',
                          style: TextStyle(
                            fontSize: 12,
                            color: Color(0xFF0A84FF),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],

              // ── Error ───────────────────────────────────────────────
              if (_error != null) ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF3A0A0A),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFFFF453A)),
                  ),
                  child: Text(
                    _error!,
                    style: const TextStyle(
                      fontSize: 12,
                      color: Color(0xFFFF453A),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        FilledButton.icon(
          onPressed: (_busy || !_canImport) ? null : _doImport,
          style: FilledButton.styleFrom(
            backgroundColor: const Color(0xFF0A84FF),
            disabledBackgroundColor: const Color(0xFF3A3A3C),
          ),
          icon: _busy
              ? const SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Colors.white,
                  ),
                )
              : const Icon(Icons.download, size: 16),
          label: const Text('Import'),
        ),
      ],
    );
  }
}

class _ImportSourceToggle extends StatelessWidget {
  const _ImportSourceToggle({
    required this.label,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        decoration: BoxDecoration(
          color: selected
              ? const Color(0xFF0A84FF).withValues(alpha: 0.15)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: selected ? const Color(0xFF0A84FF) : const Color(0xFF3A3A3C),
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 14,
              color: selected
                  ? const Color(0xFF0A84FF)
                  : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 5),
            Text(
              label,
              style: TextStyle(
                fontSize: 13,
                fontWeight: selected ? FontWeight.w600 : FontWeight.normal,
                color: selected
                    ? const Color(0xFF0A84FF)
                    : const Color(0xFF8E8E93),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Authority QR tile ─────────────────────────────────────────────────────────

class AuthorityQrTile extends StatelessWidget {
  const AuthorityQrTile({super.key});

  void _show(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) => const _AuthorityQrDialog(),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: const Icon(Icons.qr_code_2, color: Color(0xFF0A84FF), size: 20),
      title: const Text(
        'Export authority pubkey',
        style: TextStyle(fontSize: 15),
      ),
      subtitle: const Text(
        'Show QR code for devices to scan and trust this authority.',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: const Icon(
        Icons.chevron_right,
        size: 18,
        color: Color(0xFF8E8E93),
      ),
      onTap: () => _show(context),
    );
  }
}

class _AuthorityQrDialog extends StatefulWidget {
  const _AuthorityQrDialog();

  @override
  State<_AuthorityQrDialog> createState() => _AuthorityQrDialogState();
}

class _AuthorityQrDialogState extends State<_AuthorityQrDialog> {
  String? _qrData;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final data = await rust.busAuthorityPubQrData();
      if (mounted) setState(() => _qrData = data);
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  void _copy() {
    if (_qrData == null) return;
    Clipboard.setData(ClipboardData(text: _qrData!));
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('Copied to clipboard')));
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF2C2C2E),
      title: const Text(
        'Authority Public Key',
        style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
      content: SizedBox(
        width: 280,
        child: _error != null
            ? Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(
                    Icons.warning_amber_rounded,
                    color: Color(0xFFFF453A),
                    size: 36,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    _error!,
                    style: const TextStyle(
                      fontSize: 12,
                      color: Color(0xFF8E8E93),
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              )
            : _qrData == null
            ? const Center(child: CircularProgressIndicator())
            : Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    padding: const EdgeInsets.all(12),
                    child: QrImageView(
                      data: _qrData!,
                      version: QrVersions.auto,
                      size: 220,
                      errorCorrectionLevel: QrErrorCorrectLevel.M,
                    ),
                  ),
                  const SizedBox(height: 14),
                  const Text(
                    'Scan with p43 on a desktop device to\n'
                    'trust this authority for bus messages.',
                    style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
      ),
      actions: [
        if (_qrData != null)
          TextButton.icon(
            onPressed: _copy,
            icon: const Icon(Icons.copy, size: 16),
            label: const Text('Copy'),
          ),
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

// ── Session unlock tile ───────────────────────────────────────────────────────

/// Shows current session lock state and lets the user unlock / lock the
/// authority key held in memory.  The key is required to decrypt incoming
/// `BusSecure` messages and to seal outgoing responses.
///
/// To programmatically open the unlock dialog from outside this widget, obtain
/// a [GlobalKey<SessionUnlockTileState>], pass it as the widget key, and call
/// [SessionUnlockTileState.openUnlockDialog] when needed.
class SessionUnlockTile extends StatefulWidget {
  const SessionUnlockTile({
    super.key,
    this.onUnlocked,
    this.externalLockStream,
  });

  /// Called after the user successfully unlocks the session.  Use this to
  /// refresh any parent-level lock indicators (e.g. the root shell's AppBar).
  final VoidCallback? onUnlocked;

  /// Fires whenever the session is locked externally (AppBar lock button or
  /// screen-lock lifecycle event).  The tile immediately reflects the locked
  /// state so it stays in sync with the root shell's lock icon.
  final Stream<void>? externalLockStream;

  @override
  State<SessionUnlockTile> createState() => SessionUnlockTileState();
}

class SessionUnlockTileState extends State<SessionUnlockTile> {
  bool _unlocked = false;
  bool _busy = false;
  StreamSubscription<void>? _lockSub;

  @override
  void initState() {
    super.initState();
    _refresh();
    _subscribeLockStream();
  }

  @override
  void didUpdateWidget(SessionUnlockTile oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.externalLockStream != oldWidget.externalLockStream) {
      _lockSub?.cancel();
      _subscribeLockStream();
    }
  }

  void _subscribeLockStream() {
    _lockSub = widget.externalLockStream?.listen((_) {
      if (mounted) setState(() => _unlocked = false);
    });
  }

  /// Open the unlock dialog.
  ///
  /// Always re-queries Rust for the current lock state first so the tile stays
  /// correct even when it was locked externally (AppBar button / screen lock)
  /// without this widget's knowledge.
  Future<void> openUnlockDialog() async {
    if (!mounted) return;
    await _refresh();
    if (!mounted || _unlocked) return;
    _showUnlockDialog();
  }

  @override
  void dispose() {
    _lockSub?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final v = await rust.busIsSessionUnlocked();
      if (mounted) setState(() => _unlocked = v);
    } catch (_) {}
  }

  Future<void> _lock() async {
    setState(() => _busy = true);
    try {
      // lockAll clears authority session + credential cache + signing-key cache.
      rust.lockAll();
      SettingsService.instance.invalidateCache();
      if (mounted) {
        setState(() {
          _unlocked = false;
          _busy = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _busy = false);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Lock failed: $e')));
      }
    }
  }

  Future<void> _showUnlockDialog() async {
    List<rust.KeySealStatus> sealedKeys;
    try {
      sealedKeys = await rust.busAuthorityKeySealStatus();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to load keys: $e')));
      }
      return;
    }
    if (!mounted) return;
    if (sealedKeys.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'No sealed keys found — initialise the authority first.',
          ),
        ),
      );
      return;
    }

    // ── Biometric fast-path ────────────────────────────────────────────────
    // Check if any sealed key has a saved credential.  If so, try biometric
    // auth first.  On success we unlock without showing the PIN dialog at all.
    if (await BiometricService.instance.isAvailable()) {
      final saved = await BiometricService.instance.savedFingerprints();
      final match = sealedKeys.firstWhere(
        (k) => saved.contains(k.fingerprint),
        orElse: () => sealedKeys.first, // sentinel — checked below
      );
      if (saved.contains(match.fingerprint)) {
        final credential = await BiometricService.instance.authenticate(
          match.fingerprint,
          reason: 'Unlock p43 session',
        );
        if (credential != null && mounted) {
          try {
            await rust.busUnlockSession(
              useCard: credential.isCard,
              fingerprint: credential.fingerprint,
              pin: credential.isCard ? credential.credential : null,
              passphrase: credential.isCard ? null : credential.credential,
            );
            SettingsService.instance.resetCacheTimer();
            if (mounted) setState(() => _unlocked = true);
            widget.onUnlocked?.call();
            return; // done — no dialog needed
          } catch (_) {
            // Biometric unlock failed (e.g. wrong cached PIN after card re-PIN).
            // Fall through to the manual PIN dialog.
          }
        }
        // Auth cancelled or failed — fall through to manual dialog below.
        if (!mounted) return;
      }
    }

    // ── Manual PIN / passphrase dialog ─────────────────────────────────────
    // mounted is verified at every await point above.
    await showDialog<void>(
      context: context, // ignore: use_build_context_synchronously
      builder: (ctx) => _UnlockDialog(
        title: 'Unlock Session',
        description:
            'Decrypt the authority key into memory so incoming encrypted '
            'messages can be processed. The session is cleared on screen lock.',
        confirmColor: const Color(0xFF0A84FF),
        confirmLabel: 'Unlock',
        sealedKeys: sealedKeys,
        onConfirm: (useCard, fp, pin, passphrase) async {
          await rust.busUnlockSession(
            useCard: useCard,
            fingerprint: fp,
            pin: pin,
            passphrase: passphrase,
          );
          // busUnlockSession already primes the credential cache.
          // Start the session timeout so auto-approve works immediately.
          SettingsService.instance.resetCacheTimer();
          if (mounted) setState(() => _unlocked = true);
          widget.onUnlocked?.call();
        },
        onSaveCredential: (isCard, fp, credential) => BiometricService.instance
            .save(fingerprint: fp, isCard: isCard, credential: credential),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: Icon(
        _unlocked ? Icons.lock_open_outlined : Icons.lock_outlined,
        color: _unlocked ? const Color(0xFF30D158) : const Color(0xFF8E8E93),
        size: 20,
      ),
      title: Text(
        _unlocked ? 'Session unlocked' : 'Session locked',
        style: const TextStyle(fontSize: 15),
      ),
      subtitle: Text(
        _unlocked
            ? 'Encrypted messages are being processed.'
            : 'Tap to unlock — required for encrypted SSH requests.',
        style: const TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: _busy
          ? const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : _unlocked
          ? TextButton(
              onPressed: _lock,
              child: const Text(
                'Lock',
                style: TextStyle(color: Color(0xFFFF453A)),
              ),
            )
          : const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
      onTap: _unlocked ? null : _showUnlockDialog,
    );
  }
}
