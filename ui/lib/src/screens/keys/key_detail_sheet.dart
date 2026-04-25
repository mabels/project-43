import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'key_export_sheet.dart';
import 'key_widgets.dart';

// ── Key detail sheet ──────────────────────────────────────────────────────────

class KeyDetailSheet extends StatefulWidget {
  const KeyDetailSheet({super.key, required this.info, this.onDeleted});
  final KeyInfo info;
  final VoidCallback? onDeleted;

  @override
  State<KeyDetailSheet> createState() => _KeyDetailSheetState();
}

class _KeyDetailSheetState extends State<KeyDetailSheet> {
  String? _armored;
  String? _error;
  bool _deleting = false;
  bool _togglingEnabled = false;
  late bool _enabled;
  late int _selectedSubkey;

  @override
  void initState() {
    super.initState();
    _enabled = widget.info.enabled;
    _selectedSubkey = _authIndex();
    _load();
  }

  int _authIndex() {
    final idx = widget.info.subkeys.indexWhere((s) => s.role.contains('auth'));
    return idx >= 0 ? idx : 0;
  }

  Future<void> _load() async {
    try {
      final armored = await getPublicKeyArmored(
        fingerprint: widget.info.fingerprint,
      );
      if (!mounted) return;
      setState(() => _armored = armored);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    }
  }

  Future<void> _confirmDelete() async {
    final info = widget.info;
    if (info.hasSecret) {
      await _confirmDeleteWithPassphrase(info);
    } else {
      await _confirmDeletePublicOnly(info);
    }
  }

  Future<void> _confirmDeletePublicOnly(KeyInfo info) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Delete public key?'),
        content: KeySummary(info: info),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFFFF453A),
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _runDelete(info.fingerprint);
  }

  Future<void> _confirmDeleteWithPassphrase(KeyInfo info) async {
    final passphraseCtrl = TextEditingController();
    String? passphraseError;

    final passphrase = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          backgroundColor: const Color(0xFF2C2C2E),
          title: const Text('Confirm with passphrase'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              KeySummary(info: info),
              const SizedBox(height: 14),
              const Text(
                'Enter the key passphrase to confirm deletion.',
                style: TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: passphraseCtrl,
                obscureText: true,
                autofocus: true,
                decoration: InputDecoration(
                  hintText: 'Passphrase',
                  border: const OutlineInputBorder(),
                  errorText: passphraseError,
                ),
                onSubmitted: (_) async {
                  setLocal(() => passphraseError = null);
                  try {
                    await verifyKeyPassphrase(
                      fingerprint: info.fingerprint,
                      passphrase: passphraseCtrl.text,
                    );
                    if (ctx.mounted) {
                      Navigator.pop(ctx, passphraseCtrl.text);
                    }
                  } catch (_) {
                    setLocal(() => passphraseError = 'Wrong passphrase');
                  }
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                setLocal(() => passphraseError = null);
                try {
                  await verifyKeyPassphrase(
                    fingerprint: info.fingerprint,
                    passphrase: passphraseCtrl.text,
                  );
                  if (ctx.mounted) {
                    Navigator.pop(ctx, passphraseCtrl.text);
                  }
                } catch (_) {
                  setLocal(() => passphraseError = 'Wrong passphrase');
                }
              },
              child: const Text('Verify'),
            ),
          ],
        ),
      ),
    );

    if (passphrase == null || !mounted) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Delete key permanently?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            KeySummary(info: info),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFF3A1A0A),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFFFF9F0A)),
              ),
              child: const Row(
                children: [
                  Icon(
                    Icons.warning_amber_rounded,
                    size: 16,
                    color: Color(0xFFFF9F0A),
                  ),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Passphrase verified. The private key will be '
                      'deleted permanently. There is no undo.',
                      style: TextStyle(fontSize: 12, color: Color(0xFFFF9F0A)),
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
              backgroundColor: const Color(0xFFFF453A),
            ),
            child: const Text('Delete permanently'),
          ),
        ],
      ),
    );

    if (confirmed != true || !mounted) return;
    await _runDelete(info.fingerprint);
  }

  Future<void> _toggleEnabled() async {
    setState(() => _togglingEnabled = true);
    try {
      await setKeyEnabled(
        fingerprint: widget.info.fingerprint,
        enabled: !_enabled,
      );
      if (!mounted) return;
      setState(() => _enabled = !_enabled);
      widget.onDeleted?.call();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Failed to update key: $e')));
    } finally {
      if (mounted) setState(() => _togglingEnabled = false);
    }
  }

  Future<void> _runDelete(String fingerprint) async {
    setState(() => _deleting = true);
    try {
      await deleteKey(fingerprint: fingerprint);
      if (!mounted) return;
      Navigator.pop(context);
      widget.onDeleted?.call();
    } catch (e) {
      if (!mounted) return;
      setState(() => _deleting = false);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Delete failed: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.7,
      minChildSize: 0.4,
      maxChildSize: 0.95,
      builder: (_, ctrl) => Column(
        children: [
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
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 4, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    widget.info.uid,
                    style: const TextStyle(
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  widget.info.algo,
                  style: TextStyle(
                    fontSize: 12,
                    color: cs.onSurface.withValues(alpha: 0.5),
                  ),
                ),
                const SizedBox(width: 4),
                IconButton(
                  icon: const Icon(Icons.upload_outlined),
                  tooltip: 'Export key',
                  onPressed: () => showModalBottomSheet<void>(
                    context: context,
                    isScrollControlled: true,
                    backgroundColor: const Color(0xFF1C1C1E),
                    shape: const RoundedRectangleBorder(
                      borderRadius:
                          BorderRadius.vertical(top: Radius.circular(16)),
                    ),
                    builder: (_) => KeyExportSheet(info: widget.info),
                  ),
                ),
                _togglingEnabled
                    ? const Padding(
                        padding: EdgeInsets.symmetric(horizontal: 12),
                        child: SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      )
                    : IconButton(
                        icon: Icon(
                          _enabled
                              ? Icons.toggle_on_outlined
                              : Icons.toggle_off_outlined,
                          color: _enabled
                              ? const Color(0xFF30D158)
                              : const Color(0xFF8E8E93),
                        ),
                        tooltip: _enabled ? 'Disable key' : 'Enable key',
                        onPressed: _toggleEnabled,
                      ),
                _deleting
                    ? const Padding(
                        padding: EdgeInsets.all(12),
                        child: SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      )
                    : IconButton(
                        icon: const Icon(
                          Icons.delete_outline,
                          color: Color(0xFFFF453A),
                        ),
                        tooltip: 'Delete key',
                        onPressed: _confirmDelete,
                      ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: _error != null
                ? Center(
                    child: Text(
                      _error!,
                      style: const TextStyle(color: Color(0xFFFF453A)),
                    ),
                  )
                : (_armored == null
                      ? const Center(child: CircularProgressIndicator())
                      : ListView(
                          controller: ctrl,
                          padding: const EdgeInsets.all(16),
                          children: [
                            if (widget.info.subkeys.isNotEmpty) ...[
                              Padding(
                                padding: const EdgeInsets.only(bottom: 8),
                                child: Text(
                                  'SUBKEYS',
                                  style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    color: cs.onSurface.withValues(alpha: 0.5),
                                    letterSpacing: 0.5,
                                  ),
                                ),
                              ),
                              Container(
                                decoration: BoxDecoration(
                                  color: const Color(0xFF1C1C1E),
                                  borderRadius: BorderRadius.circular(10),
                                  border: Border.all(
                                    color: const Color(0xFF3A3A3C),
                                  ),
                                ),
                                child: Column(
                                  children: [
                                    for (
                                      var i = 0;
                                      i < widget.info.subkeys.length;
                                      i++
                                    ) ...[
                                      if (i > 0)
                                        const Divider(
                                          height: 1,
                                          indent: 12,
                                          endIndent: 12,
                                        ),
                                      KeySubkeyRow(
                                        subkey: widget.info.subkeys[i],
                                        selected: i == _selectedSubkey,
                                        onTap: () =>
                                            setState(() => _selectedSubkey = i),
                                      ),
                                    ],
                                  ],
                                ),
                              ),
                              const SizedBox(height: 20),
                            ],
                            if (widget.info.subkeys.isNotEmpty &&
                                widget
                                        .info
                                        .subkeys[_selectedSubkey]
                                        .opensshKey !=
                                    null) ...[
                              KeyCopyableBlock(
                                label: 'OpenSSH (authorized_keys)',
                                value: widget
                                    .info
                                    .subkeys[_selectedSubkey]
                                    .opensshKey!,
                              ),
                              const SizedBox(height: 16),
                            ],
                            KeyCopyableBlock(
                              label: 'OpenPGP Public Key',
                              value: _armored!,
                            ),
                          ],
                        )),
          ),
        ],
      ),
    );
  }
}
