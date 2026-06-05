import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;

enum AddCredentialKind { yubikey, sshKey }

/// Bottom sheet for adding a new wallet credential.
/// Shows two options: YubiKey reference or SSH key file.
/// [initialKind] skips the picker and opens that sub-sheet directly.
class AddCredentialSheet extends StatelessWidget {
  final String walletMasterHex;
  final VoidCallback onAdded;
  /// Parent context (from the route/scaffold above this sheet) used for
  /// showing sub-sheets after an async file-picker gap, when this sheet's
  /// own context may no longer be mounted.
  final BuildContext parentContext;
  final AddCredentialKind? initialKind;

  const AddCredentialSheet({
    super.key,
    required this.walletMasterHex,
    required this.parentContext,
    required this.onAdded,
    this.initialKind,
  });

  /// Called directly from the Keys page action buttons — skips the picker
  /// sheet and opens the SSH file picker immediately.
  static Future<void> pickAndImportSshKey({
    required BuildContext parentContext,
    required String walletMasterHex,
    required VoidCallback onAdded,
  }) async {
    final result = await FilePicker.pickFiles(
      type: FileType.any,
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty) return;
    final path = result.files.single.path;
    if (path == null) return;
    if (!parentContext.mounted) return;
    showModalBottomSheet(
      context: parentContext,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _AddSshKeySheet(
        walletMasterHex: walletMasterHex,
        filePath: path,
        onAdded: onAdded,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // When opened directly from an action button, skip the picker.
    if (initialKind == AddCredentialKind.yubikey) {
      return _AddYubikeySheet(
        walletMasterHex: walletMasterHex,
        onAdded: onAdded,
      );
    }

    return SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 8),
          Container(
            width: 36,
            height: 4,
            decoration: BoxDecoration(
              color: const Color(0xFF8E8E93),
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 16),
          const Text('Add credential',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          ListTile(
            leading: const Icon(Icons.credit_card_outlined,
                color: Color(0xFF0A84FF)),
            title: const Text('YubiKey reference'),
            subtitle: const Text(
                'Store card fingerprint + PIN from a connected YubiKey',
                style:
                    TextStyle(fontSize: 12, color: Color(0xFF8E8E93))),
            onTap: () {
              Navigator.pop(context);
              showModalBottomSheet(
                context: context,
                isScrollControlled: true,
                backgroundColor: const Color(0xFF1C1C1E),
                shape: const RoundedRectangleBorder(
                  borderRadius:
                      BorderRadius.vertical(top: Radius.circular(16)),
                ),
                builder: (_) => _AddYubikeySheet(
                  walletMasterHex: walletMasterHex,
                  onAdded: onAdded,
                ),
              );
            },
          ),
          ListTile(
            leading:
                const Icon(Icons.key_outlined, color: Color(0xFF0A84FF)),
            title: const Text('SSH private key'),
            subtitle: const Text('Import an OpenSSH private key file',
                style:
                    TextStyle(fontSize: 12, color: Color(0xFF8E8E93))),
            onTap: () {
              // Don't pop yet — we need this context alive while the file
              // picker is open.  _importSshKey pops the sheet itself after
              // a file is chosen, then uses parentContext for the next sheet.
              _importSshKey(context);
            },
          ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  Future<void> _importSshKey(BuildContext sheetContext) async {
    final result = await FilePicker.pickFiles(
      type: FileType.any,
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty) return;
    final path = result.files.single.path;
    if (path == null) return;

    // Close this sheet first (sheetContext may still be mounted here because
    // we didn't pop it before the await).
    if (sheetContext.mounted) Navigator.pop(sheetContext);

    // Use parentContext (from the route above) to show the SSH sheet — it
    // remains valid across the async gap.
    if (!parentContext.mounted) return;
    showModalBottomSheet(
      context: parentContext,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _AddSshKeySheet(
        walletMasterHex: walletMasterHex,
        filePath: path,
        onAdded: onAdded,
      ),
    );
  }
}

// ── YubiKey import sheet ──────────────────────────────────────────────────────

class _AddYubikeySheet extends StatefulWidget {
  final String walletMasterHex;
  final VoidCallback onAdded;
  const _AddYubikeySheet(
      {required this.walletMasterHex, required this.onAdded});

  @override
  State<_AddYubikeySheet> createState() => _AddYubikeySheetState();
}

class _AddYubikeySheetState extends State<_AddYubikeySheet> {
  final _labelCtrl = TextEditingController();
  final _pinCtrl = TextEditingController();
  List<rust.ConnectedCardInfo> _cards = [];
  rust.ConnectedCardInfo? _selected;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadCards();
  }

  Future<void> _loadCards() async {
    try {
      final cards = await rust.listConnectedCards();
      if (mounted) {
        setState(() {
          _cards = cards;
          _selected = cards.isNotEmpty ? cards.first : null;
          if (_selected != null && _labelCtrl.text.isEmpty) {
            _labelCtrl.text = _selected!.cardholderName.isNotEmpty
                ? _selected!.cardholderName
                : _selected!.ident;
          }
        });
      }
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  Future<void> _save() async {
    if (_selected == null) return;
    setState(() {_busy = true; _error = null;});
    try {
      await rust.walletAddYubikeyRef(
        masterHex: widget.walletMasterHex,
        label: _labelCtrl.text.trim().isEmpty
            ? _selected!.ident
            : _labelCtrl.text.trim(),
        pin: _pinCtrl.text,
        cardIdent: _selected!.ident,
      );
      widget.onAdded();
      if (mounted) Navigator.pop(context);
    } catch (e) {
      if (mounted) setState(() {_busy = false; _error = e.toString();});
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom),
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Add YubiKey reference',
                style: TextStyle(
                    fontSize: 17, fontWeight: FontWeight.w600)),
            const SizedBox(height: 16),
            if (_cards.isEmpty)
              const Text('No card connected',
                  style: TextStyle(color: Color(0xFF8E8E93)))
            else if (_cards.length == 1)
              Text('Card: ${_selected!.ident}',
                  style:
                      const TextStyle(fontSize: 13, color: Color(0xFF8E8E93)))
            else
              DropdownButton<rust.ConnectedCardInfo>(
                value: _selected,
                items: _cards
                    .map((c) => DropdownMenuItem(
                        value: c,
                        child: Text(c.ident)))
                    .toList(),
                onChanged: (v) => setState(() => _selected = v),
              ),
            const SizedBox(height: 12),
            TextField(
              controller: _labelCtrl,
              decoration: const InputDecoration(
                  labelText: 'Label', filled: true,
                  fillColor: Color(0xFF2C2C2E)),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _pinCtrl,
              obscureText: true,
              decoration: const InputDecoration(
                  labelText: 'Card PIN', filled: true,
                  fillColor: Color(0xFF2C2C2E)),
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!,
                  style: const TextStyle(
                      color: Color(0xFFFF453A), fontSize: 12)),
            ],
            const SizedBox(height: 16),
            FilledButton(
              onPressed: (_busy || _selected == null) ? null : _save,
              child: _busy
                  ? const SizedBox(height: 18, width: 18,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white))
                  : const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }
}

// ── SSH key import sheet ──────────────────────────────────────────────────────

class _AddSshKeySheet extends StatefulWidget {
  final String walletMasterHex;
  final String filePath;
  final VoidCallback onAdded;
  const _AddSshKeySheet(
      {required this.walletMasterHex,
      required this.filePath,
      required this.onAdded});

  @override
  State<_AddSshKeySheet> createState() => _AddSshKeySheetState();
}

class _AddSshKeySheetState extends State<_AddSshKeySheet> {
  final _passphraseCtrl = TextEditingController();
  bool _needsPassphrase = false;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _checkKey();
  }

  Future<void> _checkKey() async {
    // Peek at the file to see if it looks encrypted.
    try {
      final content = await File(widget.filePath).readAsString();
      setState(() =>
          _needsPassphrase = content.contains('ENCRYPTED'));
    } catch (_) {}
  }

  Future<void> _save() async {
    setState(() {_busy = true; _error = null;});
    try {
      final bytes = await File(widget.filePath).readAsBytes();
      await rust.walletAddSshKey(
        masterHex: widget.walletMasterHex,
        privateKeyBytes: bytes,
        sshPassphrase: _needsPassphrase && _passphraseCtrl.text.isNotEmpty
            ? _passphraseCtrl.text
            : null,
        comment: null,
      );
      widget.onAdded();
      if (mounted) Navigator.pop(context);
    } catch (e) {
      final msg = e.toString();
      if (msg.contains('passphrase') || msg.contains('decrypt')) {
        setState(() {
          _busy = false;
          _needsPassphrase = true;
          _error = 'Key is passphrase-protected — enter the passphrase.';
        });
      } else {
        setState(() {_busy = false; _error = msg;});
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final filename = widget.filePath.split('/').last;
    return Padding(
      padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom),
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Import SSH key',
                style: TextStyle(
                    fontSize: 17, fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            Text(filename,
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFF8E8E93))),
            if (_needsPassphrase) ...[
              const SizedBox(height: 12),
              TextField(
                controller: _passphraseCtrl,
                obscureText: true,
                autofocus: true,
                decoration: const InputDecoration(
                    labelText: 'Key passphrase', filled: true,
                    fillColor: Color(0xFF2C2C2E)),
              ),
            ],
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!,
                  style: const TextStyle(
                      color: Color(0xFFFF453A), fontSize: 12)),
            ],
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _busy ? null : _save,
              child: _busy
                  ? const SizedBox(height: 18, width: 18,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white))
                  : const Text('Import'),
            ),
          ],
        ),
      ),
    );
  }
}
