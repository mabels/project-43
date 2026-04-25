import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'key_widgets.dart';

// ── Enums ─────────────────────────────────────────────────────────────────────

enum KeyImportType { ssh, openpgp }

enum KeySourceMode { file, paste }

// ── Import key sheet ──────────────────────────────────────────────────────────

class KeyImportSheet extends StatefulWidget {
  const KeyImportSheet({super.key, required this.onImported});
  final VoidCallback onImported;

  @override
  State<KeyImportSheet> createState() => _KeyImportSheetState();
}

class _KeyImportSheetState extends State<KeyImportSheet> {
  KeyImportType _type = KeyImportType.ssh;
  KeySourceMode _sourceMode = KeySourceMode.file;

  String? _filePath;
  Uint8List? _fileBytes;
  String? _importError;
  bool _importing = false;

  final _pasteCtrl = TextEditingController();
  bool _pasteHasText = false;

  final _uidCtrl = TextEditingController();
  final _sshPassCtrl = TextEditingController();
  bool _sshPassVisible = false;
  final _openpgpPassCtrl = TextEditingController();
  final _openpgpPassConfirmCtrl = TextEditingController();
  bool _openpgpPassVisible = false;

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
    _uidCtrl.dispose();
    _sshPassCtrl.dispose();
    _openpgpPassCtrl.dispose();
    _openpgpPassConfirmCtrl.dispose();
    super.dispose();
  }

  bool get _hasInput =>
      _sourceMode == KeySourceMode.paste ? _pasteHasText : _fileBytes != null;

  Future<void> _pickFile() async {
    final home = Platform.environment['HOME'] ?? '';
    final initial = _type == KeyImportType.ssh ? '$home/.ssh' : home;

    final result = await FilePicker.pickFiles(
      type: FileType.any,
      initialDirectory: initial.isNotEmpty ? initial : null,
      dialogTitle: _type == KeyImportType.ssh
          ? 'Select SSH private key'
          : 'Select OpenPGP private key (.asc)',
      withData: true,
    );

    if (result == null || result.files.isEmpty) return;
    final file = result.files.first;

    final bytes =
        file.bytes ??
        (file.path != null ? await File(file.path!).readAsBytes() : null);

    if (bytes == null) {
      setState(() => _importError = 'Could not read file contents.');
      return;
    }

    setState(() {
      _filePath = file.path ?? file.name;
      _fileBytes = bytes;
      _importError = null;
      if (_type == KeyImportType.ssh && _uidCtrl.text.isEmpty) {
        _tryFillUidFromSshComment(bytes);
      }
    });
  }

  void _tryFillUidFromSshComment(Uint8List bytes) {
    try {
      final text = String.fromCharCodes(bytes);
      text.isEmpty; // no-op, avoids lint warning
    } catch (_) {}
  }

  Future<void> _doImport() async {
    Uint8List bytes;
    if (_sourceMode == KeySourceMode.paste) {
      final text = _pasteCtrl.text.trim();
      if (text.isEmpty) {
        setState(() => _importError = 'Paste a key first.');
        return;
      }
      bytes = Uint8List.fromList(text.codeUnits);
    } else {
      if (_fileBytes == null) {
        setState(() => _importError = 'Pick a file first.');
        return;
      }
      bytes = _fileBytes!;
    }

    if (_type == KeyImportType.ssh) {
      final pw = _openpgpPassCtrl.text;
      final confirm = _openpgpPassConfirmCtrl.text;
      if (pw.isNotEmpty && pw != confirm) {
        setState(() => _importError = 'OpenPGP passphrases do not match.');
        return;
      }
    }

    setState(() {
      _importing = true;
      _importError = null;
    });

    try {
      if (_type == KeyImportType.ssh) {
        await importSshKey(
          pemBytes: bytes,
          uidOverride: _uidCtrl.text.trim(),
          sshPassphrase: _sshPassCtrl.text.isEmpty ? null : _sshPassCtrl.text,
          openpgpPassphrase: _openpgpPassCtrl.text.isEmpty
              ? null
              : _openpgpPassCtrl.text,
        );
      } else {
        await importOpenpgpKey(armored: String.fromCharCodes(bytes));
      }
      if (!mounted) return;
      Navigator.pop(context);
      widget.onImported();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _importError = e.toString();
        _importing = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.7,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      builder: (_, ctrl) => Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: const Color(0xFF8E8E93),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Row(
              children: [
                const Icon(Icons.download_outlined, size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Import private key',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                if (_importing)
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
              children: [
                // ── Type toggle ───────────────────────────────────────
                Row(
                  children: [
                    KeyTypeButton(
                      label: 'SSH key',
                      icon: Icons.terminal,
                      selected: _type == KeyImportType.ssh,
                      onTap: () => setState(() {
                        _type = KeyImportType.ssh;
                        _fileBytes = null;
                        _filePath = null;
                        _pasteCtrl.clear();
                        _importError = null;
                      }),
                    ),
                    const SizedBox(width: 8),
                    KeyTypeButton(
                      label: 'OpenPGP key',
                      icon: Icons.vpn_key_outlined,
                      selected: _type == KeyImportType.openpgp,
                      onTap: () => setState(() {
                        _type = KeyImportType.openpgp;
                        _fileBytes = null;
                        _filePath = null;
                        _pasteCtrl.clear();
                        _importError = null;
                      }),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // ── Source mode toggle ────────────────────────────────
                Row(
                  children: [
                    KeySourceToggle(
                      label: 'File',
                      icon: Icons.folder_open,
                      selected: _sourceMode == KeySourceMode.file,
                      onTap: () => setState(() {
                        _sourceMode = KeySourceMode.file;
                        _importError = null;
                      }),
                    ),
                    const SizedBox(width: 8),
                    KeySourceToggle(
                      label: 'Paste',
                      icon: Icons.content_paste,
                      selected: _sourceMode == KeySourceMode.paste,
                      onTap: () => setState(() {
                        _sourceMode = KeySourceMode.paste;
                        _importError = null;
                      }),
                    ),
                  ],
                ),
                const SizedBox(height: 12),

                // ── File picker ───────────────────────────────────────
                if (_sourceMode == KeySourceMode.file) ...[
                  GestureDetector(
                    onTap: _pickFile,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 12,
                      ),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2C2C2E),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: _filePath != null
                              ? const Color(0xFF30D158)
                              : const Color(0xFF3A3A3C),
                        ),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            _filePath != null
                                ? Icons.check_circle_outline
                                : Icons.folder_open,
                            size: 18,
                            color: _filePath != null
                                ? const Color(0xFF30D158)
                                : const Color(0xFF8E8E93),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              _filePath != null
                                  ? _filePath!.split('/').last
                                  : _type == KeyImportType.ssh
                                  ? 'Browse ~/.ssh/ …'
                                  : 'Browse for .asc file …',
                              style: TextStyle(
                                fontSize: 13,
                                color: _filePath != null
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
                  if (_filePath != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        _filePath!,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 10,
                          color: Color(0xFF8E8E93),
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                ],

                // ── Paste area ────────────────────────────────────────
                if (_sourceMode == KeySourceMode.paste) ...[
                  TextField(
                    controller: _pasteCtrl,
                    maxLines: 8,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: Color(0xFFE5E5EA),
                      height: 1.5,
                    ),
                    decoration: InputDecoration(
                      hintText: _type == KeyImportType.ssh
                          ? '-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----'
                          : '-----BEGIN PGP PRIVATE KEY BLOCK-----\n…\n-----END PGP PRIVATE KEY BLOCK-----',
                      hintStyle: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                        color: Color(0xFF48484A),
                        height: 1.5,
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
                const SizedBox(height: 16),

                // ── SSH-specific fields ───────────────────────────────
                if (_type == KeyImportType.ssh) ...[
                  const KeySectionLabel('User ID'),
                  TextField(
                    controller: _uidCtrl,
                    style: const TextStyle(fontSize: 14),
                    decoration: const InputDecoration(
                      hintText: 'Alice <alice@example.com>',
                      hintStyle: TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: Color(0xFF2C2C2E),
                      border: OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                    ),
                  ),
                  const Padding(
                    padding: EdgeInsets.fromLTRB(0, 4, 0, 16),
                    child: Text(
                      "Leave blank to use the SSH key's comment field.",
                      style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                    ),
                  ),
                  const KeySectionLabel('SSH passphrase (if key is encrypted)'),
                  TextField(
                    controller: _sshPassCtrl,
                    obscureText: !_sshPassVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'Leave blank if unencrypted',
                      hintStyle: const TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: const Color(0xFF2C2C2E),
                      border: const OutlineInputBorder(
                        borderSide: BorderSide.none,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _sshPassVisible
                              ? Icons.visibility_off
                              : Icons.visibility,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () =>
                            setState(() => _sshPassVisible = !_sshPassVisible),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const KeySectionLabel(
                    'OpenPGP passphrase (protects stored key)',
                  ),
                  TextField(
                    controller: _openpgpPassCtrl,
                    obscureText: !_openpgpPassVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'New passphrase (leave blank = unencrypted)',
                      hintStyle: const TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: const Color(0xFF2C2C2E),
                      border: const OutlineInputBorder(
                        borderSide: BorderSide.none,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _openpgpPassVisible
                              ? Icons.visibility_off
                              : Icons.visibility,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () => setState(
                          () => _openpgpPassVisible = !_openpgpPassVisible,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _openpgpPassConfirmCtrl,
                    obscureText: !_openpgpPassVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: const InputDecoration(
                      hintText: 'Confirm passphrase',
                      hintStyle: TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: Color(0xFF2C2C2E),
                      border: OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                    ),
                    onSubmitted: (_) => _doImport(),
                  ),
                  const Padding(
                    padding: EdgeInsets.fromLTRB(0, 4, 0, 0),
                    child: Text(
                      'You will need this passphrase every time the agent signs. '
                      'Leave blank to store the key unencrypted.',
                      style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                    ),
                  ),
                ],

                // ── OpenPGP hint ──────────────────────────────────────
                if (_type == KeyImportType.openpgp)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text(
                      'Pick a file containing a PGP PRIVATE KEY BLOCK '
                      '(armored .asc or binary .pgp/.gpg). The passphrase, '
                      'if any, stays unchanged and is required when signing.',
                      style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
                    ),
                  ),

                if (_importError != null) ...[
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF3A0A0A),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFFFF453A)),
                    ),
                    child: Text(
                      _importError!,
                      style: const TextStyle(
                        fontSize: 12,
                        color: Color(0xFFFF453A),
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: 20),

                FilledButton.icon(
                  onPressed: (_importing || !_hasInput) ? null : _doImport,
                  style: FilledButton.styleFrom(
                    backgroundColor: const Color(0xFF0A84FF),
                    minimumSize: const Size.fromHeight(44),
                    disabledBackgroundColor: const Color(0xFF2C2C2E),
                  ),
                  icon: _importing
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(Icons.download, size: 18),
                  label: Text(
                    _type == KeyImportType.ssh
                        ? 'Import SSH key'
                        : 'Import OpenPGP key',
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ── Source toggle ─────────────────────────────────────────────────────────────

class KeySourceToggle extends StatelessWidget {
  const KeySourceToggle({
    super.key,
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
          color: selected ? const Color(0xFF2C2C2E) : Colors.transparent,
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

// ── Type button ───────────────────────────────────────────────────────────────

class KeyTypeButton extends StatelessWidget {
  const KeyTypeButton({
    super.key,
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
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: selected
                ? const Color(0xFF0A84FF).withValues(alpha: 0.15)
                : const Color(0xFF2C2C2E),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: selected
                  ? const Color(0xFF0A84FF)
                  : const Color(0xFF3A3A3C),
              width: selected ? 1.5 : 1,
            ),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                icon,
                size: 16,
                color: selected
                    ? const Color(0xFF0A84FF)
                    : const Color(0xFF8E8E93),
              ),
              const SizedBox(width: 6),
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
      ),
    );
  }
}
