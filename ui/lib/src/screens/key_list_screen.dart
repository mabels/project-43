import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'generate_key_screen.dart';

// ── Card-import sheet ─────────────────────────────────────────────────────────

class _CardImportSheet extends StatefulWidget {
  const _CardImportSheet({required this.onImported});
  final VoidCallback onImported;

  @override
  State<_CardImportSheet> createState() => _CardImportSheetState();
}

class _CardImportSheetState extends State<_CardImportSheet> {
  List<ConnectedCardInfo>? _cards;
  String? _loadError;
  String? _selectedIdent;

  final _uidCtrl = TextEditingController();
  final _pinCtrl = TextEditingController();
  String? _importError;
  bool _importing = false;

  @override
  void initState() {
    super.initState();
    _loadCards();
  }

  @override
  void dispose() {
    _uidCtrl.dispose();
    _pinCtrl.dispose();
    super.dispose();
  }

  Future<void> _loadCards() async {
    try {
      final cards = await listConnectedCards();
      if (!mounted) return;
      setState(() {
        _cards = cards;
        if (cards.isNotEmpty) {
          _selectCard(cards.first.ident, cards.first.cardholderName);
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _loadError = e.toString());
    }
  }

  void _selectCard(String ident, String cardholderName) {
    _selectedIdent = ident;
    // Pre-fill UID from cardholder name only when the field is empty or still
    // holds the previous card's name.
    final prev = _cards?.firstWhere(
      (c) => c.ident == _selectedIdent,
      orElse: () => ConnectedCardInfo(
        ident: '', cardholderName: '', sigFingerprint: null, authFingerprint: null,
      ),
    );
    final prevName = prev?.cardholderName ?? '';
    if (_uidCtrl.text.isEmpty || _uidCtrl.text == prevName) {
      _uidCtrl.text = cardholderName;
    }
  }

  Future<void> _doImport() async {
    final ident = _selectedIdent;
    if (ident == null) return;
    setState(() {
      _importing = true;
      _importError = null;
    });
    try {
      await importCard(
        cardIdent: ident,
        uid: _uidCtrl.text.trim(),
        pin: _pinCtrl.text,
      );
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
    final cs = Theme.of(context).colorScheme;

    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      minChildSize: 0.4,
      maxChildSize: 0.9,
      builder: (_, ctrl) => Column(
        children: [
          // Drag handle
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Container(
              width: 36, height: 4,
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
                const Icon(Icons.contactless_outlined, size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Import from card',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                if (_importing)
                  const SizedBox(
                    width: 16, height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Body
          Expanded(
            child: _buildBody(ctrl, cs),
          ),
        ],
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

    if (_cards == null) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_cards!.isEmpty) {
      return const Center(
        child: Text(
          'No OpenPGP cards connected.\nPlug in a YubiKey and try again.',
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
        ),
      );
    }

    return ListView(
      controller: ctrl,
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
      children: [
        // ── Card selector ──────────────────────────────────────────────────
        const _SectionLabel('Select card'),
        ..._cards!.map((c) => _CardTile(
          card: c,
          selected: _selectedIdent == c.ident,
          onTap: () => setState(() => _selectCard(c.ident, c.cardholderName)),
        )),
        const SizedBox(height: 16),

        // ── UID ────────────────────────────────────────────────────────────
        const _SectionLabel('User ID'),
        TextField(
          controller: _uidCtrl,
          style: const TextStyle(fontSize: 14),
          decoration: const InputDecoration(
            hintText: 'Alice <alice@example.com>',
            hintStyle: TextStyle(color: Color(0xFF8E8E93)),
            filled: true,
            fillColor: Color(0xFF2C2C2E),
            border: OutlineInputBorder(borderSide: BorderSide.none),
            contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
        ),
        const SizedBox(height: 4),
        const Text(
          'Leave blank to use the cardholder name stored on the card.',
          style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
        ),
        const SizedBox(height: 16),

        // ── PIN ────────────────────────────────────────────────────────────
        const _SectionLabel('User Signing PIN'),
        TextField(
          controller: _pinCtrl,
          obscureText: true,
          style: const TextStyle(fontSize: 14),
          decoration: const InputDecoration(
            hintText: '······',
            hintStyle: TextStyle(color: Color(0xFF8E8E93)),
            filled: true,
            fillColor: Color(0xFF2C2C2E),
            border: OutlineInputBorder(borderSide: BorderSide.none),
            contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
          onSubmitted: (_) => _doImport(),
        ),
        const SizedBox(height: 4),
        const Text(
          'The card will create a self-signature — touch the YubiKey when prompted.',
          style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
        ),

        // ── Error ──────────────────────────────────────────────────────────
        if (_importError != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFF3A0A0A),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFFFF453A)),
            ),
            child: Text(
              _importError!,
              style: const TextStyle(fontSize: 12, color: Color(0xFFFF453A)),
            ),
          ),
        ],
        const SizedBox(height: 20),

        // ── Import button ──────────────────────────────────────────────────
        FilledButton(
          onPressed: _importing ? null : _doImport,
          style: FilledButton.styleFrom(
            backgroundColor: const Color(0xFF0A84FF),
            minimumSize: const Size.fromHeight(44),
          ),
          child: _importing
              ? const SizedBox(
                  width: 18, height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2, color: Colors.white,
                  ),
                )
              : const Text('Import key from card'),
        ),
      ],
    );
  }
}

class _SectionLabel extends StatelessWidget {
  const _SectionLabel(this.label);
  final String label;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Text(
      label.toUpperCase(),
      style: const TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w600,
        color: Color(0xFF8E8E93),
        letterSpacing: 0.5,
      ),
    ),
  );
}

class _CardTile extends StatelessWidget {
  const _CardTile({
    required this.card,
    required this.selected,
    required this.onTap,
  });

  final ConnectedCardInfo card;
  final bool selected;
  final VoidCallback onTap;

  String get _shortIdent {
    final id = card.ident;
    return id.length > 12 ? '…${id.substring(id.length - 12)}' : id;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: selected ? const Color(0xFF0A84FF) : const Color(0xFF3A3A3C),
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              Icons.contactless,
              size: 20,
              color: selected ? const Color(0xFF0A84FF) : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    card.cardholderName.isNotEmpty
                        ? card.cardholderName
                        : 'Unnamed card',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                      color: card.cardholderName.isNotEmpty
                          ? null
                          : const Color(0xFF8E8E93),
                    ),
                  ),
                  Text(
                    _shortIdent,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 10,
                      color: Color(0xFF8E8E93),
                    ),
                  ),
                ],
              ),
            ),
            if (selected)
              const Icon(Icons.check_circle, size: 18, color: Color(0xFF0A84FF)),
          ],
        ),
      ),
    );
  }
}

// ── Import key sheet ──────────────────────────────────────────────────────────

enum _ImportType { ssh, openpgp }

enum _SourceMode { file, paste }

class _ImportKeySheet extends StatefulWidget {
  const _ImportKeySheet({required this.onImported});
  final VoidCallback onImported;

  @override
  State<_ImportKeySheet> createState() => _ImportKeySheetState();
}

class _ImportKeySheetState extends State<_ImportKeySheet> {
  _ImportType _type = _ImportType.ssh;
  _SourceMode _sourceMode = _SourceMode.file;

  // Shared
  String? _filePath;
  Uint8List? _fileBytes;
  String? _importError;
  bool _importing = false;

  // Paste input
  final _pasteCtrl = TextEditingController();
  bool _pasteHasText = false;

  // SSH fields
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
      _sourceMode == _SourceMode.paste ? _pasteHasText : _fileBytes != null;

  // ── File picker ─────────────────────────────────────────────────────────────

  Future<void> _pickFile() async {
    final home = Platform.environment['HOME'] ?? '';
    final initial = _type == _ImportType.ssh
        ? '$home/.ssh'
        : home;

    final result = await FilePicker.platform.pickFiles(
      type: FileType.any,
      initialDirectory: initial.isNotEmpty ? initial : null,
      dialogTitle: _type == _ImportType.ssh
          ? 'Select SSH private key'
          : 'Select OpenPGP private key (.asc)',
      withData: true,
    );

    if (result == null || result.files.isEmpty) return;
    final file = result.files.first;

    // Prefer bytes from picker; fall back to reading path directly.
    final bytes = file.bytes ??
        (file.path != null ? await File(file.path!).readAsBytes() : null);

    if (bytes == null) {
      setState(() => _importError = 'Could not read file contents.');
      return;
    }

    setState(() {
      _filePath = file.path ?? file.name;
      _fileBytes = bytes;
      _importError = null;

      // For SSH keys, try to extract the comment and pre-fill UID.
      if (_type == _ImportType.ssh && _uidCtrl.text.isEmpty) {
        _tryFillUidFromSshComment(bytes);
      }
    });
  }

  void _tryFillUidFromSshComment(Uint8List bytes) {
    try {
      final text = String.fromCharCodes(bytes);
      // OpenSSH private key comment is embedded in the binary payload.
      // A reliable extraction requires Rust parsing; for now leave the field
      // blank and let the user fill it in (or derive from key comment via Rust).
      text.isEmpty; // no-op, avoids lint warning
    } catch (_) {}
  }

  // ── Import ──────────────────────────────────────────────────────────────────

  Future<void> _doImport() async {
    // Resolve bytes from whichever source is active.
    Uint8List bytes;
    if (_sourceMode == _SourceMode.paste) {
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

    if (_type == _ImportType.ssh) {
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
      if (_type == _ImportType.ssh) {
        await importSshKey(
          pemBytes: bytes,
          uidOverride: _uidCtrl.text.trim(),
          sshPassphrase: _sshPassCtrl.text.isEmpty ? null : _sshPassCtrl.text,
          openpgpPassphrase:
              _openpgpPassCtrl.text.isEmpty ? null : _openpgpPassCtrl.text,
        );
      } else {
        await importOpenpgpKey(
          armored: String.fromCharCodes(bytes),
        );
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

  // ── Build ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.7,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      builder: (_, ctrl) => Column(
        children: [
          // Drag handle
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
          // Header
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
          // Body
          Expanded(
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
              children: [
                // ── Type toggle ──────────────────────────────────────────
                Row(
                  children: [
                    _TypeButton(
                      label: 'SSH key',
                      icon: Icons.terminal,
                      selected: _type == _ImportType.ssh,
                      onTap: () => setState(() {
                        _type = _ImportType.ssh;
                        _fileBytes = null;
                        _filePath = null;
                        _pasteCtrl.clear();
                        _importError = null;
                      }),
                    ),
                    const SizedBox(width: 8),
                    _TypeButton(
                      label: 'OpenPGP key',
                      icon: Icons.vpn_key_outlined,
                      selected: _type == _ImportType.openpgp,
                      onTap: () => setState(() {
                        _type = _ImportType.openpgp;
                        _fileBytes = null;
                        _filePath = null;
                        _pasteCtrl.clear();
                        _importError = null;
                      }),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // ── Source mode toggle (File / Paste) ────────────────────
                Row(
                  children: [
                    _SourceToggle(
                      label: 'File',
                      icon: Icons.folder_open,
                      selected: _sourceMode == _SourceMode.file,
                      onTap: () => setState(() {
                        _sourceMode = _SourceMode.file;
                        _importError = null;
                      }),
                    ),
                    const SizedBox(width: 8),
                    _SourceToggle(
                      label: 'Paste',
                      icon: Icons.content_paste,
                      selected: _sourceMode == _SourceMode.paste,
                      onTap: () => setState(() {
                        _sourceMode = _SourceMode.paste;
                        _importError = null;
                      }),
                    ),
                  ],
                ),
                const SizedBox(height: 12),

                // ── File picker (file mode) ──────────────────────────────
                if (_sourceMode == _SourceMode.file) ...[
                  GestureDetector(
                    onTap: _pickFile,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 12),
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
                                  : _type == _ImportType.ssh
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
                                fontSize: 12, color: Color(0xFF0A84FF)),
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
                            color: Color(0xFF8E8E93)),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                ],

                // ── Paste text area (paste mode) ─────────────────────────
                if (_sourceMode == _SourceMode.paste) ...[
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
                      hintText: _type == _ImportType.ssh
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
                        borderSide:
                            BorderSide(color: Color(0xFF0A84FF), width: 1.5),
                      ),
                      contentPadding: const EdgeInsets.all(12),
                      suffixIcon: _pasteHasText
                          ? IconButton(
                              icon: const Icon(Icons.clear,
                                  size: 16, color: Color(0xFF8E8E93)),
                              onPressed: () => _pasteCtrl.clear(),
                            )
                          : null,
                    ),
                  ),
                ],
                const SizedBox(height: 16),

                // ── SSH-specific fields ──────────────────────────────────
                if (_type == _ImportType.ssh) ...[
                  const _SectionLabel('User ID'),
                  TextField(
                    controller: _uidCtrl,
                    style: const TextStyle(fontSize: 14),
                    decoration: const InputDecoration(
                      hintText: 'Alice <alice@example.com>',
                      hintStyle: TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: Color(0xFF2C2C2E),
                      border:
                          OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: EdgeInsets.symmetric(
                          horizontal: 12, vertical: 10),
                    ),
                  ),
                  const Padding(
                    padding: EdgeInsets.fromLTRB(0, 4, 0, 16),
                    child: Text(
                      'Leave blank to use the SSH key\'s comment field.',
                      style:
                          TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                    ),
                  ),
                  const _SectionLabel('SSH passphrase (if key is encrypted)'),
                  TextField(
                    controller: _sshPassCtrl,
                    obscureText: !_sshPassVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'Leave blank if unencrypted',
                      hintStyle:
                          const TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: const Color(0xFF2C2C2E),
                      border:
                          const OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 10),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _sshPassVisible
                              ? Icons.visibility_off
                              : Icons.visibility,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () => setState(
                            () => _sshPassVisible = !_sshPassVisible),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const _SectionLabel('OpenPGP passphrase (protects stored key)'),
                  TextField(
                    controller: _openpgpPassCtrl,
                    obscureText: !_openpgpPassVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'New passphrase (leave blank = unencrypted)',
                      hintStyle:
                          const TextStyle(color: Color(0xFF8E8E93)),
                      filled: true,
                      fillColor: const Color(0xFF2C2C2E),
                      border:
                          const OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 10),
                      suffixIcon: IconButton(
                        icon: Icon(
                          _openpgpPassVisible
                              ? Icons.visibility_off
                              : Icons.visibility,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () => setState(
                            () => _openpgpPassVisible = !_openpgpPassVisible),
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
                      border:
                          OutlineInputBorder(borderSide: BorderSide.none),
                      contentPadding: EdgeInsets.symmetric(
                          horizontal: 12, vertical: 10),
                    ),
                    onSubmitted: (_) => _doImport(),
                  ),
                  const Padding(
                    padding: EdgeInsets.fromLTRB(0, 4, 0, 0),
                    child: Text(
                      'You will need this passphrase every time the agent signs. '
                      'Leave blank to store the key unencrypted.',
                      style:
                          TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                    ),
                  ),
                ],

                // ── OpenPGP-specific hint ────────────────────────────────
                if (_type == _ImportType.openpgp)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 8),
                    child: Text(
                      'Pick a file containing a PGP PRIVATE KEY BLOCK '
                      '(armored .asc or binary .pgp/.gpg). The passphrase, '
                      'if any, stays unchanged and is required when signing.',
                      style:
                          TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
                    ),
                  ),

                // ── Error ────────────────────────────────────────────────
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
                          fontSize: 12, color: Color(0xFFFF453A)),
                    ),
                  ),
                ],
                const SizedBox(height: 20),

                // ── Import button ─────────────────────────────────────────
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
                    _type == _ImportType.ssh
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

class _SourceToggle extends StatelessWidget {
  const _SourceToggle({
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
              ? const Color(0xFF2C2C2E)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: selected
                ? const Color(0xFF0A84FF)
                : const Color(0xFF3A3A3C),
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
                fontWeight:
                    selected ? FontWeight.w600 : FontWeight.normal,
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

class _TypeButton extends StatelessWidget {
  const _TypeButton({
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
          padding:
              const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
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

class KeyListScreen extends StatefulWidget {
  const KeyListScreen({super.key});

  @override
  State<KeyListScreen> createState() => _KeyListScreenState();
}

class _KeyListScreenState extends State<KeyListScreen> {
  late Future<List<KeyInfo>> _keysFuture;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  void _reload() {
    setState(() {
      _keysFuture = listKeys();
    });
  }

  void _showKeyDetail(BuildContext context, KeyInfo info) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _KeyDetailSheet(info: info, onDeleted: _reload),
    );
  }

  Future<void> _openGenerate() async {
    final didGenerate = await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (_) => const GenerateKeyScreen()),
    );
    if (didGenerate == true) _reload();
  }

  void _openCardImport() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _CardImportSheet(onImported: _reload),
    );
  }

  void _openImport() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _ImportKeySheet(onImported: _reload),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: Row(
          children: [
            Text(
              'p43',
              style: TextStyle(
                fontWeight: FontWeight.w700,
                fontSize: 17,
                color: cs.onSurface,
              ),
            ),
            const SizedBox(width: 8),
            Text(
              'Key Store',
              style: TextStyle(
                fontWeight: FontWeight.w400,
                fontSize: 14,
                color: cs.onSurface.withValues(alpha: 0.5),
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.contactless_outlined),
            tooltip: 'Import from card',
            onPressed: _openCardImport,
          ),
          IconButton(
            icon: const Icon(Icons.download_outlined),
            tooltip: 'Import SSH / OpenPGP key',
            onPressed: _openImport,
          ),
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Generate key',
            onPressed: _openGenerate,
          ),
        ],
      ),
      body: FutureBuilder<List<KeyInfo>>(
        future: _keysFuture,
        builder: (context, snap) {
          if (snap.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return _ErrorView(message: snap.error.toString());
          }
          final keys = snap.data!;
          if (keys.isEmpty) {
            return _EmptyView(onGenerate: _openGenerate);
          }
          return ListView.separated(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            itemCount: keys.length,
            separatorBuilder: (context, _) => const SizedBox(height: 8),
            itemBuilder: (context, i) => _KeyCard(
              key: ValueKey(keys[i].fingerprint),
              info: keys[i],
              onTap: () => _showKeyDetail(context, keys[i]),
            ),
          );
        },
      ),
    );
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Converts a card ident like `"0006:17684870"` to `"cardno:17_684_870"`.
/// Groups the serial digits in threes from the right, separated by underscores.
String _cardnoFromIdent(String ident) {
  final serial = ident.contains(':') ? ident.split(':').last : ident;
  final buf = StringBuffer();
  for (var i = 0; i < serial.length; i++) {
    final fromRight = serial.length - i;
    if (i > 0 && fromRight % 3 == 0) buf.write('_');
    buf.write(serial[i]);
  }
  return 'cardno:$buf';
}

// ── Key card ──────────────────────────────────────────────────────────────────

class _KeyCard extends StatelessWidget {
  const _KeyCard({super.key, required this.info, this.onTap});

  final KeyInfo info;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    final isDisabled = !info.enabled;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Opacity(
        opacity: isDisabled ? 0.45 : 1.0,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          decoration: BoxDecoration(
            color: const Color(0xFF2C2C2E),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: isDisabled
                  ? const Color(0xFF48484A)
                  : const Color(0xFF3A3A3C),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      info.uid,
                      style: const TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(width: 8),
                  if (isDisabled) ...[
                    const _Badge(
                      label: 'off',
                      color: Color(0xFF8E8E93),
                      background: Color(0xFF2C2C2E),
                    ),
                    const SizedBox(width: 6),
                  ],
                  if (info.cardIdents.isNotEmpty) ...[
                    Text(
                      _cardnoFromIdent(info.cardIdents.first),
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 10,
                        color: Color(0xFF0A84FF),
                      ),
                    ),
                    const SizedBox(width: 8),
                  ],
                  _Badge(
                    label: info.hasSecret ? 'sec' : 'pub',
                    color: info.hasSecret
                        ? const Color(0xFFF5A623)
                        : const Color(0xFF30D158),
                    background: info.hasSecret
                        ? const Color(0xFF3A2A0A)
                        : const Color(0xFF1A2A1A),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  _Label(info.algo),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      info.fingerprint,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 10,
                        color: cs.onSurface.withValues(alpha: 0.45),
                        letterSpacing: 0.4,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Key summary (used inside dialogs) ────────────────────────────────────────

class _KeySummary extends StatelessWidget {
  const _KeySummary({required this.info});
  final KeyInfo info;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(info.uid,
            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13)),
        const SizedBox(height: 3),
        Text(
          info.fingerprint,
          style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 10,
              color: cs.onSurface.withValues(alpha: 0.5)),
        ),
      ],
    );
  }
}

// ── Key detail sheet ──────────────────────────────────────────────────────────

class _KeyDetailSheet extends StatefulWidget {
  const _KeyDetailSheet({required this.info, this.onDeleted});
  final KeyInfo info;
  final VoidCallback? onDeleted;

  @override
  State<_KeyDetailSheet> createState() => _KeyDetailSheetState();
}

class _KeyDetailSheetState extends State<_KeyDetailSheet> {
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
    // Default to the AUTH subkey; fall back to index 0.
    _selectedSubkey = _authIndex();
    _load();
  }

  int _authIndex() {
    final idx = widget.info.subkeys
        .indexWhere((s) => s.role.contains('auth'));
    return idx >= 0 ? idx : 0;
  }

  Future<void> _load() async {
    try {
      final armored =
          await getPublicKeyArmored(fingerprint: widget.info.fingerprint);
      if (!mounted) return;
      setState(() => _armored = armored);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    }
  }

  Future<void> _confirmDelete() async {
    final info = widget.info;

    // For keys with secret material, require passphrase verification first.
    if (info.hasSecret) {
      await _confirmDeleteWithPassphrase(info);
    } else {
      await _confirmDeletePublicOnly(info);
    }
  }

  /// Delete flow for pub-only keys: just a simple "are you sure?" dialog.
  Future<void> _confirmDeletePublicOnly(KeyInfo info) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Delete public key?'),
        content: _KeySummary(info: info),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(
                backgroundColor: const Color(0xFFFF453A)),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _runDelete(info.fingerprint);
  }

  /// Delete flow for keys with secret material: passphrase entry + verify,
  /// then a final "you're really sure?" confirmation before wiping.
  Future<void> _confirmDeleteWithPassphrase(KeyInfo info) async {
    final passphraseCtrl = TextEditingController();
    String? passphraseError;

    // Step 1 — ask for passphrase and verify it.
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
              _KeySummary(info: info),
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
                    if (ctx.mounted) Navigator.pop(ctx, passphraseCtrl.text);
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
                  if (ctx.mounted) Navigator.pop(ctx, passphraseCtrl.text);
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

    // Step 2 — final "this is permanent" confirmation.
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Delete key permanently?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _KeySummary(info: info),
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
                  Icon(Icons.warning_amber_rounded,
                      size: 16, color: Color(0xFFFF9F0A)),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Passphrase verified. The private key will be '
                      'deleted permanently. There is no undo.',
                      style:
                          TextStyle(fontSize: 12, color: Color(0xFFFF9F0A)),
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
                backgroundColor: const Color(0xFFFF453A)),
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
      widget.onDeleted?.call(); // reloads the key list
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to update key: $e')),
      );
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
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Delete failed: $e')),
      );
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
          // Drag handle
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
            padding: const EdgeInsets.fromLTRB(16, 0, 4, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    widget.info.uid,
                    style: const TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  widget.info.algo,
                  style: TextStyle(
                      fontSize: 12,
                      color: cs.onSurface.withValues(alpha: 0.5)),
                ),
                const SizedBox(width: 4),
                // Enable / disable toggle
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
                        icon: const Icon(Icons.delete_outline,
                            color: Color(0xFFFF453A)),
                        tooltip: 'Delete key',
                        onPressed: _confirmDelete,
                      ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Body
          Expanded(
            child: _error != null
                ? Center(
                    child: Text(_error!,
                        style: const TextStyle(color: Color(0xFFFF453A))))
                : (_armored == null
                    ? const Center(child: CircularProgressIndicator())
                    : ListView(
                        controller: ctrl,
                        padding: const EdgeInsets.all(16),
                        children: [
                          // ── Subkey selector ──────────────────────────
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
                                    color: const Color(0xFF3A3A3C)),
                              ),
                              child: Column(
                                children: [
                                  for (var i = 0;
                                      i < widget.info.subkeys.length;
                                      i++) ...[
                                    if (i > 0)
                                      const Divider(
                                          height: 1,
                                          indent: 12,
                                          endIndent: 12),
                                    _SubkeyRow(
                                      subkey: widget.info.subkeys[i],
                                      selected: i == _selectedSubkey,
                                      onTap: () => setState(
                                          () => _selectedSubkey = i),
                                    ),
                                  ],
                                ],
                              ),
                            ),
                            const SizedBox(height: 20),
                          ],
                          // ── Public keys for selected subkey ──────────
                          if (widget.info.subkeys.isNotEmpty &&
                              widget.info.subkeys[_selectedSubkey]
                                      .opensshKey !=
                                  null) ...[
                            _CopyableBlock(
                              label: 'OpenSSH (authorized_keys)',
                              value: widget
                                  .info.subkeys[_selectedSubkey].opensshKey!,
                            ),
                            const SizedBox(height: 16),
                          ],
                          _CopyableBlock(
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

class _CopyableBlock extends StatelessWidget {
  const _CopyableBlock({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              label,
              style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: cs.onSurface.withValues(alpha: 0.5),
                  letterSpacing: 0.4),
            ),
            const Spacer(),
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: value));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('$label copied'),
                    duration: const Duration(seconds: 2),
                  ),
                );
              },
              child: const Icon(Icons.copy, size: 16, color: Color(0xFF0A84FF)),
            ),
          ],
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
            value,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 10,
              color: cs.onSurface.withValues(alpha: 0.85),
              height: 1.5,
            ),
          ),
        ),
      ],
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge({
    required this.label,
    required this.color,
    required this.background,
  });

  final String label;
  final Color color;
  final Color background;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w700,
          color: color,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

class _Label extends StatelessWidget {
  const _Label(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: TextStyle(
        fontSize: 11,
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.5),
      ),
    );
  }
}

// ── Subkey row ────────────────────────────────────────────────────────────────

/// Maps a raw role string like `"certify"`, `"sign"`, `"auth"`, `"encrypt"` to
/// a display-friendly label and colour.
(String label, Color color) _roleStyle(String role) {
  if (role.contains('auth')) return ('AUTH', const Color(0xFF0A84FF));
  if (role.contains('sign') && role.contains('certify')) {
    return ('CERTIFY+SIGN', const Color(0xFFF5A623));
  }
  if (role.contains('sign')) return ('SIGN', const Color(0xFFF5A623));
  if (role.contains('certify')) return ('CERTIFY', const Color(0xFF8E8E93));
  if (role.contains('encrypt')) return ('ENCRYPT', const Color(0xFF30D158));
  return (role.toUpperCase(), const Color(0xFF8E8E93));
}

class _SubkeyRow extends StatelessWidget {
  const _SubkeyRow({
    required this.subkey,
    required this.selected,
    required this.onTap,
  });

  final SubkeyInfo subkey;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final (label, color) = _roleStyle(subkey.role);

    return InkWell(
      onTap: onTap,
      child: Container(
        decoration: selected
            ? BoxDecoration(
                color: const Color(0xFF0A84FF).withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(10),
              )
            : null,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
        child: Row(
          children: [
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: color.withValues(alpha: selected ? 0.25 : 0.15),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  color: color,
                  letterSpacing: 0.4,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            if (subkey.role.contains('auth')) ...[
              const SizedBox(width: 6),
              const Text(
                'used by SSH',
                style: TextStyle(
                  fontSize: 10,
                  color: Color(0xFF636366),
                  fontStyle: FontStyle.italic,
                ),
              ),
            ],
            const Spacer(),
            Text(
              subkey.algo,
              style: const TextStyle(
                fontSize: 11,
                fontFamily: 'monospace',
                color: Color(0xFF8E8E93),
              ),
            ),
            if (selected) ...[
              const SizedBox(width: 8),
              const Icon(Icons.chevron_right,
                  size: 14, color: Color(0xFF0A84FF)),
            ],
          ],
        ),
      ),
    );
  }
}

// ── Empty / error states ──────────────────────────────────────────────────────

class _EmptyView extends StatelessWidget {
  const _EmptyView({required this.onGenerate});
  final VoidCallback onGenerate;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('🔑', style: TextStyle(fontSize: 40)),
          const SizedBox(height: 12),
          const Text(
            'No keys in store.',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 6),
          Text(
            'Generate your first key to get started.',
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.5),
            ),
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: onGenerate,
            icon: const Icon(Icons.add, size: 16),
            label: const Text('Generate Key'),
          ),
        ],
      ),
    );
  }
}

class _ErrorView extends StatelessWidget {
  const _ErrorView({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Text(
          message,
          style: const TextStyle(color: Color(0xFFFF453A), fontSize: 13),
          textAlign: TextAlign.center,
        ),
      ),
    );
  }
}
