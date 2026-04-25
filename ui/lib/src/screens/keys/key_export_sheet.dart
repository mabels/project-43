import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

// ── Export format ─────────────────────────────────────────────────────────────

enum _ExportFormat { pgpPublic, sshPublic, pgpPrivate }

// ── KeyExportSheet ────────────────────────────────────────────────────────────

/// Bottom sheet that lets the user save a key to disk in one of three formats:
///   • OpenPGP public key  (.asc)
///   • OpenSSH public key  (.pub)
///   • OpenPGP private key (.asc) — requires passphrase if key is encrypted
class KeyExportSheet extends StatefulWidget {
  const KeyExportSheet({super.key, required this.info});
  final KeyInfo info;

  @override
  State<KeyExportSheet> createState() => _KeyExportSheetState();
}

class _KeyExportSheetState extends State<KeyExportSheet> {
  _ExportFormat _format = _ExportFormat.pgpPublic;

  final _passCtrl = TextEditingController();
  bool _passVisible = false;

  bool _busy = false;
  String? _error;
  String? _savedPath;

  @override
  void dispose() {
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _doExport() async {
    setState(() {
      _busy = true;
      _error = null;
      _savedPath = null;
    });

    try {
      // ── 1. Fetch the key material ─────────────────────────────────────────
      final String armor;
      final String defaultName;
      final String ext;

      switch (_format) {
        case _ExportFormat.pgpPublic:
          armor = await getPublicKeyArmored(
            fingerprint: widget.info.fingerprint,
          );
          defaultName =
              '${widget.info.uid.replaceAll(RegExp(r'[^\w@.-]'), '_')}_pub.asc';
          ext = 'asc';

        case _ExportFormat.sshPublic:
          armor = await getPublicKeyOpenssh(
            fingerprint: widget.info.fingerprint,
          );
          defaultName =
              '${widget.info.uid.replaceAll(RegExp(r'[^\w@.-]'), '_')}.pub';
          ext = 'pub';

        case _ExportFormat.pgpPrivate:
          armor = await getPrivateKeyArmored(
            fingerprint: widget.info.fingerprint,
            passphrase: _passCtrl.text,
          );
          defaultName =
              '${widget.info.uid.replaceAll(RegExp(r'[^\w@.-]'), '_')}_sec.asc';
          ext = 'asc';
      }

      // ── 2. Ask where to save ──────────────────────────────────────────────
      final savePath = await FilePicker.saveFile(
        dialogTitle: 'Save key as…',
        fileName: defaultName,
        type: FileType.custom,
        allowedExtensions: [ext],
      );

      if (savePath == null) {
        setState(() => _busy = false);
        return;
      }

      // ── 3. Write ──────────────────────────────────────────────────────────
      final out = savePath.endsWith('.$ext') ? savePath : '$savePath.$ext';
      await File(out).writeAsString(armor);

      setState(() {
        _savedPath = out;
        _busy = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _busy = false;
      });
    }
  }

  bool get _canExport {
    if (_busy) return false;
    if (_format == _ExportFormat.pgpPrivate) {
      // Unencrypted keys export with an empty passphrase — always enabled.
      return true;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.55,
      minChildSize: 0.4,
      maxChildSize: 0.85,
      builder: (_, ctrl) => Column(
        children: [
          // ── Handle ─────────────────────────────────────────────────────────
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
          // ── Title ──────────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Row(
              children: [
                const Icon(Icons.upload_outlined, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Export key',
                        style: TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        widget.info.uid,
                        style: const TextStyle(
                          fontSize: 12,
                          color: Color(0xFF8E8E93),
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                if (_busy)
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
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
              children: [
                // ── Format chooser ──────────────────────────────────────────
                _FormatTile(
                  title: 'OpenPGP public key',
                  subtitle: 'Armored .asc — safe to share',
                  icon: Icons.vpn_key_outlined,
                  selected: _format == _ExportFormat.pgpPublic,
                  onTap: () => setState(() {
                    _format = _ExportFormat.pgpPublic;
                    _error = null;
                    _savedPath = null;
                  }),
                ),
                const SizedBox(height: 8),
                _FormatTile(
                  title: 'OpenSSH public key',
                  subtitle: 'authorized_keys line (.pub)',
                  icon: Icons.terminal,
                  selected: _format == _ExportFormat.sshPublic,
                  onTap: () => setState(() {
                    _format = _ExportFormat.sshPublic;
                    _error = null;
                    _savedPath = null;
                  }),
                ),
                if (widget.info.hasSecret) ...[
                  const SizedBox(height: 8),
                  _FormatTile(
                    title: 'OpenPGP private key',
                    subtitle: 'Armored .asc — keep safe',
                    icon: Icons.lock_outline,
                    selected: _format == _ExportFormat.pgpPrivate,
                    danger: true,
                    onTap: () => setState(() {
                      _format = _ExportFormat.pgpPrivate;
                      _error = null;
                      _savedPath = null;
                    }),
                  ),
                ],

                // ── Passphrase field (private key only) ─────────────────────
                if (_format == _ExportFormat.pgpPrivate) ...[
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF3A1A0A),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFFFF9F0A)),
                    ),
                    child: const Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.warning_amber_rounded,
                          size: 16,
                          color: Color(0xFFFF9F0A),
                        ),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Private keys must be kept secret. '
                            'Store the exported file securely and '
                            'never share it.',
                            style: TextStyle(
                              fontSize: 12,
                              color: Color(0xFFFF9F0A),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _passCtrl,
                    obscureText: !_passVisible,
                    style: const TextStyle(fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'Key passphrase (leave blank if unencrypted)',
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
                          _passVisible
                              ? Icons.visibility_off
                              : Icons.visibility,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () =>
                            setState(() => _passVisible = !_passVisible),
                      ),
                    ),
                  ),
                ],

                // ── Error ────────────────────────────────────────────────────
                if (_error != null) ...[
                  const SizedBox(height: 12),
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

                // ── Success ──────────────────────────────────────────────────
                if (_savedPath != null) ...[
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A2A0A),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFF30D158)),
                    ),
                    child: Row(
                      children: [
                        const Icon(
                          Icons.check_circle_outline,
                          size: 16,
                          color: Color(0xFF30D158),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Saved to $_savedPath',
                            style: const TextStyle(
                              fontSize: 12,
                              color: Color(0xFF30D158),
                              fontFamily: 'monospace',
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],

                const SizedBox(height: 20),

                // ── Export button ────────────────────────────────────────────
                FilledButton.icon(
                  onPressed: _canExport ? _doExport : null,
                  style: FilledButton.styleFrom(
                    backgroundColor: _format == _ExportFormat.pgpPrivate
                        ? const Color(0xFFFF9F0A)
                        : const Color(0xFF0A84FF),
                    minimumSize: const Size.fromHeight(44),
                    disabledBackgroundColor: const Color(0xFF2C2C2E),
                  ),
                  icon: _busy
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : Icon(
                          _format == _ExportFormat.pgpPrivate
                              ? Icons.lock_open_outlined
                              : Icons.upload_outlined,
                          size: 18,
                        ),
                  label: Text(
                    _format == _ExportFormat.pgpPrivate
                        ? 'Export private key…'
                        : 'Export public key…',
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

// ── Format tile ───────────────────────────────────────────────────────────────

class _FormatTile extends StatelessWidget {
  const _FormatTile({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.selected,
    required this.onTap,
    this.danger = false,
  });

  final String title;
  final String subtitle;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;
  final bool danger;

  @override
  Widget build(BuildContext context) {
    final accent =
        danger ? const Color(0xFFFF9F0A) : const Color(0xFF0A84FF);
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: selected
              ? accent.withValues(alpha: 0.1)
              : const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: selected ? accent : const Color(0xFF3A3A3C),
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              icon,
              size: 20,
              color: selected ? accent : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                      color: selected ? accent : null,
                    ),
                  ),
                  Text(
                    subtitle,
                    style: const TextStyle(
                      fontSize: 12,
                      color: Color(0xFF8E8E93),
                    ),
                  ),
                ],
              ),
            ),
            if (selected)
              Icon(Icons.check_circle, size: 18, color: accent),
          ],
        ),
      ),
    );
  }
}
