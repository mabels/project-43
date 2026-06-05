import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

// ── Export sheet ──────────────────────────────────────────────────────────────

/// Export public key material from a wallet credential.
///
/// Offers:
///   • OpenPGP public key  (.asc) — when [pgpArmored] is non-empty
///   • OpenSSH public key  (.pub) — when the selected subkey has an openssh_key
class WalletKeyExportSheet extends StatefulWidget {
  const WalletKeyExportSheet({
    super.key,
    required this.uid,
    required this.pgpArmored,
    required this.opensshKey,
  });

  /// Human-readable label / UID — used as the default filename base.
  final String uid;

  /// Armored OpenPGP public key, or empty string when not applicable (e.g. YubiKey).
  final String pgpArmored;

  /// OpenSSH `authorized_keys` line for the selected subkey, or null.
  final String? opensshKey;

  @override
  State<WalletKeyExportSheet> createState() => _WalletKeyExportSheetState();
}

enum _ExportFmt { pgpPublic, sshPublic }

class _WalletKeyExportSheetState extends State<WalletKeyExportSheet> {
  late _ExportFmt _fmt;
  bool _busy = false;
  String? _error;
  String? _savedPath;

  @override
  void initState() {
    super.initState();
    // Default to whichever is available — prefer PGP if both present.
    _fmt = widget.pgpArmored.isNotEmpty
        ? _ExportFmt.pgpPublic
        : _ExportFmt.sshPublic;
  }

  bool get _hasPgp => widget.pgpArmored.isNotEmpty;
  bool get _hasSsh => widget.opensshKey != null;

  String get _content => _fmt == _ExportFmt.pgpPublic
      ? widget.pgpArmored
      : widget.opensshKey ?? '';

  Future<void> _doExport() async {
    setState(() { _busy = true; _error = null; _savedPath = null; });
    try {
      final base = widget.uid.replaceAll(RegExp(r'[^\w@.+-]'), '_');
      final (defaultName, ext) = _fmt == _ExportFmt.pgpPublic
          ? ('${base}_pub.asc', 'asc')
          : ('$base.pub', 'pub');

      final savePath = await FilePicker.saveFile(
        dialogTitle: 'Export public key…',
        fileName: defaultName,
        type: FileType.custom,
        allowedExtensions: [ext],
      );

      if (savePath == null) { setState(() => _busy = false); return; }

      final out = savePath.endsWith('.$ext') ? savePath : '$savePath.$ext';
      await File(out).writeAsString(_content);
      setState(() { _savedPath = out; _busy = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _busy = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.45,
      minChildSize: 0.35,
      maxChildSize: 0.7,
      builder: (_, ctrl) => Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Container(
              width: 36, height: 4,
              decoration: BoxDecoration(
                  color: const Color(0xFF8E8E93),
                  borderRadius: BorderRadius.circular(2)),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Row(
              children: [
                const Icon(Icons.upload_outlined, size: 18),
                const SizedBox(width: 8),
                const Text('Export public key',
                    style: TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w600)),
                const Spacer(),
                if (_busy)
                  const SizedBox(
                      width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2)),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
              children: [
                // ── Format selector ─────────────────────────────────────────
                if (_hasPgp)
                  _FormatTile(
                    label: 'OpenPGP public key',
                    subtitle: '.asc — paste into keyservers or share as file',
                    icon: Icons.lock_outlined,
                    selected: _fmt == _ExportFmt.pgpPublic,
                    onTap: () => setState(() => _fmt = _ExportFmt.pgpPublic),
                  ),
                if (_hasPgp && _hasSsh) const SizedBox(height: 8),
                if (_hasSsh)
                  _FormatTile(
                    label: 'OpenSSH public key',
                    subtitle: '.pub — paste into authorized_keys',
                    icon: Icons.terminal,
                    selected: _fmt == _ExportFmt.sshPublic,
                    onTap: () => setState(() => _fmt = _ExportFmt.sshPublic),
                  ),

                // ── Status ──────────────────────────────────────────────────
                if (_savedPath != null) ...[
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      const Icon(Icons.check_circle_outline,
                          size: 16, color: Color(0xFF30D158)),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          'Saved to ${_savedPath!.split('/').last}',
                          style: const TextStyle(
                              fontSize: 12, color: Color(0xFF30D158)),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ],
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(_error!,
                      style: const TextStyle(
                          fontSize: 12, color: Color(0xFFFF453A))),
                ],
                const SizedBox(height: 20),

                // ── Export button ────────────────────────────────────────────
                FilledButton.icon(
                  onPressed: (!_busy && (_hasPgp || _hasSsh))
                      ? _doExport
                      : null,
                  style: FilledButton.styleFrom(
                    backgroundColor: const Color(0xFF0A84FF),
                    minimumSize: const Size.fromHeight(44),
                  ),
                  icon: const Icon(Icons.save_alt_outlined, size: 18),
                  label: Text(_fmt == _ExportFmt.pgpPublic
                      ? 'Save .asc'
                      : 'Save .pub'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _FormatTile extends StatelessWidget {
  final String label;
  final String subtitle;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;
  const _FormatTile({
    required this.label,
    required this.subtitle,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 120),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          decoration: BoxDecoration(
            color: selected
                ? const Color(0xFF0A84FF).withValues(alpha: 0.1)
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
            children: [
              Icon(icon,
                  size: 18,
                  color: selected
                      ? const Color(0xFF0A84FF)
                      : const Color(0xFF8E8E93)),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(label,
                        style: TextStyle(
                            fontSize: 14,
                            fontWeight: selected
                                ? FontWeight.w600
                                : FontWeight.normal,
                            color: selected
                                ? const Color(0xFF0A84FF)
                                : null)),
                    const SizedBox(height: 2),
                    Text(subtitle,
                        style: const TextStyle(
                            fontSize: 11, color: Color(0xFF8E8E93))),
                  ],
                ),
              ),
              if (selected)
                const Icon(Icons.check_circle,
                    size: 18, color: Color(0xFF0A84FF)),
            ],
          ),
        ),
      );
}
