import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart';

// ── Section label ─────────────────────────────────────────────────────────────

class KeySectionLabel extends StatelessWidget {
  const KeySectionLabel(this.label, {super.key});
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

// ── Badge ─────────────────────────────────────────────────────────────────────

class KeyBadge extends StatelessWidget {
  const KeyBadge({
    super.key,
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

// ── Label ─────────────────────────────────────────────────────────────────────

class KeyLabel extends StatelessWidget {
  const KeyLabel(this.text, {super.key});
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

// ── Copyable block ────────────────────────────────────────────────────────────

class KeyCopyableBlock extends StatelessWidget {
  const KeyCopyableBlock({super.key, required this.label, required this.value});

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
                letterSpacing: 0.4,
              ),
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

// ── Role style ────────────────────────────────────────────────────────────────

/// Maps a raw role string like `"certify"`, `"sign"`, `"auth"`, `"encrypt"`
/// to a display-friendly label and colour.
(String label, Color color) keyRoleStyle(String role) {
  if (role.contains('auth')) return ('AUTH', const Color(0xFF0A84FF));
  if (role.contains('sign') && role.contains('certify')) {
    return ('CERTIFY+SIGN', const Color(0xFFF5A623));
  }
  if (role.contains('sign')) return ('SIGN', const Color(0xFFF5A623));
  if (role.contains('certify')) return ('CERTIFY', const Color(0xFF8E8E93));
  if (role.contains('encrypt')) return ('ENCRYPT', const Color(0xFF30D158));
  return (role.toUpperCase(), const Color(0xFF8E8E93));
}

// ── Subkey row ────────────────────────────────────────────────────────────────

class KeySubkeyRow extends StatelessWidget {
  const KeySubkeyRow({
    super.key,
    required this.subkey,
    required this.selected,
    required this.onTap,
  });

  final SubkeyInfo subkey;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final (label, color) = keyRoleStyle(subkey.role);

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
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
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
              const Icon(
                Icons.chevron_right,
                size: 14,
                color: Color(0xFF0A84FF),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ── Key summary ───────────────────────────────────────────────────────────────

class KeySummary extends StatelessWidget {
  const KeySummary({super.key, required this.info});
  final KeyInfo info;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          info.uid,
          style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
        ),
        const SizedBox(height: 3),
        Text(
          info.fingerprint,
          style: TextStyle(
            fontFamily: 'monospace',
            fontSize: 10,
            color: cs.onSurface.withValues(alpha: 0.5),
          ),
        ),
      ],
    );
  }
}
