import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import '../key_helpers.dart';
import 'key_widgets.dart';

// ── Key card ──────────────────────────────────────────────────────────────────

class KeyCard extends StatelessWidget {
  const KeyCard({
    super.key,
    required this.info,
    this.onTap,
    this.isDefault = false,
    this.onSetDefault,
  });

  final KeyInfo info;
  final VoidCallback? onTap;
  final bool isDefault;
  final VoidCallback? onSetDefault;

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
                    const KeyBadge(
                      label: 'off',
                      color: Color(0xFF8E8E93),
                      background: Color(0xFF2C2C2E),
                    ),
                    const SizedBox(width: 6),
                  ],
                  if (info.cardIdents.isNotEmpty) ...[
                    Text(
                      cardnoFromIdent(info.cardIdents.first),
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 10,
                        color: Color(0xFF0A84FF),
                      ),
                    ),
                    const SizedBox(width: 8),
                  ],
                  KeyBadge(
                    label: info.hasSecret ? 'sec' : 'pub',
                    color: info.hasSecret
                        ? const Color(0xFFF5A623)
                        : const Color(0xFF30D158),
                    background: info.hasSecret
                        ? const Color(0xFF3A2A0A)
                        : const Color(0xFF1A2A1A),
                  ),
                  const SizedBox(width: 6),
                  GestureDetector(
                    onTap: isDefault ? null : onSetDefault,
                    child: Tooltip(
                      message: isDefault ? 'Default key' : 'Set as default',
                      child: Icon(
                        isDefault ? Icons.star : Icons.star_border,
                        size: 18,
                        color: isDefault
                            ? const Color(0xFFFFD60A)
                            : const Color(0xFF48484A),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  KeyLabel(info.algo),
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
