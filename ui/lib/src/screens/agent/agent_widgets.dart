import 'package:flutter/material.dart';
import '../key_helpers.dart';
import 'request_model.dart';

String _fmtTime(DateTime t) {
  final h = t.hour.toString().padLeft(2, '0');
  final m = t.minute.toString().padLeft(2, '0');
  final s = t.second.toString().padLeft(2, '0');
  return '$h:$m:$s';
}

// ── Room banner ───────────────────────────────────────────────────────────────

class AgentRoomBanner extends StatelessWidget {
  const AgentRoomBanner({
    super.key,
    required this.roomId,
    required this.listening,
    required this.onPick,
  });

  final String? roomId;
  final bool listening;
  final VoidCallback onPick;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onPick,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        color: const Color(0xFF2C2C2E),
        child: Row(
          children: [
            Icon(
              listening ? Icons.sensors : Icons.sensors_off,
              size: 18,
              color: listening
                  ? const Color(0xFF30D158)
                  : cs.onSurface.withValues(alpha: 0.4),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: roomId == null
                  ? Text(
                      'Tap to select a room',
                      style: TextStyle(
                        color: cs.onSurface.withValues(alpha: 0.5),
                        fontSize: 13,
                      ),
                    )
                  : Text(
                      roomId!,
                      style: const TextStyle(
                        fontSize: 12,
                        fontFamily: 'monospace',
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

// ── Log tile ──────────────────────────────────────────────────────────────────

class AgentLogTile extends StatelessWidget {
  const AgentLogTile({
    super.key,
    required this.entry,
    this.onApprove,
    this.onReject,
  });

  final RequestEntry entry;
  final VoidCallback? onApprove;
  final VoidCallback? onReject;

  void _showError(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Row(
          children: [
            Icon(Icons.error_outline, color: Color(0xFFFF453A), size: 18),
            SizedBox(width: 8),
            Text('Sign error', style: TextStyle(fontSize: 15)),
          ],
        ),
        content: SingleChildScrollView(
          child: SelectableText(
            entry.errorMessage ?? 'Unknown error',
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 11,
              color: Color(0xFFFF453A),
              height: 1.5,
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isSign = entry.type == 'ssh.sign_request';
    final isPending = entry.status == RequestStatus.pending;
    final isError = entry.status == RequestStatus.error;
    final hasErrorDetail = isError && entry.errorMessage != null;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: isPending && isSign
                ? const Color(0xFFFF9F0A)
                : isError
                ? const Color(0xFFFF453A).withValues(alpha: 0.4)
                : const Color(0xFF3A3A3C),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                AgentStatusDot(entry.status),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        entry.type,
                        style: const TextStyle(
                          fontSize: 12,
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (entry.keyName != null &&
                          entry.keyName!.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                keyLabel(entry.keyName!, entry.cardIdents),
                                style: const TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w500,
                                  color: Color(0xFFE5E5EA),
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (entry.keyAlgo != null &&
                                entry.keyAlgo!.isNotEmpty) ...[
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 5,
                                  vertical: 1,
                                ),
                                decoration: BoxDecoration(
                                  color: const Color(0xFF3A3A3C),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  entry.keyAlgo!,
                                  style: const TextStyle(
                                    fontSize: 9,
                                    fontFamily: 'monospace',
                                    color: Color(0xFF8E8E93),
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ],
                      if (entry.fingerprint != null)
                        Text(
                          entry.fingerprint!,
                          style: TextStyle(
                            fontSize: 10,
                            fontFamily: 'monospace',
                            color: cs.onSurface.withValues(alpha: 0.5),
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      if (entry.description != null)
                        Text(
                          entry.description!,
                          style: TextStyle(
                            fontSize: 11,
                            color: cs.onSurface.withValues(alpha: 0.55),
                          ),
                        ),
                      // ── Device meta (hostname + IP) ──────────────────────
                      if (entry.hostname.isNotEmpty ||
                          entry.primaryIp.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: Row(
                            children: [
                              const Icon(
                                Icons.computer_outlined,
                                size: 10,
                                color: Color(0xFF8E8E93),
                              ),
                              const SizedBox(width: 4),
                              Text(
                                [
                                  if (entry.hostname.isNotEmpty) entry.hostname,
                                  if (entry.primaryIp.isNotEmpty)
                                    entry.primaryIp,
                                ].join(' · '),
                                style: const TextStyle(
                                  fontSize: 10,
                                  color: Color(0xFF8E8E93),
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ),
                        ),
                      Text(
                        entry.requestId.substring(0, 8),
                        style: TextStyle(
                          fontSize: 10,
                          color: cs.onSurface.withValues(alpha: 0.35),
                          fontFamily: 'monospace',
                        ),
                      ),
                      if (entry.sourceLabel.isNotEmpty ||
                          entry.sourceDeviceId.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Row(
                          children: [
                            const Icon(
                              Icons.devices_other,
                              size: 10,
                              color: Color(0xFF636366),
                            ),
                            const SizedBox(width: 4),
                            Expanded(
                              child: Text(
                                entry.sourceLabel.isNotEmpty
                                    ? entry.sourceLabel
                                    : entry.sourceDeviceId,
                                style: const TextStyle(
                                  fontSize: 10,
                                  color: Color(0xFF636366),
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            if (entry.sourceLabel.isNotEmpty &&
                                entry.sourceDeviceId.isNotEmpty) ...[
                              const SizedBox(width: 4),
                              Text(
                                entry.sourceDeviceId,
                                style: const TextStyle(
                                  fontSize: 9,
                                  fontFamily: 'monospace',
                                  color: Color(0xFF48484A),
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ],
                        ),
                      ],
                    ],
                  ),
                ),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(
                      _fmtTime(entry.timestamp),
                      style: TextStyle(
                        fontSize: 10,
                        fontFamily: 'monospace',
                        color: Theme.of(
                          context,
                        ).colorScheme.onSurface.withValues(alpha: 0.35),
                      ),
                    ),
                    const SizedBox(height: 2),
                    AgentStatusLabel(entry.status),
                  ],
                ),
                if (hasErrorDetail) ...[
                  const SizedBox(width: 4),
                  GestureDetector(
                    onTap: () => _showError(context),
                    child: const Icon(
                      Icons.info_outline,
                      size: 16,
                      color: Color(0xFFFF453A),
                    ),
                  ),
                ],
              ],
            ),
            if (isSign && isPending) ...[
              const SizedBox(height: 8),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: onReject,
                    style: TextButton.styleFrom(
                      foregroundColor: const Color(0xFFFF453A),
                      visualDensity: VisualDensity.compact,
                    ),
                    child: const Text('Reject'),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: onApprove,
                    style: FilledButton.styleFrom(
                      backgroundColor: const Color(0xFF30D158),
                      foregroundColor: Colors.black,
                      visualDensity: VisualDensity.compact,
                    ),
                    child: const Text('Approve'),
                  ),
                ],
              ),
            ],
            // ── Meta detail (always shown for sign requests) ───────────────
            if (isSign && entry.meta.isNotEmpty) ...[
              const SizedBox(height: 8),
              MetaSection(
                meta: entry.meta,
                certMeta: entry.certMeta.isNotEmpty ? entry.certMeta : null,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ── Status dot ────────────────────────────────────────────────────────────────

class AgentStatusDot extends StatelessWidget {
  const AgentStatusDot(this.status, {super.key});
  final RequestStatus status;

  @override
  Widget build(BuildContext context) {
    final color = switch (status) {
      RequestStatus.pending => const Color(0xFFFF9F0A),
      RequestStatus.responding => const Color(0xFF0A84FF),
      RequestStatus.done => const Color(0xFF30D158),
      RequestStatus.error => const Color(0xFFFF453A),
    };
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(color: color, shape: BoxShape.circle),
    );
  }
}

// ── Status label ──────────────────────────────────────────────────────────────

class AgentStatusLabel extends StatelessWidget {
  const AgentStatusLabel(this.status, {super.key});
  final RequestStatus status;

  @override
  Widget build(BuildContext context) {
    final (label, color) = switch (status) {
      RequestStatus.pending => ('pending', const Color(0xFFFF9F0A)),
      RequestStatus.responding => ('responding', const Color(0xFF0A84FF)),
      RequestStatus.done => ('done', const Color(0xFF30D158)),
      RequestStatus.error => ('error', const Color(0xFFFF453A)),
    };
    return Text(
      label,
      style: TextStyle(fontSize: 10, color: color, fontFamily: 'monospace'),
    );
  }
}

// ── Meta section ──────────────────────────────────────────────────────────────

/// Collapsible device metadata section — shown in sign-request dialogs.
///
/// Renders all key-value pairs from [meta] sorted alphabetically.
/// Hidden when [meta] is empty.
class MetaSection extends StatefulWidget {
  const MetaSection({super.key, required this.meta, this.certMeta});
  final Map<String, String> meta;

  /// Optional cert/registration-time snapshot for comparison.
  /// When present, values that differ from [meta] are highlighted.
  final Map<String, String>? certMeta;

  @override
  State<MetaSection> createState() => _MetaSectionState();
}

class _MetaSectionState extends State<MetaSection> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    if (widget.meta.isEmpty) return const SizedBox.shrink();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        GestureDetector(
          onTap: () => setState(() => _expanded = !_expanded),
          child: Row(
            children: [
              const Icon(
                Icons.computer_outlined,
                size: 12,
                color: Color(0xFF8E8E93),
              ),
              const SizedBox(width: 4),
              const Text(
                'Device info',
                style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
              ),
              const Spacer(),
              Icon(
                _expanded ? Icons.expand_less : Icons.expand_more,
                size: 14,
                color: const Color(0xFF8E8E93),
              ),
            ],
          ),
        ),
        if (_expanded) ...[
          const SizedBox(height: 6),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: const Color(0xFF1C1C1E),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Column headers when cert meta is present.
                if (widget.certMeta != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Row(
                      children: const [
                        SizedBox(width: 110),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'live',
                            style: TextStyle(
                              fontSize: 9,
                              color: Color(0xFF8E8E93),
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        Expanded(
                          child: Text(
                            'cert',
                            style: TextStyle(
                              fontSize: 9,
                              color: Color(0xFF8E8E93),
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                // All keys from both snapshots, merged.
                ...() {
                  final cert = widget.certMeta;
                  final allKeys = {
                    ...widget.meta.keys,
                    if (cert != null) ...cert.keys,
                  }.toList()..sort();
                  return allKeys.map((key) {
                    final live = widget.meta[key];
                    final certVal = cert?[key];
                    final changed =
                        cert != null &&
                        live != null &&
                        certVal != null &&
                        live != certVal;
                    final missingInLive =
                        cert != null && live == null && certVal != null;
                    final newInLive =
                        cert != null && live != null && certVal == null;
                    final rowColor = changed
                        ? const Color(0xFFFF9F0A) // amber — value changed
                        : missingInLive
                        ? const Color(0xFFFF453A) // red — gone from live
                        : newInLive
                        ? const Color(0xFF30D158) // green — new in live
                        : const Color(0xFFD1D1D6);
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 1),
                      child: Row(
                        children: [
                          SizedBox(
                            width: 110,
                            child: Text(
                              key,
                              style: const TextStyle(
                                fontSize: 10,
                                fontFamily: 'monospace',
                                color: Color(0xFF8E8E93),
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              live ?? '—',
                              style: TextStyle(
                                fontSize: 10,
                                fontFamily: 'monospace',
                                color: rowColor,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (cert != null)
                            Expanded(
                              child: Text(
                                certVal ?? '—',
                                style: const TextStyle(
                                  fontSize: 10,
                                  fontFamily: 'monospace',
                                  color: Color(0xFF8E8E93),
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                        ],
                      ),
                    );
                  }).toList();
                }(),
              ],
            ),
          ),
        ],
      ],
    );
  }
}
