import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart'
    show sshAgentIsRunning, sshAgentSocketPath, sshAgentStart, sshAgentStop;
import '../../services/settings_service.dart';
import 'shared_widgets.dart';

// ── Cache-timeout tile ────────────────────────────────────────────────────────

class SettingsTimeoutTile extends StatelessWidget {
  const SettingsTimeoutTile({
    super.key,
    required this.current,
    required this.onChanged,
  });

  final int? current;
  final ValueChanged<int?> onChanged;

  static const _options = <(int?, String)>[
    (null, 'Never'),
    (1, '1 minute'),
    (5, '5 minutes'),
    (15, '15 minutes'),
    (30, '30 minutes'),
    (60, '1 hour'),
  ];

  String get _label => _options
      .firstWhere((e) => e.$1 == current, orElse: () => (null, 'Never'))
      .$2;

  void _pick(BuildContext context) {
    showDialog<int?>(
      context: context,
      builder: (ctx) => SimpleDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'Cache timeout',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        children: _options
            .map(
              (opt) => RadioListTile<int?>(
                value: opt.$1,
                groupValue: current,
                title: Text(opt.$2, style: const TextStyle(fontSize: 14)),
                activeColor: const Color(0xFF0A84FF),
                onChanged: (v) {
                  Navigator.pop(ctx);
                  onChanged(v);
                },
              ),
            )
            .toList(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      title: const Text('Cache timeout', style: TextStyle(fontSize: 15)),
      subtitle: const Text(
        'Clear credentials after last sign',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            _label,
            style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
          ),
          const SizedBox(width: 4),
          const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
        ],
      ),
      onTap: () => _pick(context),
    );
  }
}

// ── Desktop SSH-agent section ─────────────────────────────────────────────────

/// Shows the in-process SSH agent toggle on macOS and Linux.
/// Returns [SizedBox.shrink] on other platforms.
class DesktopAgentSection extends StatefulWidget {
  const DesktopAgentSection({super.key});

  @override
  State<DesktopAgentSection> createState() => _DesktopAgentSectionState();
}

class _DesktopAgentSectionState extends State<DesktopAgentSection> {
  final TextEditingController _labelCtrl = TextEditingController();
  String? _socketPath;
  bool _running = false;

  @override
  void initState() {
    super.initState();
    final s = SettingsService.instance.settings;
    _labelCtrl.text = s.desktopAgentLabel ?? '';
    _refresh();
  }

  @override
  void dispose() {
    _labelCtrl.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    if (!Platform.isMacOS && !Platform.isLinux) return;
    try {
      final running = await sshAgentIsRunning();
      final path = running ? await sshAgentSocketPath() : null;
      if (mounted) setState(() {
        _running = running;
        _socketPath = path;
      });
    } catch (_) {}
  }

  Future<void> _onToggle(bool value) async {
    final s = SettingsService.instance.settings;
    await SettingsService.instance.save(
      s.copyWith(desktopAgentEnabled: value),
    );
    // Give Rust a moment to start/stop then refresh status.
    await Future<void>.delayed(const Duration(milliseconds: 400));
    await _refresh();
  }

  Future<void> _onLabelChanged(String value) async {
    final s = SettingsService.instance.settings;
    final label = value.trim().isEmpty ? null : value.trim();
    await SettingsService.instance.save(
      s.copyWith(desktopAgentLabel: label),
    );
  }

  void _copySocket() {
    if (_socketPath == null) return;
    Clipboard.setData(ClipboardData(text: _socketPath!));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Socket path copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (!Platform.isMacOS && !Platform.isLinux) return const SizedBox.shrink();

    final s = SettingsService.instance.settings;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SettingsToggleTile(
          title: 'In-process SSH agent',
          subtitle: _running
              ? 'SSH agent is running — set SSH_AUTH_SOCK to the path below.'
              : 'Start an SSH agent inside this app. No separate process needed.',
          value: s.desktopAgentEnabled,
          onChanged: _onToggle,
        ),
        if (s.desktopAgentEnabled) ...[
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: TextField(
              controller: _labelCtrl,
              style: const TextStyle(fontSize: 14),
              decoration: InputDecoration(
                filled: true,
                fillColor: const Color(0xFF2C2C2E),
                labelText: 'Device label (optional)',
                hintText: 'hostname default',
                hintStyle: const TextStyle(
                  fontSize: 13,
                  color: Color(0xFF8E8E93),
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none,
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
              ),
              onSubmitted: _onLabelChanged,
              onEditingComplete: () => _onLabelChanged(_labelCtrl.text),
            ),
          ),
          if (_socketPath != null) ...[
            const SizedBox(height: 8),
            ListTile(
              tileColor: const Color(0xFF2C2C2E),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 2,
              ),
              leading: Icon(
                Icons.cable_outlined,
                size: 18,
                color: _running
                    ? const Color(0xFF30D158)
                    : const Color(0xFF8E8E93),
              ),
              title: const Text(
                'SSH_AUTH_SOCK',
                style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
              ),
              subtitle: Text(
                _socketPath!,
                style: const TextStyle(
                  fontSize: 12,
                  fontFamily: 'Menlo',
                  color: Color(0xFFE5E5EA),
                ),
              ),
              trailing: IconButton(
                icon: const Icon(Icons.copy_outlined, size: 16),
                color: const Color(0xFF8E8E93),
                tooltip: 'Copy path',
                onPressed: _copySocket,
              ),
            ),
          ],
          if (s.desktopAgentEnabled && !_running)
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 6, 16, 0),
              child: Text(
                'Agent will start automatically once Matrix connects.',
                style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
              ),
            ),
        ],
      ],
    );
  }
}
