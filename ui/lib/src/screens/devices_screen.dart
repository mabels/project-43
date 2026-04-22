import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;
import 'settings/authority_section.dart';
import '../services/notification_service.dart';
import '../services/settings_service.dart';
import '../services/window_service.dart';

class DevicesScreen extends StatefulWidget {
  const DevicesScreen({
    super.key,
    this.onCsrRequest,
    this.busStream,
    this.sessionLockStream,
    this.unlockRequestStream,
    this.externalLockStream,
    this.onSessionUnlocked,
    this.sessionUnlockKey,
  });

  /// Called when an incoming CSR arrives so the shell can switch to this tab.
  final VoidCallback? onCsrRequest;

  /// Broadcast stream of bus CSR events routed by the root shell's single
  /// [mxListenAll] subscription.  When provided, this screen never starts
  /// its own Matrix listener.
  final Stream<rust.BusCsrEvent>? busStream;

  /// Fires whenever a [BusSecure] message arrives but the authority session is
  /// locked.  The screen will animate to the Authority tab so the user can
  /// unlock and shows an OS notification.
  final Stream<void>? sessionLockStream;

  /// Fires when the user taps the global AppBar lock button while the session
  /// is locked.  Same behaviour as [sessionLockStream] but without the OS
  /// notification — the user is already looking at the screen.
  final Stream<void>? unlockRequestStream;

  /// Fires whenever the session is locked externally (AppBar lock button,
  /// screen-lock lifecycle).  Forwarded to [SessionUnlockTile] so its visual
  /// stays in sync with the root shell's lock icon.
  final Stream<void>? externalLockStream;

  /// Called after the user successfully unlocks the authority session so the
  /// root shell can refresh the global lock icon.
  final VoidCallback? onSessionUnlocked;

  /// Optional external key for [SessionUnlockTile].  Pass this from the root
  /// shell so it can imperatively call [SessionUnlockTileState.openUnlockDialog]
  /// from the global AppBar lock button.
  final GlobalKey<SessionUnlockTileState>? sessionUnlockKey;

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabCtrl;

  // ── Room + listener state ─────────────────────────────────────────────────
  String? _agentRoom;
  StreamSubscription<rust.BusCsrEvent>? _busSub;
  StreamSubscription<void>? _sessionLockSub;
  StreamSubscription<void>? _unlockRequestSub;

  // Key used to imperatively open the session unlock dialog from outside
  // the SessionUnlockTile widget when a BusSecure message arrives while locked.
  // Prefer the external key passed via widget.sessionUnlockKey (root shell holds
  // it so the global AppBar lock button can also trigger the dialog).
  late final GlobalKey<SessionUnlockTileState> _sessionUnlockKey;

  // ── Registered devices ────────────────────────────────────────────────────
  List<rust.BusPeer> _peers = [];
  bool _loadingPeers = false;

  // ── Approval serialisation ────────────────────────────────────────────────
  // Only one approval dialog at a time; queue the rest.
  final List<rust.BusCsrEvent> _pendingQueue = [];
  bool _approvalInFlight = false;

  @override
  void initState() {
    _sessionUnlockKey =
        widget.sessionUnlockKey ?? GlobalKey<SessionUnlockTileState>();
    super.initState();
    _tabCtrl = TabController(length: 2, vsync: this, initialIndex: 1);
    _loadAgentRoom();
    _loadPeers();
    _subscribeToStream();
    _subscribeToSessionLock();
    _subscribeToUnlockRequest();
  }

  @override
  void dispose() {
    _busSub?.cancel();
    _sessionLockSub?.cancel();
    _unlockRequestSub?.cancel();
    _tabCtrl.dispose();
    super.dispose();
  }

  // ── Room ──────────────────────────────────────────────────────────────────

  /// Load the saved agent room ID so we know where to send CSR responses.
  /// Does NOT start a Matrix listener — that is owned by the root shell.
  Future<void> _loadAgentRoom() async {
    try {
      final room = await rust.mxGetAgentRoom();
      if (!mounted || room == null || room == _agentRoom) return;
      setState(() => _agentRoom = room);
    } catch (_) {}
  }

  // ── Stream subscription ───────────────────────────────────────────────────

  /// Subscribe once to the root shell's broadcast stream.
  void _subscribeToStream() {
    final stream = widget.busStream;
    if (stream == null) return;
    _busSub = stream.listen(
      (event) {
        if (!mounted) return;
        // Deduplicate across reconnects.
        if (_pendingQueue.any((e) => e.requestId == event.requestId)) return;
        _pendingQueue.add(event);
        _drainQueue();
      },
      onError: (_) {},
      onDone: () {},
    );
  }

  // ── Session-lock navigation ───────────────────────────────────────────────

  /// When the root shell emits a session-lock signal, animate to the Authority
  /// tab (index 0) and open the unlock dialog once the animation has settled.
  void _subscribeToSessionLock() {
    final stream = widget.sessionLockStream;
    if (stream == null) return;
    _sessionLockSub = stream.listen(
      (_) {
        if (!mounted) return;
        _tabCtrl.animateTo(0);
        NotificationService.instance.show(
          title: 'Session locked',
          body: 'Unlock the authority session to process the encrypted request.',
          stableId: 'session_lock_required',
          channelId: 'p43_session_lock',
          channelName: 'Session lock',
          channelDescription:
              'Notifications when the authority session must be unlocked',
        );
        WindowService.instance.bringToFront();
        // Open the unlock dialog after the tab animation completes and the
        // SessionUnlockTile is guaranteed to be in the widget tree.
        // Flutter's default tab animation is 300 ms; 350 ms gives a buffer.
        Future.delayed(const Duration(milliseconds: 350), () {
          _sessionUnlockKey.currentState?.openUnlockDialog();
        });
      },
      onError: (_) {},
      onDone: () {},
    );
  }

  /// When the root shell emits a user-initiated unlock request (AppBar lock
  /// button tapped while locked), animate to the Authority tab and open the
  /// dialog — same as [_subscribeToSessionLock] but without the OS notification.
  void _subscribeToUnlockRequest() {
    final stream = widget.unlockRequestStream;
    if (stream == null) return;
    _unlockRequestSub = stream.listen(
      (_) {
        if (!mounted) return;
        _tabCtrl.animateTo(0);
        Future.delayed(const Duration(milliseconds: 350), () {
          if (!mounted) return;
          _sessionUnlockKey.currentState?.openUnlockDialog();
        });
      },
      onError: (_) {},
      onDone: () {},
    );
  }

  // ── Approval queue ────────────────────────────────────────────────────────

  void _drainQueue() {
    if (_approvalInFlight || _pendingQueue.isEmpty || !mounted) return;
    final event = _pendingQueue.removeAt(0);
    _approvalInFlight = true;
    // Notify the user, switch to the Devices tab, and bring the window up.
    NotificationService.instance.show(
      title: 'Approve device',
      body: event.deviceLabel.isNotEmpty ? event.deviceLabel : event.deviceId,
      stableId: event.deviceId,
      channelId: 'p43_csr_requests',
      channelName: 'Device approvals',
      channelDescription:
          'Notifications for incoming device registration requests',
    );
    _tabCtrl.animateTo(1);
    widget.onCsrRequest?.call();
    WindowService.instance.bringToFront();
    // Give the tab animation a frame to settle before showing the dialog.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _showApprovalDialog(event);
    });
  }

  Future<void> _showApprovalDialog(rust.BusCsrEvent event) async {
    final roomId = _agentRoom;
    if (roomId == null) {
      _approvalInFlight = false;
      _drainQueue();
      return;
    }

    List<rust.KeySealStatus> sealedKeys;
    try {
      sealedKeys = await rust.busAuthorityKeySealStatus();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load authority keys: $e')),
        );
      }
      _approvalInFlight = false;
      _drainQueue();
      return;
    }
    if (!mounted) {
      _approvalInFlight = false;
      return;
    }

    final approved = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _CsrApprovalDialog(
        event: event,
        sealedKeys: sealedKeys,
        onConfirm: (useCard, fp, pin, passphrase) async {
          final ttlDays = SettingsService.instance.settings.deviceCertTtlDays;
          final ttlSecs = ttlDays > 0 ? ttlDays * 24 * 60 * 60 : null;
          await rust.mxRespondCsr(
            roomId: roomId,
            requestId: event.requestId,
            csrB64: event.csrB64,
            ttlSecs: ttlSecs,
            useCard: useCard,
            fingerprint: fp,
            pin: pin,
            passphrase: passphrase,
          );
        },
      ),
    );

    _approvalInFlight = false;
    if (approved == true && mounted) _loadPeers();
    _drainQueue();
  }

  // ── Peers ─────────────────────────────────────────────────────────────────

  Future<void> _loadPeers() async {
    setState(() => _loadingPeers = true);
    try {
      final peers = await rust.busListPeers();
      if (mounted) {
        setState(() {
          _peers = peers;
          _loadingPeers = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _loadingPeers = false);
    }
  }

  Future<void> _removePeer(rust.BusPeer peer) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'Remove device',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        content: Text(
          'Remove "${peer.label}" (${peer.deviceId})?\n\n'
          'This device will no longer be trusted by the authority. '
          'It will need to re-register to be approved again.',
          style: const TextStyle(fontSize: 13),
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
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await rust.busRemovePeer(deviceId: peer.deviceId);
      if (mounted) _loadPeers();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to remove device: $e')));
      }
    }
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text('Devices'),
        bottom: TabBar(
          controller: _tabCtrl,
          tabs: const [
            Tab(text: 'Authority'),
            Tab(text: 'Devices'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabCtrl,
        children: [
          _AuthorityTab(
            sessionUnlockKey: _sessionUnlockKey,
            onSessionUnlocked: widget.onSessionUnlocked,
            externalLockStream: widget.externalLockStream,
          ),
          _DevicesTab(
            peers: _peers,
            loading: _loadingPeers,
            onRefresh: _loadPeers,
            onRemove: _removePeer,
          ),
        ],
      ),
    );
  }
}

// ── Authority tab ─────────────────────────────────────────────────────────────

class _AuthorityTab extends StatelessWidget {
  const _AuthorityTab({
    this.sessionUnlockKey,
    this.onSessionUnlocked,
    this.externalLockStream,
  });

  final GlobalKey<SessionUnlockTileState>? sessionUnlockKey;
  final VoidCallback? onSessionUnlocked;
  final Stream<void>? externalLockStream;

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        const AuthorityStatusTile(),
        const SizedBox(height: 1),
        SessionUnlockTile(
          key: sessionUnlockKey,
          onUnlocked: onSessionUnlocked,
          externalLockStream: externalLockStream,
        ),
        const SizedBox(height: 1),
        const AuthorityQrTile(),
        const SizedBox(height: 1),
        const AuthorityResealTile(),
        const SizedBox(height: 1),
        const AuthorityExportTile(),
        const SizedBox(height: 1),
        const AuthorityImportTile(),
        const SizedBox(height: 32),
      ],
    );
  }
}

// ── Devices tab ───────────────────────────────────────────────────────────────

class _DevicesTab extends StatelessWidget {
  const _DevicesTab({
    required this.peers,
    required this.loading,
    required this.onRefresh,
    required this.onRemove,
  });

  final List<rust.BusPeer> peers;
  final bool loading;
  final VoidCallback onRefresh;
  final Future<void> Function(rust.BusPeer) onRemove;

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 8, 8),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  'Registered Devices',
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                    color: const Color(0xFF8E8E93),
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.4,
                  ),
                ),
              ),
              if (loading)
                const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 12),
                  child: SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                )
              else
                IconButton(
                  icon: const Icon(Icons.refresh, size: 18),
                  tooltip: 'Refresh',
                  visualDensity: VisualDensity.compact,
                  onPressed: onRefresh,
                ),
            ],
          ),
        ),
        if (!loading && peers.isEmpty)
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 4, 16, 8),
            child: Text(
              'No registered devices yet.',
              style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            ),
          )
        else
          for (final peer in peers)
            _PeerTile(
              key: ValueKey(peer.deviceId),
              peer: peer,
              onRemove: () => onRemove(peer),
            ),
        const SizedBox(height: 32),
      ],
    );
  }
}

// ── Registered peer tile ──────────────────────────────────────────────────────

class _PeerTile extends StatelessWidget {
  const _PeerTile({super.key, required this.peer, required this.onRemove});

  final rust.BusPeer peer;
  final VoidCallback onRemove;

  String _formatDate(PlatformInt64 ts) {
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts * 1000,
      isUtc: true,
    ).toLocal();
    return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-'
        '${dt.day.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final expiry = peer.expiresAt;
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: const Icon(
        Icons.verified_user_outlined,
        size: 20,
        color: Color(0xFF30D158),
      ),
      title: Text(
        peer.label.isNotEmpty ? peer.label : peer.deviceId,
        style: const TextStyle(fontSize: 15),
      ),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            peer.deviceId,
            style: const TextStyle(
              fontSize: 10,
              fontFamily: 'monospace',
              color: Color(0xFF8E8E93),
            ),
          ),
          Text(
            'Issued ${_formatDate(peer.issuedAt)}'
            '${expiry != null ? ' · Expires ${_formatDate(expiry)}' : ' · No expiry'}',
            style: const TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
          ),
        ],
      ),
      trailing: TextButton(
        onPressed: onRemove,
        style: TextButton.styleFrom(
          foregroundColor: const Color(0xFFFF453A),
          visualDensity: VisualDensity.compact,
        ),
        child: const Text('Remove', style: TextStyle(fontSize: 13)),
      ),
    );
  }
}

// ── CSR approval dialog ───────────────────────────────────────────────────────

class _CsrApprovalDialog extends StatefulWidget {
  const _CsrApprovalDialog({
    required this.event,
    required this.sealedKeys,
    required this.onConfirm,
  });

  final rust.BusCsrEvent event;
  final List<rust.KeySealStatus> sealedKeys;
  final Future<void> Function(
    bool useCard,
    String? fingerprint,
    String? pin,
    String? passphrase,
  )
  onConfirm;

  @override
  State<_CsrApprovalDialog> createState() => _CsrApprovalDialogState();
}

class _CsrApprovalDialogState extends State<_CsrApprovalDialog> {
  String? _selectedFp;
  final _credCtrl = TextEditingController();
  bool _obscure = true;
  Timer? _obscureTimer;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    if (widget.sealedKeys.isNotEmpty) {
      final dfp = SettingsService.instance.settings.defaultKeyFingerprint;
      final hasDefault = dfp != null &&
          widget.sealedKeys.any((k) => k.fingerprint == dfp);
      _selectedFp =
          hasDefault ? dfp : widget.sealedKeys.first.fingerprint;
    }
  }

  @override
  void dispose() {
    _obscureTimer?.cancel();
    _credCtrl.dispose();
    super.dispose();
  }

  void _toggleObscure() {
    _obscureTimer?.cancel();
    if (_obscure) {
      setState(() => _obscure = false);
      _obscureTimer = Timer(const Duration(seconds: 10), () {
        if (mounted) setState(() => _obscure = true);
      });
    } else {
      _obscureTimer = null;
      setState(() => _obscure = true);
    }
  }

  void _resetObscure() {
    _obscureTimer?.cancel();
    _obscureTimer = null;
    if (mounted && !_obscure) setState(() => _obscure = true);
  }

  rust.KeySealStatus? get _selectedKey => _selectedFp == null
      ? null
      : widget.sealedKeys
            .where((k) => k.fingerprint == _selectedFp)
            .firstOrNull;

  bool get _isCard => _selectedKey?.hasCard ?? false;

  @override
  Widget build(BuildContext context) {
    final credLabel = _isCard ? 'YubiKey PIN' : 'Passphrase';
    return AlertDialog(
      backgroundColor: const Color(0xFF2C2C2E),
      title: Row(
        children: [
          const Expanded(
            child: Text(
              'Approve device',
              style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
            ),
          ),
          if (_busy) ...[
            const SizedBox(width: 10),
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          ],
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Device info ─────────────────────────────────────────
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              margin: const EdgeInsets.only(bottom: 14),
              decoration: BoxDecoration(
                color: const Color(0xFF1C1C1E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF3A3A3C)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(
                        Icons.devices_outlined,
                        size: 14,
                        color: Color(0xFF0A84FF),
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          widget.event.deviceLabel.isNotEmpty
                              ? widget.event.deviceLabel
                              : 'Unknown device',
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    widget.event.deviceId,
                    style: const TextStyle(
                      fontSize: 10,
                      fontFamily: 'monospace',
                      color: Color(0xFF8E8E93),
                    ),
                  ),
                ],
              ),
            ),
            const Text(
              'Unlock the authority key to sign the device certificate:',
              style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            ),
            const SizedBox(height: 14),
            // ── Key picker ──────────────────────────────────────────
            if (widget.sealedKeys.isNotEmpty) ...[
              const Text(
                'UNLOCK WITH',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Color(0xFF8E8E93),
                  letterSpacing: 0.5,
                ),
              ),
              const SizedBox(height: 4),
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1C1C1E),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF3A3A3C)),
                ),
                child: Column(
                  children: [
                    for (var i = 0; i < widget.sealedKeys.length; i++) ...[
                      if (i > 0)
                        const Divider(height: 1, indent: 12, endIndent: 12),
                      _KeyPickerRow(
                        status: widget.sealedKeys[i],
                        selected:
                            _selectedFp == widget.sealedKeys[i].fingerprint,
                        enabled: !_busy,
                        onTap: _busy
                            ? null
                            : () {
                                _obscureTimer?.cancel();
                                _obscureTimer = null;
                                setState(() {
                                  _selectedFp =
                                      widget.sealedKeys[i].fingerprint;
                                  _credCtrl.clear();
                                  _error = null;
                                  _obscure = true;
                                });
                              },
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 12),
            ],
            // ── Credential input ────────────────────────────────────
            Text(
              credLabel.toUpperCase(),
              style: const TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: Color(0xFF8E8E93),
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 4),
            TextField(
              key: ValueKey(_isCard),
              controller: _credCtrl,
              obscureText: _obscure,
              autofocus: true,
              enabled: !_busy,
              style: const TextStyle(fontSize: 14),
              keyboardType: _isCard ? TextInputType.number : TextInputType.text,
              decoration: InputDecoration(
                hintText: '••••••',
                hintStyle: const TextStyle(color: Color(0xFF8E8E93)),
                filled: true,
                fillColor: const Color(0xFF1C1C1E),
                border: const OutlineInputBorder(borderSide: BorderSide.none),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 8,
                ),
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscure
                        ? Icons.visibility_outlined
                        : Icons.visibility_off_outlined,
                    size: 18,
                    color: const Color(0xFF8E8E93),
                  ),
                  onPressed: _busy ? null : _toggleObscure,
                ),
              ),
              onSubmitted: _busy
                  ? null
                  : (_) {
                      _resetObscure();
                      _submit();
                    },
            ),
            // ── Inline error ────────────────────────────────────────
            if (_error != null) ...[
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF3A0A0A),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFFF453A)),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.error_outline,
                      size: 14,
                      color: Color(0xFFFF453A),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _error!,
                        style: const TextStyle(
                          fontSize: 12,
                          color: Color(0xFFFF453A),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.pop(context, false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _busy ? null : _submit,
          style: FilledButton.styleFrom(
            backgroundColor: const Color(0xFF0A84FF),
          ),
          child: const Text('Approve'),
        ),
      ],
    );
  }

  Future<void> _submit() async {
    _resetObscure();
    final cred = _credCtrl.text.isEmpty ? null : _credCtrl.text;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.onConfirm(
        _isCard,
        _selectedFp, // always pass: card uses it for AID lookup, soft-key for key file
        _isCard ? cred : null,
        _isCard ? null : cred,
      );
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = e.toString();
        });
      }
    }
  }
}

// ── Key picker row ────────────────────────────────────────────────────────────

class _KeyPickerRow extends StatelessWidget {
  const _KeyPickerRow({
    required this.status,
    required this.selected,
    required this.enabled,
    required this.onTap,
  });

  final rust.KeySealStatus status;
  final bool selected;
  final bool enabled;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: enabled ? onTap : null,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        color: Colors.transparent,
        child: Row(
          children: [
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_off,
              size: 16,
              color: selected
                  ? const Color(0xFF0A84FF)
                  : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                status.uid,
                style: TextStyle(
                  fontSize: 13,
                  color: selected ? null : const Color(0xFF8E8E93),
                  fontWeight: selected ? FontWeight.w500 : FontWeight.normal,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            if (status.hasCard)
              const Padding(
                padding: EdgeInsets.only(left: 6),
                child: Icon(
                  Icons.credit_card,
                  size: 14,
                  color: Color(0xFF8E8E93),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
