import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import '../services/notification_service.dart';
import '../services/settings_service.dart';
import '../services/window_service.dart';

class AgentScreen extends StatefulWidget {
  const AgentScreen({super.key, this.onSignRequest});

  /// Called when an `ssh.sign_request` arrives so the shell can switch to
  /// the Agent tab if it is not already in focus.
  final VoidCallback? onSignRequest;

  @override
  State<AgentScreen> createState() => _AgentScreenState();
}

class _AgentScreenState extends State<AgentScreen> {
  String? _agentRoom;
  final List<_RequestEntry> _log = [];
  bool _listening = false;

  @override
  void initState() {
    super.initState();
    _loadAgentRoom();
  }

  Future<void> _loadAgentRoom() async {
    final room = await mxGetAgentRoom();
    if (!mounted) return;
    if (room != _agentRoom) {
      setState(() => _agentRoom = room);
      if (room != null) _startListening(room);
    }
  }

  void _startListening(String roomId) {
    if (_listening) return;
    _listening = true;
    mxListenAgent(roomId: roomId).listen(
      (event) async {
        if (!mounted) return;
        if (event is AgentRequest_ListKeys) {
          setState(() => _log.insert(
                0,
                _RequestEntry(
                  type: 'ssh.list_keys_request',
                  requestId: event.requestId,
                  description: null,
                  fingerprint: null,
                  status: _RequestStatus.responding,
                ),
              ));
          _autoRespondListKeys(roomId, event.requestId);
        } else if (event is AgentRequest_Sign) {
          final fp = event.fingerprint;
          final autoApprove =
              SettingsService.instance.settings.autoApproveWhenCached;

          // Switch to the agent tab so the request is visible.
          widget.onSignRequest?.call();

          // Resolve key details first so we know whether it's a card key.
          final SshKeyDetails? details = fp.isNotEmpty
              ? await getSshKeyDetails(fingerprint: fp)
              : null;
          if (!mounted) return;

          // Check the appropriate cache depending on key type.
          final bool cached;
          if (!autoApprove) {
            cached = false;
          } else if (details != null && details.cardIdents.isNotEmpty) {
            // Card key — check PIN cache for any associated card ident.
            cached = await Future.any(
              details.cardIdents.map((id) => hasCachedCardPin(cardIdent: id)),
            ).then((v) => v).catchError((_) => false);
          } else if (fp.isNotEmpty) {
            cached = await hasCachedPassphrase(fingerprint: fp);
          } else {
            cached = false;
          }
          if (!mounted) return;

          // Emit notification if enabled in settings.
          if (SettingsService.instance.settings.notifyOnSignRequest) {
            final label = _keyLabel(details?.name ?? '', details?.cardIdents ?? []);
            NotificationService.instance.showSignRequest(
              keyLabel: label,
              algo: details?.algo ?? '',
              fingerprint: fp,
            );
          }

          final isCardKey = details != null && details.cardIdents.isNotEmpty;

          if (cached) {
            // Auto-approve: add as responding immediately, no tile shown to user.
            setState(() => _log.insert(
                  0,
                  _RequestEntry(
                    type: 'ssh.sign_request',
                    requestId: event.requestId,
                    description: event.description,
                    fingerprint: fp,
                    keyName: details?.name,
                    keyAlgo: details?.algo,
                    cardIdents: details?.cardIdents ?? const [],
                    status: _RequestStatus.responding,
                  ),
                ));
            if (isCardKey) {
              _autoRespondSignCard(roomId, event.requestId);
            } else {
              _autoRespondSign(roomId, event.requestId);
            }
          } else {
            // Manual approval required — show pending tile with buttons,
            // then immediately open the passphrase / PIN dialog.
            final newEntry = _RequestEntry(
              type: 'ssh.sign_request',
              requestId: event.requestId,
              description: event.description,
              fingerprint: fp,
              keyName: details?.name,
              keyAlgo: details?.algo,
              cardIdents: details?.cardIdents ?? const [],
              status: _RequestStatus.pending,
            );
            setState(() => _log.insert(0, newEntry));
            _approveSign(newEntry);
          }
        }
        // Keep log bounded.
        if (_log.length > 50) _log.removeLast();
      },
      onError: (_) => setState(() => _listening = false),
      onDone: () => setState(() => _listening = false),
    );
  }

  Future<void> _autoRespondSign(String roomId, String requestId) async {
    try {
      await mxRespondSignCached(roomId: roomId, requestId: requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(requestId, _RequestStatus.done);
    } catch (e) {
      // Cache miss or stale — surface as error so the user notices.
      _updateStatusWithError(requestId, e);
    }
  }

  Future<void> _autoRespondSignCard(String roomId, String requestId) async {
    try {
      await mxRespondSignCardCached(roomId: roomId, requestId: requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(requestId, _RequestStatus.done);
    } catch (e) {
      // Cached PIN may have been evicted — fall back to PIN dialog.
      _updateStatus(requestId, _RequestStatus.pending);
      final entry = _log.firstWhere(
        (e) => e.requestId == requestId,
        orElse: () => _RequestEntry(
          type: 'ssh.sign_request',
          requestId: requestId,
          description: null,
          fingerprint: null,
          status: _RequestStatus.pending,
        ),
      );
      _approveSign(entry);
    }
  }

  Future<void> _autoRespondListKeys(String roomId, String requestId) async {
    try {
      await mxRespondListKeys(roomId: roomId, requestId: requestId);
      _updateStatus(requestId, _RequestStatus.done);
    } catch (e) {
      _updateStatusWithError(requestId, e);
    }
  }

  void _updateStatus(String requestId, _RequestStatus status) {
    if (!mounted) return;
    setState(() {
      final idx = _log.indexWhere((e) => e.requestId == requestId);
      if (idx != -1) _log[idx] = _log[idx].copyWith(status: status);
    });
  }

  void _updateStatusWithError(String requestId, Object error) {
    if (!mounted) return;
    setState(() {
      final idx = _log.indexWhere((e) => e.requestId == requestId);
      if (idx != -1) {
        _log[idx] = _log[idx].copyWith(
          status: _RequestStatus.error,
          errorMessage: error.toString(),
        );
      }
    });
  }

  // ── Sign approval ────────────────────────────────────────────────────────────

  Future<void> _approveSign(_RequestEntry entry) async {
    final roomId = _agentRoom;
    if (roomId == null) return;

    // Card-backed key: check PIN cache first, then prompt if needed.
    if (entry.cardIdents.isNotEmpty) {
      // Try any cached ident — if found, skip the dialog entirely.
      bool pinCached = false;
      for (final id in entry.cardIdents) {
        if (await hasCachedCardPin(cardIdent: id)) {
          pinCached = true;
          break;
        }
      }

      if (pinCached) {
        _updateStatus(entry.requestId, _RequestStatus.responding);
        try {
          await mxRespondSignCardCached(
            roomId: roomId,
            requestId: entry.requestId,
          );
          SettingsService.instance.resetCacheTimer();
          _updateStatus(entry.requestId, _RequestStatus.done);
        } catch (_) {
          // Stale cache — fall through to PIN dialog below.
          pinCached = false;
        }
        if (pinCached) return;
      }

      // No cached PIN (or cache was stale) — show PIN dialog.
      final pin = await _promptPin(entry);
      if (pin == null) return; // cancelled
      _updateStatus(entry.requestId, _RequestStatus.responding);
      try {
        await mxRespondSignCard(
          roomId: roomId,
          requestId: entry.requestId,
          pin: pin,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, _RequestStatus.done);
      } catch (e) {
        _updateStatusWithError(entry.requestId, e);
      }
      return;
    }

    // Soft-key path ──────────────────────────────────────────────────────────
    final fp = entry.fingerprint ?? '';

    // If the passphrase for this key is already cached, skip the dialog.
    // Future biometric path: biometric success → mxRespondSignCached, same
    // flow, no passphrase dialog shown.
    final cached = fp.isNotEmpty && await hasCachedPassphrase(fingerprint: fp);

    if (!cached) {
      final passphrase = await _promptPassphrase(entry);
      if (passphrase == null) return; // cancelled

      _updateStatus(entry.requestId, _RequestStatus.responding);
      try {
        await mxRespondSign(
          roomId: roomId,
          requestId: entry.requestId,
          passphrase: passphrase,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, _RequestStatus.done);
      } catch (e) {
        _updateStatusWithError(entry.requestId, e);
      }
      return;
    }

    // Cached path — no dialog needed.
    _updateStatus(entry.requestId, _RequestStatus.responding);
    try {
      await mxRespondSignCached(roomId: roomId, requestId: entry.requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(entry.requestId, _RequestStatus.done);
    } catch (_) {
      // Cache may be stale (key was re-encrypted); fall back to passphrase prompt.
      _updateStatus(entry.requestId, _RequestStatus.pending);
      final passphrase = await _promptPassphrase(entry);
      if (passphrase == null) {
        _updateStatus(entry.requestId, _RequestStatus.error);
        return;
      }
      _updateStatus(entry.requestId, _RequestStatus.responding);
      try {
        await mxRespondSign(
          roomId: roomId,
          requestId: entry.requestId,
          passphrase: passphrase,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, _RequestStatus.done);
      } catch (e2) {
        _updateStatusWithError(entry.requestId, e2);
      }
    }
  }

  Future<void> _rejectSign(String requestId) async {
    final roomId = _agentRoom;
    if (roomId == null) return;

    _updateStatus(requestId, _RequestStatus.error);
    try {
      await mxRejectSign(roomId: roomId, requestId: requestId);
    } catch (_) {
      // Best-effort — status already updated.
    }
  }

  Future<String?> _promptPassphrase(_RequestEntry entry) async {
    // Prefer the already-resolved details on the entry; fall back to a fresh
    // lookup only when missing (e.g. stale-cache retry path).
    final fp = entry.fingerprint ?? '';
    final details = (entry.keyName != null)
        ? SshKeyDetails(
            name: entry.keyName!,
            algo: entry.keyAlgo ?? '',
            cardIdents: entry.cardIdents,
          )
        : (fp.isNotEmpty ? await getSshKeyDetails(fingerprint: fp) : null);

    if (!mounted) return null;

    // Bring the window forward — the user must type their passphrase.
    WindowService.instance.bringToFront();

    final ctrl = TextEditingController();
    var obscure = true; // captured by the StatefulBuilder closure
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
              backgroundColor: const Color(0xFF2C2C2E),
              title: const Text('Key passphrase'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ── Key context ─────────────────────────────────────────
                  Container(
                    width: double.infinity,
                    padding:
                        const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                    margin: const EdgeInsets.only(bottom: 14),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1C1C1E),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFF3A3A3C)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (details != null && details.name.isNotEmpty) ...[
                          Row(
                            children: [
                              Expanded(
                                child: Text(
                                  _keyLabel(details.name, details.cardIdents),
                                  style: const TextStyle(
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600,
                                    color: Color(0xFFE5E5EA),
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              if (details.algo.isNotEmpty) ...[
                                const SizedBox(width: 6),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 5, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF3A3A3C),
                                    borderRadius: BorderRadius.circular(4),
                                  ),
                                  child: Text(
                                    details.algo,
                                    style: const TextStyle(
                                      fontSize: 10,
                                      fontFamily: 'monospace',
                                      color: Color(0xFF8E8E93),
                                    ),
                                  ),
                                ),
                              ],
                            ],
                          ),
                          const SizedBox(height: 4),
                        ],
                        if (fp.isNotEmpty)
                          Text(
                            fp,
                            style: const TextStyle(
                              fontSize: 10,
                              fontFamily: 'monospace',
                              color: Color(0xFF636366),
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        if (entry.description != null &&
                            entry.description!.isNotEmpty) ...[
                          const SizedBox(height: 6),
                          Text(
                            entry.description!,
                            style: const TextStyle(
                              fontSize: 11,
                              color: Color(0xFF8E8E93),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                  // ── Passphrase field ────────────────────────────────────
                  TextField(
                    controller: ctrl,
                    obscureText: obscure,
                    autofocus: true,
                    decoration: InputDecoration(
                      hintText: 'Enter passphrase',
                      border: const OutlineInputBorder(),
                      suffixIcon: IconButton(
                        icon: Icon(
                          obscure
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined,
                          size: 18,
                          color: const Color(0xFF8E8E93),
                        ),
                        onPressed: () => setLocal(() => obscure = !obscure),
                      ),
                    ),
                    onSubmitted: (_) => Navigator.pop(ctx, ctrl.text),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  onPressed: () => Navigator.pop(ctx, ctrl.text),
                  child: const Text('Sign'),
                ),
              ],
            ),
          ),
        );
  }

  Future<String?> _promptPin(_RequestEntry entry) async {
    final fp = entry.fingerprint ?? '';
    final firstIdent =
        entry.cardIdents.isNotEmpty ? entry.cardIdents.first : null;

    // Fetch key details and PIN retry counter concurrently — best-effort.
    final futures = await Future.wait([
      (entry.keyName != null)
          ? Future<SshKeyDetails?>.value(SshKeyDetails(
              name: entry.keyName!,
              algo: entry.keyAlgo ?? '',
              cardIdents: entry.cardIdents,
            ))
          : (fp.isNotEmpty
              ? getSshKeyDetails(fingerprint: fp)
              : Future<SshKeyDetails?>.value(null)),
      if (firstIdent != null)
        getCardPinRetries(cardIdent: firstIdent)
            .then<int?>((v) => v)
            .catchError((_) => null as int?)
      else
        Future<int?>.value(null),
    ]);

    if (!mounted) return null;

    final details = futures[0] as SshKeyDetails?;
    final pinRetries = futures[1] as int?;

    // Bring the window forward — the user must enter their PIN.
    WindowService.instance.bringToFront();

    final ctrl = TextEditingController();
    var obscure = true; // captured by StatefulBuilder closure
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Card PIN'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Key context ───────────────────────────────────────────────
            Container(
              width: double.infinity,
              padding:
                  const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              margin: const EdgeInsets.only(bottom: 14),
              decoration: BoxDecoration(
                color: const Color(0xFF1C1C1E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF3A3A3C)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (details != null && details.name.isNotEmpty) ...[
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            _keyLabel(details.name, details.cardIdents),
                            style: const TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: Color(0xFFE5E5EA),
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (details.algo.isNotEmpty) ...[
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 5, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF3A3A3C),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              details.algo,
                              style: const TextStyle(
                                fontSize: 10,
                                fontFamily: 'monospace',
                                color: Color(0xFF8E8E93),
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                    const SizedBox(height: 4),
                  ],
                  if (fp.isNotEmpty)
                    Text(
                      fp,
                      style: const TextStyle(
                        fontSize: 10,
                        fontFamily: 'monospace',
                        color: Color(0xFF636366),
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  if (entry.description != null &&
                      entry.description!.isNotEmpty) ...[
                    const SizedBox(height: 6),
                    Text(
                      entry.description!,
                      style: const TextStyle(
                        fontSize: 11,
                        color: Color(0xFF8E8E93),
                      ),
                    ),
                  ],
                ],
              ),
            ),
            // ── PIN retry counter ─────────────────────────────────────────
            if (pinRetries != null) ...[
              Row(
                children: [
                  Icon(
                    pinRetries <= 1
                        ? Icons.warning_amber_rounded
                        : Icons.pin_outlined,
                    size: 14,
                    color: pinRetries <= 1
                        ? const Color(0xFFFF9F0A)
                        : const Color(0xFF636366),
                  ),
                  const SizedBox(width: 6),
                  Text(
                    '$pinRetries attempt${pinRetries == 1 ? '' : 's'} remaining',
                    style: TextStyle(
                      fontSize: 12,
                      color: pinRetries <= 1
                          ? const Color(0xFFFF9F0A)
                          : const Color(0xFF8E8E93),
                      fontWeight: pinRetries <= 1
                          ? FontWeight.w600
                          : FontWeight.normal,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
            ],
            // ── PIN field ─────────────────────────────────────────────────
            TextField(
              controller: ctrl,
              obscureText: obscure,
              autofocus: true,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                hintText: '4–8 digit PIN',
                border: const OutlineInputBorder(),
                suffixIcon: IconButton(
                  icon: Icon(
                    obscure
                        ? Icons.visibility_outlined
                        : Icons.visibility_off_outlined,
                    size: 18,
                    color: const Color(0xFF8E8E93),
                  ),
                  onPressed: () => setLocal(() => obscure = !obscure),
                ),
              ),
              onSubmitted: (_) => Navigator.pop(ctx, ctrl.text),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, ctrl.text),
            child: const Text('Sign'),
          ),
        ],
        ),
      ),
    );
  }

  // ── Room picker ──────────────────────────────────────────────────────────────

  Future<void> _pickRoom() async {
    final rooms = await mxListRooms();
    if (!mounted) return;
    if (rooms.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No rooms joined yet.')),
      );
      return;
    }
    final picked = await showModalBottomSheet<MxRoomInfo>(
      context: context,
      builder: (ctx) => ListView(
        children: [
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'Select agent room',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
            ),
          ),
          ...rooms.map(
            (r) => ListTile(
              leading: r.isEncrypted
                  ? const Icon(Icons.lock, size: 18, color: Color(0xFF30D158))
                  : const Icon(Icons.chat_bubble_outline, size: 18),
              title: Text(r.name, style: const TextStyle(fontSize: 14)),
              subtitle: Text(
                r.roomId,
                style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
                overflow: TextOverflow.ellipsis,
              ),
              onTap: () => Navigator.pop(ctx, r),
            ),
          ),
        ],
      ),
    );
    if (picked == null) return;

    try {
      await mxSetAgentRoom(roomId: picked.roomId);
      if (!mounted) return;
      setState(() {
        _agentRoom = picked.roomId;
        _listening = false;
        _log.clear();
      });
      _startListening(picked.roomId);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to set agent room: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text('SSH Agent'),
        actions: [
          IconButton(
            icon: const Icon(Icons.swap_horiz),
            tooltip: 'Change room',
            onPressed: _pickRoom,
          ),
        ],
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _RoomBanner(
            roomId: _agentRoom,
            listening: _listening,
            onPick: _pickRoom,
          ),
          const Divider(height: 1),
          Expanded(
            child: _log.isEmpty
                ? Center(
                    child: Text(
                      _agentRoom == null
                          ? 'Select a room to start listening.'
                          : 'Waiting for requests…',
                      style: TextStyle(
                        color: cs.onSurface.withValues(alpha: 0.45),
                      ),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    itemCount: _log.length,
                    itemBuilder: (context, i) => _LogTile(
                      entry: _log[i],
                      onApprove: _log[i].status == _RequestStatus.pending
                          ? () => _approveSign(_log[i])
                          : null,
                      onReject: _log[i].status == _RequestStatus.pending
                          ? () => _rejectSign(_log[i].requestId)
                          : null,
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}

// ── Room banner ───────────────────────────────────────────────────────────────

class _RoomBanner extends StatelessWidget {
  const _RoomBanner({
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
                          fontSize: 12, fontFamily: 'monospace'),
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

class _LogTile extends StatelessWidget {
  const _LogTile({
    required this.entry,
    this.onApprove,
    this.onReject,
  });

  final _RequestEntry entry;
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
    final isPending = entry.status == _RequestStatus.pending;
    final isError = entry.status == _RequestStatus.error;
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
                _StatusDot(entry.status),
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
                            fontWeight: FontWeight.w600),
                      ),
                      if (entry.keyName != null &&
                          entry.keyName!.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                _keyLabel(
                                    entry.keyName!, entry.cardIdents),
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
                                    horizontal: 5, vertical: 1),
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
                              color: cs.onSurface.withValues(alpha: 0.5)),
                          overflow: TextOverflow.ellipsis,
                        ),
                      if (entry.description != null)
                        Text(
                          entry.description!,
                          style: TextStyle(
                              fontSize: 11,
                              color: cs.onSurface.withValues(alpha: 0.55)),
                        ),
                      Text(
                        entry.requestId.substring(0, 8),
                        style: TextStyle(
                            fontSize: 10,
                            color: cs.onSurface.withValues(alpha: 0.35),
                            fontFamily: 'monospace'),
                      ),
                    ],
                  ),
                ),
                _StatusLabel(entry.status),
                // Info button — visible only when there is an error detail.
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
            // Approve / Reject buttons — only for pending sign requests.
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
          ],
        ),
      ),
    );
  }
}

class _StatusDot extends StatelessWidget {
  const _StatusDot(this.status);
  final _RequestStatus status;

  @override
  Widget build(BuildContext context) {
    final color = switch (status) {
      _RequestStatus.pending => const Color(0xFFFF9F0A),
      _RequestStatus.responding => const Color(0xFF0A84FF),
      _RequestStatus.done => const Color(0xFF30D158),
      _RequestStatus.error => const Color(0xFFFF453A),
    };
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(color: color, shape: BoxShape.circle),
    );
  }
}

class _StatusLabel extends StatelessWidget {
  const _StatusLabel(this.status);
  final _RequestStatus status;

  @override
  Widget build(BuildContext context) {
    final (label, color) = switch (status) {
      _RequestStatus.pending => ('pending', const Color(0xFFFF9F0A)),
      _RequestStatus.responding => ('responding', const Color(0xFF0A84FF)),
      _RequestStatus.done => ('done', const Color(0xFF30D158)),
      _RequestStatus.error => ('error', const Color(0xFFFF453A)),
    };
    return Text(label,
        style: TextStyle(fontSize: 10, color: color, fontFamily: 'monospace'));
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Converts a card ident like `"0006:17684870"` to `"cardno:17_684_870"`.
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

/// Build the display label for a key: `uid` optionally followed by
/// `cardno:XX_XXX_XXX` for each associated card.
String _keyLabel(String uid, List<String> cardIdents) {
  if (cardIdents.isEmpty) return uid;
  final labels = cardIdents.map(_cardnoFromIdent);
  return '$uid ${labels.join(', ')}';
}

// ── Data model ────────────────────────────────────────────────────────────────

enum _RequestStatus { pending, responding, done, error }

class _RequestEntry {
  const _RequestEntry({
    required this.type,
    required this.requestId,
    required this.description,
    required this.fingerprint,
    required this.status,
    this.keyName,
    this.keyAlgo,
    this.cardIdents = const [],
    this.errorMessage,
  });

  final String type;
  final String requestId;
  final String? description;
  final String? fingerprint;
  final String? keyName;
  final String? keyAlgo;
  final List<String> cardIdents;
  final _RequestStatus status;
  final String? errorMessage;

  _RequestEntry copyWith({
    _RequestStatus? status,
    String? keyName,
    String? keyAlgo,
    List<String>? cardIdents,
    String? errorMessage,
  }) =>
      _RequestEntry(
        type: type,
        requestId: requestId,
        description: description,
        fingerprint: fingerprint,
        status: status ?? this.status,
        keyName: keyName ?? this.keyName,
        keyAlgo: keyAlgo ?? this.keyAlgo,
        cardIdents: cardIdents ?? this.cardIdents,
        errorMessage: errorMessage ?? this.errorMessage,
      );
}
