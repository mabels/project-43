import 'dart:async';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import '../services/biometric_service.dart';
import '../services/notification_service.dart';
import '../services/settings_service.dart';
import '../services/window_service.dart';
import 'agent/agent_widgets.dart';
import 'agent/request_model.dart';
import 'key_helpers.dart';

class AgentScreen extends StatefulWidget {
  const AgentScreen({
    super.key,
    this.onSignRequest,
    this.agentStream,
    this.onRoomChanged,
  });

  /// Called when an `ssh.sign_request` arrives so the shell can switch to
  /// the Agent tab if it is not already in focus.
  final VoidCallback? onSignRequest;

  /// Broadcast stream of agent events routed by the root shell's single
  /// [mxListenAll] subscription.  When provided, this screen never calls
  /// [mxListenAgent] itself — one sync loop for the whole app.
  final Stream<AgentRequest>? agentStream;

  /// Called when the user picks a different agent room, so the root shell
  /// can restart the unified [mxListenAll] listener with the new room.
  final void Function(String roomId)? onRoomChanged;

  @override
  State<AgentScreen> createState() => _AgentScreenState();
}

class _AgentScreenState extends State<AgentScreen> {
  String? _agentRoom;
  final List<RequestEntry> _log = [];
  bool _listening = false;
  StreamSubscription<AgentRequest>? _agentSub;

  /// Per-fingerprint credential gate.
  ///
  /// Completes (void) once the first sign request for a given key has
  /// successfully acquired the credential AND it is hot in the Rust cache.
  /// Subsequent sign requests for the same key await this gate, then call the
  /// *_cached Rust variant directly — the credential is guaranteed present.
  ///
  /// Completes with an error if acquisition was cancelled or failed; all
  /// waiters then reject their respective requests without showing a dialog.
  final Map<String, Completer<void>> _fingerprintGate = {};

  @override
  void initState() {
    super.initState();
    _loadAgentRoom();
    _subscribeToStream();
  }

  @override
  void dispose() {
    _agentSub?.cancel();
    super.dispose();
  }

  Future<void> _loadAgentRoom() async {
    final room = await mxGetAgentRoom();
    if (!mounted) return;
    if (room != _agentRoom) {
      setState(() => _agentRoom = room);
    }
  }

  // ── Stream subscription ───────────────────────────────────────────────────

  void _subscribeToStream() {
    final stream = widget.agentStream;
    if (stream == null) return;
    _agentSub = stream.listen(
      (event) {
        if (!mounted) return;
        if (event is AgentRequest_ListKeys) {
          _handleListKeysEvent(event);
        } else if (event is AgentRequest_Sign) {
          // Fire-and-forget: sign events are serialised per fingerprint via
          // _fingerprintGate; different fingerprints process concurrently.
          _handleSignEvent(event);
        }
        if (_log.length > 50) _log.removeLast();
      },
      onError: (_) {},
      onDone: () {},
    );
    if (mounted) setState(() => _listening = true);
  }

  // ── List-keys handling ────────────────────────────────────────────────────

  void _handleListKeysEvent(AgentRequest_ListKeys event) {
    setState(
      () => _log.insert(
        0,
        RequestEntry(
          type: 'ssh.list_keys_request',
          requestId: event.requestId,
          description: null,
          fingerprint: null,
          status: RequestStatus.responding,
        ),
      ),
    );
    final room = _agentRoom;
    if (room != null) _autoRespondListKeys(room, event.requestId);
  }

  Future<void> _autoRespondListKeys(String roomId, String requestId) async {
    try {
      await mxRespondListKeys(roomId: roomId, requestId: requestId);
      _updateStatus(requestId, RequestStatus.done);
    } catch (e) {
      _updateStatusWithError(requestId, e);
    }
  }

  // ── Sign handling ─────────────────────────────────────────────────────────

  Future<void> _handleSignEvent(AgentRequest_Sign event) async {
    if (!mounted) return;
    final fp = event.fingerprint;

    widget.onSignRequest?.call();

    final SshKeyDetails? details = fp.isNotEmpty
        ? await getSshKeyDetails(fingerprint: fp)
        : null;
    if (!mounted) return;

    final bool autoApprove =
        SettingsService.instance.settings.autoApproveWhenCached;

    // Notification.
    {
      final label = keyLabel(details?.name ?? '', details?.cardIdents ?? []);
      final algo = details?.algo ?? '';
      final keyPart = label.isNotEmpty
          ? (algo.isNotEmpty ? '$label ($algo)' : label)
          : fp;
      final srcLabel = event.deviceLabel;
      final srcId = event.deviceId;
      final srcPart = srcLabel.isNotEmpty
          ? srcLabel
          : (srcId.isNotEmpty ? srcId : null);
      final body = srcPart != null ? '$keyPart · from $srcPart' : keyPart;
      NotificationService.instance.show(
        title: 'Sign request',
        body: body,
        stableId: fp,
        channelId: 'p43_sign_requests',
        channelName: 'Sign requests',
        channelDescription: 'Notifications for incoming SSH sign requests',
      );
    }

    final entry = RequestEntry(
      type: 'ssh.sign_request',
      requestId: event.requestId,
      description: event.description,
      fingerprint: fp,
      keyName: details?.name,
      keyAlgo: details?.algo,
      cardIdents: details?.cardIdents ?? const [],
      // autoApprove → show as "responding" immediately; manual → "pending"
      // so the Approve button appears.
      status:
          autoApprove ? RequestStatus.responding : RequestStatus.pending,
      sourceLabel: event.deviceLabel,
      sourceDeviceId: event.deviceId,
    );
    setState(() => _log.insert(0, entry));

    if (autoApprove) {
      await _processSignRequest(entry);
    }
    // autoApprove=false: stays pending, user taps the Approve button.
  }

  /// Process a sign request — called from the auto-approve path or user tap.
  ///
  /// Gate semantics:
  ///   • First caller for a fingerprint acquires the credential (cache →
  ///     biometric → dialog) and completes the gate when the credential is
  ///     hot in the Rust cache.
  ///   • Every subsequent caller for the same fingerprint waits on the gate
  ///     and then calls the *_cached Rust variant directly — no dialog shown.
  ///   • If acquisition fails or the dialog is cancelled the gate completes
  ///     with an error and all waiters reject their requests.
  Future<void> _processSignRequest(RequestEntry entry) async {
    final roomId = _agentRoom;
    if (roomId == null) return;
    final fp = entry.fingerprint ?? '';
    final isCardKey = entry.cardIdents.isNotEmpty;

    // ── Waiter path ────────────────────────────────────────────────────────
    final existing = _fingerprintGate[fp];
    if (existing != null) {
      try {
        // Block until the gate holder has credential hot in the Rust cache.
        await existing.future;
        _updateStatus(entry.requestId, RequestStatus.responding);
        await _signCached(roomId, entry.requestId, isCardKey);
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, RequestStatus.done);
      } catch (e) {
        debugPrint('[p43::agent] waiter error  ${entry.requestId}: $e');
        // Gate holder was cancelled or failed — reject this request too.
        try {
          await mxRejectSign(roomId: roomId, requestId: entry.requestId);
        } catch (rejectErr) {
          debugPrint('[p43::agent] reject error ${entry.requestId}: $rejectErr');
        }
        _updateStatus(entry.requestId, RequestStatus.error);
      }
      return;
    }

    // ── Gate-holder path ───────────────────────────────────────────────────
    final gate = Completer<void>();
    _fingerprintGate[fp] = gate;

    try {
      await _acquireAndSign(roomId, entry, isCardKey, fp);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(entry.requestId, RequestStatus.done);
      // Signal waiters: credential is now hot in the Rust cache.
      gate.complete();
    } catch (e) {
      debugPrint('[p43::agent] gate-holder error ${entry.requestId}: $e');
      if (!gate.isCompleted) gate.completeError(e);
      if (e.toString() == 'cancelled') {
        _updateStatus(entry.requestId, RequestStatus.error);
      } else {
        _updateStatusWithError(entry.requestId, e);
      }
    } finally {
      _fingerprintGate.remove(fp);
      if (!gate.isCompleted) gate.completeError('disposed');
    }
  }

  /// Acquire the signing credential for [fp] and sign [entry]'s request.
  ///
  /// Try order:
  ///   1. Rust credential cache (no Dart string needed).
  ///   2. Biometric secure store (Face ID / Touch ID / device PIN).
  ///   3. PIN / passphrase dialog — result auto-saved to biometric store.
  ///
  /// Throws the string `'cancelled'` when the user dismisses the dialog.
  Future<void> _acquireAndSign(
    String roomId,
    RequestEntry entry,
    bool isCardKey,
    String fp,
  ) async {
    final requestId = entry.requestId;
    final cardIdents = entry.cardIdents;

    debugPrint('[p43::agent] acquire  $requestId  fp=$fp  card=$isCardKey');

    // ── 1. Rust cache hit ─────────────────────────────────────────────────
    if (isCardKey) {
      for (final id in cardIdents) {
        if (await hasCachedCardPin(cardIdent: id)) {
          debugPrint('[p43::agent] path=rust-cache  $requestId');
          _updateStatus(requestId, RequestStatus.responding);
          await mxRespondSignCardCached(
            roomId: roomId,
            requestId: requestId,
          );
          return; // credential stays hot for waiters
        }
      }
    } else if (fp.isNotEmpty && await hasCachedPassphrase(fingerprint: fp)) {
      debugPrint('[p43::agent] path=rust-cache  $requestId');
      _updateStatus(requestId, RequestStatus.responding);
      await mxRespondSignCached(roomId: roomId, requestId: requestId);
      return;
    }

    // ── 2. Biometric secure store ─────────────────────────────────────────
    if (fp.isNotEmpty && await BiometricService.instance.hasSaved(fp)) {
      debugPrint('[p43::agent] path=biometric  $requestId');
      WindowService.instance.bringToFront();
      final saved = await BiometricService.instance.authenticate(
        fp,
        reason: 'Approve SSH sign request',
      );
      if (!mounted) throw 'cancelled';
      if (saved != null) {
        debugPrint('[p43::agent] biometric ok  $requestId');
        _updateStatus(requestId, RequestStatus.responding);
        if (isCardKey) {
          await mxRespondSignCard(
            roomId: roomId,
            requestId: requestId,
            pin: saved.credential,
          );
        } else {
          await mxRespondSign(
            roomId: roomId,
            requestId: requestId,
            passphrase: saved.credential,
          );
        }
        return; // Rust also caches the credential for waiters
      }
      debugPrint('[p43::agent] biometric cancelled/failed  $requestId  → dialog');
      // Biometric cancelled / failed — fall through to dialog.
    }

    // ── 3. Dialog ─────────────────────────────────────────────────────────
    // Gate guarantees only one dialog is open at a time for this fingerprint.
    debugPrint('[p43::agent] path=dialog  $requestId');
    _updateStatus(requestId, RequestStatus.pending);
    WindowService.instance.bringToFront();

    final String? credential = isCardKey
        ? await _promptPin(entry)
        : await _promptPassphrase(entry);

    if (credential == null) {
      debugPrint('[p43::agent] dialog cancelled  $requestId');
      throw 'cancelled';
    }

    // Auto-save to biometric store — next request uses Face ID / Touch ID.
    if (fp.isNotEmpty) {
      try {
        await BiometricService.instance.save(
          fingerprint: fp,
          isCard: isCardKey,
          credential: credential,
        );
        debugPrint('[p43::agent] biometric saved  $requestId');
      } catch (e) {
        debugPrint('[p43::agent] biometric save failed  $requestId: $e');
        // Saving failed (device has no passcode, etc.) — continue without it.
      }
    }

    debugPrint('[p43::agent] signing via dialog credential  $requestId');
    _updateStatus(requestId, RequestStatus.responding);
    if (isCardKey) {
      await mxRespondSignCard(
        roomId: roomId,
        requestId: requestId,
        pin: credential,
      );
    } else {
      await mxRespondSign(
        roomId: roomId,
        requestId: requestId,
        passphrase: credential,
      );
    }
    // Rust caches the credential; waiters call *_cached variants.
  }

  /// Call the Rust cached-sign variant for a waiter (gate already complete).
  Future<void> _signCached(
    String roomId,
    String requestId,
    bool isCardKey,
  ) async {
    if (isCardKey) {
      await mxRespondSignCardCached(roomId: roomId, requestId: requestId);
    } else {
      await mxRespondSignCached(roomId: roomId, requestId: requestId);
    }
  }

  // ── Reject ────────────────────────────────────────────────────────────────

  Future<void> _rejectSign(String requestId) async {
    final roomId = _agentRoom;
    if (roomId == null) return;
    _updateStatus(requestId, RequestStatus.error);
    try {
      await mxRejectSign(roomId: roomId, requestId: requestId);
    } catch (_) {}
  }

  // ── Status helpers ────────────────────────────────────────────────────────

  void _updateStatus(String requestId, RequestStatus status) {
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
          status: RequestStatus.error,
          errorMessage: error.toString(),
        );
      }
    });
  }

  // ── Dialogs ───────────────────────────────────────────────────────────────

  Future<String?> _promptPassphrase(RequestEntry entry) async {
    final fp = entry.fingerprint ?? '';
    final details = (entry.keyName != null)
        ? SshKeyDetails(
            name: entry.keyName!,
            algo: entry.keyAlgo ?? '',
            cardIdents: entry.cardIdents,
          )
        : (fp.isNotEmpty ? await getSshKeyDetails(fingerprint: fp) : null);

    if (!mounted) return null;

    final ctrl = TextEditingController();
    var obscure = true;
    Timer? obscureTimer;

    void toggleObscure(StateSetter setLocal) {
      obscureTimer?.cancel();
      if (obscure) {
        setLocal(() => obscure = false);
        obscureTimer = Timer(const Duration(seconds: 10), () {
          setLocal(() => obscure = true);
        });
      } else {
        obscureTimer = null;
        setLocal(() => obscure = true);
      }
    }

    final result = await showDialog<String>(
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
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 8,
                ),
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
                              keyLabel(details.name, details.cardIdents),
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
                                horizontal: 5,
                                vertical: 2,
                              ),
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
                    onPressed: () => toggleObscure(setLocal),
                  ),
                ),
                onSubmitted: (_) {
                  obscureTimer?.cancel();
                  Navigator.pop(ctx, ctrl.text);
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () {
                obscureTimer?.cancel();
                Navigator.pop(ctx);
              },
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                obscureTimer?.cancel();
                Navigator.pop(ctx, ctrl.text);
              },
              child: const Text('Sign'),
            ),
          ],
        ),
      ),
    );
    obscureTimer?.cancel();
    return result;
  }

  Future<String?> _promptPin(RequestEntry entry) async {
    final fp = entry.fingerprint ?? '';
    final firstIdent = entry.cardIdents.isNotEmpty
        ? entry.cardIdents.first
        : null;

    final futures = await Future.wait([
      (entry.keyName != null)
          ? Future<SshKeyDetails?>.value(
              SshKeyDetails(
                name: entry.keyName!,
                algo: entry.keyAlgo ?? '',
                cardIdents: entry.cardIdents,
              ),
            )
          : (fp.isNotEmpty
                ? getSshKeyDetails(fingerprint: fp)
                : Future<SshKeyDetails?>.value(null)),
      if (firstIdent != null)
        getCardPinRetries(
          cardIdent: firstIdent,
        ).then<int?>((v) => v).catchError((_) => null as int?)
      else
        Future<int?>.value(null),
    ]);

    if (!mounted) return null;

    final details = futures[0] as SshKeyDetails?;
    final pinRetries = futures[1] as int?;

    final ctrl = TextEditingController();
    var obscure = true;
    Timer? obscureTimer;

    void toggleObscure(StateSetter setLocal) {
      obscureTimer?.cancel();
      if (obscure) {
        setLocal(() => obscure = false);
        obscureTimer = Timer(const Duration(seconds: 10), () {
          setLocal(() => obscure = true);
        });
      } else {
        obscureTimer = null;
        setLocal(() => obscure = true);
      }
    }

    final result = await showDialog<String>(
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
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 8,
                ),
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
                              keyLabel(details.name, details.cardIdents),
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
                                horizontal: 5,
                                vertical: 2,
                              ),
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
                    onPressed: () => toggleObscure(setLocal),
                  ),
                ),
                onSubmitted: (_) {
                  obscureTimer?.cancel();
                  Navigator.pop(ctx, ctrl.text);
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () {
                obscureTimer?.cancel();
                Navigator.pop(ctx);
              },
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                obscureTimer?.cancel();
                Navigator.pop(ctx, ctrl.text);
              },
              child: const Text('Sign'),
            ),
          ],
        ),
      ),
    );
    obscureTimer?.cancel();
    return result;
  }

  // ── Room picker ───────────────────────────────────────────────────────────

  Future<void> _pickRoom() async {
    final rooms = await mxListRooms();
    if (!mounted) return;
    if (rooms.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('No rooms joined yet.')));
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
        _log.clear();
      });
      widget.onRoomChanged?.call(picked.roomId);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to set agent room: $e')));
      }
    }
  }

  // ── Build ─────────────────────────────────────────────────────────────────

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
          AgentRoomBanner(
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
                    itemBuilder: (context, i) => AgentLogTile(
                      entry: _log[i],
                      onApprove: _log[i].status == RequestStatus.pending
                          ? () => _processSignRequest(_log[i])
                          : null,
                      onReject: _log[i].status == RequestStatus.pending
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
