import 'dart:async';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
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

  /// Load the saved agent room ID so we know where to send responses.
  /// Does NOT start a Matrix listener — that is owned by the root shell.
  Future<void> _loadAgentRoom() async {
    final room = await mxGetAgentRoom();
    if (!mounted) return;
    if (room != _agentRoom) {
      setState(() => _agentRoom = room);
    }
  }

  /// Subscribe once to the root shell's broadcast stream.
  void _subscribeToStream() {
    final stream = widget.agentStream;
    if (stream == null) return;
    _agentSub = stream.listen(
      (event) async {
        if (!mounted) return;
        if (event is AgentRequest_ListKeys) {
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
          final room0 = _agentRoom;
          if (room0 != null) _autoRespondListKeys(room0, event.requestId);
        } else if (event is AgentRequest_Sign) {
          final fp = event.fingerprint;
          final autoApprove =
              SettingsService.instance.settings.autoApproveWhenCached;

          widget.onSignRequest?.call();

          final SshKeyDetails? details = fp.isNotEmpty
              ? await getSshKeyDetails(fingerprint: fp)
              : null;
          if (!mounted) return;

          final bool cached;
          if (!autoApprove) {
            cached = false;
          } else if (details != null && details.cardIdents.isNotEmpty) {
            cached = await Future.any(
              details.cardIdents.map((id) => hasCachedCardPin(cardIdent: id)),
            ).then((v) => v).catchError((_) => false);
          } else if (fp.isNotEmpty) {
            cached = await hasCachedPassphrase(fingerprint: fp);
          } else {
            cached = false;
          }
          if (!mounted) return;

          if (SettingsService.instance.settings.notifyOnSignRequest) {
            final label = keyLabel(
              details?.name ?? '',
              details?.cardIdents ?? [],
            );
            final algo = details?.algo ?? '';
            NotificationService.instance.show(
              title: 'Sign request',
              body: label.isNotEmpty
                  ? (algo.isNotEmpty ? '$label ($algo)' : label)
                  : fp,
              stableId: fp,
              channelId: 'p43_sign_requests',
              channelName: 'Sign requests',
              channelDescription:
                  'Notifications for incoming SSH sign requests',
            );
          }

          final isCardKey = details != null && details.cardIdents.isNotEmpty;

          if (cached) {
            setState(
              () => _log.insert(
                0,
                RequestEntry(
                  type: 'ssh.sign_request',
                  requestId: event.requestId,
                  description: event.description,
                  fingerprint: fp,
                  keyName: details?.name,
                  keyAlgo: details?.algo,
                  cardIdents: details?.cardIdents ?? const [],
                  status: RequestStatus.responding,
                ),
              ),
            );
            final room1 = _agentRoom;
            if (room1 != null) {
              if (isCardKey) {
                _autoRespondSignCard(room1, event.requestId);
              } else {
                _autoRespondSign(room1, event.requestId);
              }
            }
          } else {
            final newEntry = RequestEntry(
              type: 'ssh.sign_request',
              requestId: event.requestId,
              description: event.description,
              fingerprint: fp,
              keyName: details?.name,
              keyAlgo: details?.algo,
              cardIdents: details?.cardIdents ?? const [],
              status: RequestStatus.pending,
            );
            setState(() => _log.insert(0, newEntry));
            _approveSign(newEntry);
          }
        }
        if (_log.length > 50) _log.removeLast();
      },
      onError: (_) {},
      onDone: () {},
    );
    if (mounted) setState(() => _listening = true);
  }

  Future<void> _autoRespondSign(String roomId, String requestId) async {
    try {
      await mxRespondSignCached(roomId: roomId, requestId: requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(requestId, RequestStatus.done);
    } catch (e) {
      _updateStatusWithError(requestId, e);
    }
  }

  Future<void> _autoRespondSignCard(String roomId, String requestId) async {
    try {
      await mxRespondSignCardCached(roomId: roomId, requestId: requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(requestId, RequestStatus.done);
    } catch (e) {
      _updateStatus(requestId, RequestStatus.pending);
      final entry = _log.firstWhere(
        (e) => e.requestId == requestId,
        orElse: () => RequestEntry(
          type: 'ssh.sign_request',
          requestId: requestId,
          description: null,
          fingerprint: null,
          status: RequestStatus.pending,
        ),
      );
      _approveSign(entry);
    }
  }

  Future<void> _autoRespondListKeys(String roomId, String requestId) async {
    try {
      await mxRespondListKeys(roomId: roomId, requestId: requestId);
      _updateStatus(requestId, RequestStatus.done);
    } catch (e) {
      _updateStatusWithError(requestId, e);
    }
  }

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

  // ── Sign approval ─────────────────────────────────────────────────────────

  Future<void> _approveSign(RequestEntry entry) async {
    final roomId = _agentRoom;
    if (roomId == null) return;

    if (entry.cardIdents.isNotEmpty) {
      bool pinCached = false;
      for (final id in entry.cardIdents) {
        if (await hasCachedCardPin(cardIdent: id)) {
          pinCached = true;
          break;
        }
      }

      if (pinCached) {
        _updateStatus(entry.requestId, RequestStatus.responding);
        try {
          await mxRespondSignCardCached(
            roomId: roomId,
            requestId: entry.requestId,
          );
          SettingsService.instance.resetCacheTimer();
          _updateStatus(entry.requestId, RequestStatus.done);
        } catch (_) {
          pinCached = false;
        }
        if (pinCached) return;
      }

      final pin = await _promptPin(entry);
      if (pin == null) return;
      _updateStatus(entry.requestId, RequestStatus.responding);
      try {
        await mxRespondSignCard(
          roomId: roomId,
          requestId: entry.requestId,
          pin: pin,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, RequestStatus.done);
      } catch (e) {
        _updateStatusWithError(entry.requestId, e);
      }
      return;
    }

    final fp = entry.fingerprint ?? '';
    final cached = fp.isNotEmpty && await hasCachedPassphrase(fingerprint: fp);

    if (!cached) {
      final passphrase = await _promptPassphrase(entry);
      if (passphrase == null) return;

      _updateStatus(entry.requestId, RequestStatus.responding);
      try {
        await mxRespondSign(
          roomId: roomId,
          requestId: entry.requestId,
          passphrase: passphrase,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, RequestStatus.done);
      } catch (e) {
        _updateStatusWithError(entry.requestId, e);
      }
      return;
    }

    _updateStatus(entry.requestId, RequestStatus.responding);
    try {
      await mxRespondSignCached(roomId: roomId, requestId: entry.requestId);
      SettingsService.instance.resetCacheTimer();
      _updateStatus(entry.requestId, RequestStatus.done);
    } catch (_) {
      _updateStatus(entry.requestId, RequestStatus.pending);
      final passphrase = await _promptPassphrase(entry);
      if (passphrase == null) {
        _updateStatus(entry.requestId, RequestStatus.error);
        return;
      }
      _updateStatus(entry.requestId, RequestStatus.responding);
      try {
        await mxRespondSign(
          roomId: roomId,
          requestId: entry.requestId,
          passphrase: passphrase,
        );
        SettingsService.instance.resetCacheTimer();
        _updateStatus(entry.requestId, RequestStatus.done);
      } catch (e2) {
        _updateStatusWithError(entry.requestId, e2);
      }
    }
  }

  Future<void> _rejectSign(String requestId) async {
    final roomId = _agentRoom;
    if (roomId == null) return;

    _updateStatus(requestId, RequestStatus.error);
    try {
      await mxRejectSign(roomId: roomId, requestId: requestId);
    } catch (_) {}
  }

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
    WindowService.instance.bringToFront();

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

    WindowService.instance.bringToFront();

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
      // Notify the root shell so it restarts mxListenAll with the new room.
      widget.onRoomChanged?.call(picked.roomId);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to set agent room: $e')));
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
                          ? () => _approveSign(_log[i])
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
