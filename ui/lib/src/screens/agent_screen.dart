import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

class AgentScreen extends StatefulWidget {
  const AgentScreen({super.key});

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
      (event) {
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
          setState(() => _log.insert(
                0,
                _RequestEntry(
                  type: 'ssh.sign_request',
                  requestId: event.requestId,
                  description: event.description,
                  fingerprint: event.fingerprint,
                  status: _RequestStatus.pending,
                ),
              ));
        }
        // Keep log bounded.
        if (_log.length > 50) _log.removeLast();
      },
      onError: (_) => setState(() => _listening = false),
      onDone: () => setState(() => _listening = false),
    );
  }

  Future<void> _autoRespondListKeys(String roomId, String requestId) async {
    try {
      await mxRespondListKeys(roomId: roomId, requestId: requestId);
      _updateStatus(requestId, _RequestStatus.done);
    } catch (e) {
      _updateStatus(requestId, _RequestStatus.error);
    }
  }

  void _updateStatus(String requestId, _RequestStatus status) {
    if (!mounted) return;
    setState(() {
      final idx = _log.indexWhere((e) => e.requestId == requestId);
      if (idx != -1) _log[idx] = _log[idx].copyWith(status: status);
    });
  }

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
                    itemBuilder: (context, i) => _LogTile(entry: _log[i]),
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
  const _LogTile({required this.entry});

  final _RequestEntry entry;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: const Color(0xFF3A3A3C)),
        ),
        child: Row(
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
                  if (entry.description != null)
                    Text(
                      entry.description!,
                      style: TextStyle(
                          fontSize: 11,
                          color: cs.onSurface.withValues(alpha: 0.6)),
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
      _RequestStatus.pending    => const Color(0xFFFF9F0A),
      _RequestStatus.responding => const Color(0xFF0A84FF),
      _RequestStatus.done       => const Color(0xFF30D158),
      _RequestStatus.error      => const Color(0xFFFF453A),
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
      _RequestStatus.pending    => ('pending',    const Color(0xFFFF9F0A)),
      _RequestStatus.responding => ('responding', const Color(0xFF0A84FF)),
      _RequestStatus.done       => ('done',       const Color(0xFF30D158)),
      _RequestStatus.error      => ('error',      const Color(0xFFFF453A)),
    };
    return Text(label,
        style: TextStyle(fontSize: 10, color: color, fontFamily: 'monospace'));
  }
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
  });

  final String type;
  final String requestId;
  final String? description;
  final String? fingerprint;
  final _RequestStatus status;

  _RequestEntry copyWith({_RequestStatus? status}) => _RequestEntry(
        type: type,
        requestId: requestId,
        description: description,
        fingerprint: fingerprint,
        status: status ?? this.status,
      );
}
