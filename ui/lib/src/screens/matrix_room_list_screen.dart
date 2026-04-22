import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'chat_screen.dart';
import 'verify_screen.dart';

class MatrixRoomListScreen extends StatefulWidget {
  const MatrixRoomListScreen({super.key, required this.onLoggedOut});

  final VoidCallback onLoggedOut;

  @override
  State<MatrixRoomListScreen> createState() => _MatrixRoomListScreenState();
}

class _MatrixRoomListScreenState extends State<MatrixRoomListScreen> {
  late Future<List<MxRoomInfo>> _roomsFuture;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  void _reload() {
    setState(() {
      _roomsFuture = mxListRooms();
    });
  }

  Future<void> _logout() async {
    try {
      await mxLogout();
      widget.onLoggedOut();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Logout failed: $e')));
      }
    }
  }

  Future<void> _joinRoom() async {
    final ctrl = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Join Room'),
        content: TextField(
          controller: ctrl,
          decoration: const InputDecoration(
            labelText: 'Room ID or alias',
            hintText: '#room:matrix.org',
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Join'),
          ),
        ],
      ),
    );
    if (confirmed != true || ctrl.text.trim().isEmpty) return;

    try {
      await mxJoinRoom(room: ctrl.text.trim());
      _reload();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to join: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text('Rooms'),
        actions: [
          IconButton(
            icon: const Icon(Icons.verified_user_outlined),
            tooltip: 'Verify device',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const VerifyScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Logout',
            onPressed: _logout,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _joinRoom,
        tooltip: 'Join room',
        child: const Icon(Icons.add),
      ),
      body: FutureBuilder<List<MxRoomInfo>>(
        future: _roomsFuture,
        builder: (context, snap) {
          if (snap.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  snap.error.toString(),
                  style: const TextStyle(color: Color(0xFFFF453A)),
                  textAlign: TextAlign.center,
                ),
              ),
            );
          }
          final rooms = snap.data!;
          if (rooms.isEmpty) {
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text('💬', style: TextStyle(fontSize: 40)),
                  const SizedBox(height: 12),
                  const Text('No rooms yet.'),
                  const SizedBox(height: 8),
                  FilledButton.icon(
                    onPressed: _joinRoom,
                    icon: const Icon(Icons.add, size: 16),
                    label: const Text('Join a room'),
                  ),
                ],
              ),
            );
          }
          return RefreshIndicator(
            onRefresh: () async => _reload(),
            child: ListView.separated(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              itemCount: rooms.length,
              separatorBuilder: (context, idx) => const SizedBox(height: 8),
              itemBuilder: (context, i) => _RoomTile(
                room: rooms[i],
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => ChatScreen(room: rooms[i])),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

class _RoomTile extends StatelessWidget {
  const _RoomTile({required this.room, required this.onTap});

  final MxRoomInfo room;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFF3A3A3C)),
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    room.name,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    room.roomId,
                    style: TextStyle(
                      fontSize: 10,
                      color: cs.onSurface.withValues(alpha: 0.45),
                      fontFamily: 'monospace',
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            if (room.isEncrypted)
              const Padding(
                padding: EdgeInsets.only(left: 8),
                child: Icon(Icons.lock, size: 16, color: Color(0xFF30D158)),
              ),
            const Icon(Icons.chevron_right, size: 18),
          ],
        ),
      ),
    );
  }
}
