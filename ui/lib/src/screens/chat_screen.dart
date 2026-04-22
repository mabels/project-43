import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.room});

  final MxRoomInfo room;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final List<MxMessage> _messages = [];
  final _sendCtrl = TextEditingController();
  final _scrollCtrl = ScrollController();
  bool _sending = false;
  bool _connected = false;

  @override
  void initState() {
    super.initState();
    _startListen();
  }

  void _startListen() {
    mxListen(roomId: widget.room.roomId).listen(
      (msg) {
        if (!mounted) return;
        setState(() {
          _messages.add(msg);
          _connected = true;
        });
        WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());
      },
      onError: (e) {
        if (mounted) {
          setState(() => _connected = false);
        }
      },
      onDone: () {
        if (mounted) setState(() => _connected = false);
      },
    );
  }

  void _scrollToBottom() {
    if (_scrollCtrl.hasClients) {
      _scrollCtrl.animateTo(
        _scrollCtrl.position.maxScrollExtent,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    }
  }

  Future<void> _send() async {
    final text = _sendCtrl.text.trim();
    if (text.isEmpty) return;
    setState(() => _sending = true);
    try {
      await mxSend(roomId: widget.room.roomId, text: text);
      _sendCtrl.clear();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Send failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  void dispose() {
    _sendCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.room.name,
              style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
            ),
            Row(
              children: [
                if (widget.room.isEncrypted)
                  const Icon(Icons.lock, size: 11, color: Color(0xFF30D158)),
                if (widget.room.isEncrypted) const SizedBox(width: 4),
                Text(
                  _connected ? 'connected' : 'connecting…',
                  style: TextStyle(
                    fontSize: 11,
                    color: _connected
                        ? const Color(0xFF30D158)
                        : cs.onSurface.withValues(alpha: 0.45),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: _messages.isEmpty
                ? Center(
                    child: Text(
                      'No messages yet.',
                      style: TextStyle(
                        color: cs.onSurface.withValues(alpha: 0.45),
                      ),
                    ),
                  )
                : ListView.builder(
                    controller: _scrollCtrl,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 8,
                    ),
                    itemCount: _messages.length,
                    itemBuilder: (context, i) =>
                        _MessageBubble(message: _messages[i]),
                  ),
          ),
          _SendBar(controller: _sendCtrl, sending: _sending, onSend: _send),
        ],
      ),
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({required this.message});

  final MxMessage message;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            radius: 14,
            backgroundColor: _avatarColor(message.sender),
            child: Text(
              _initial(message.sender),
              style: const TextStyle(fontSize: 12, color: Colors.white),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _displayName(message.sender),
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: cs.onSurface.withValues(alpha: 0.6),
                  ),
                ),
                const SizedBox(height: 2),
                Text(message.body, style: const TextStyle(fontSize: 14)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _initial(String sender) {
    final local = sender.startsWith('@') ? sender.substring(1) : sender;
    return local.isNotEmpty ? local[0].toUpperCase() : '?';
  }

  String _displayName(String sender) {
    if (sender.startsWith('@')) {
      return sender.substring(1).split(':').first;
    }
    return sender;
  }

  Color _avatarColor(String sender) {
    const colors = [
      Color(0xFF0A84FF),
      Color(0xFF30D158),
      Color(0xFFFF9F0A),
      Color(0xFFFF453A),
      Color(0xFFBF5AF2),
      Color(0xFF64D2FF),
    ];
    return colors[sender.hashCode.abs() % colors.length];
  }
}

class _SendBar extends StatelessWidget {
  const _SendBar({
    required this.controller,
    required this.sending,
    required this.onSend,
  });

  final TextEditingController controller;
  final bool sending;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: const BoxDecoration(
          color: Color(0xFF2C2C2E),
          border: Border(top: BorderSide(color: Color(0xFF3A3A3C))),
        ),
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: controller,
                decoration: const InputDecoration(
                  hintText: 'Message…',
                  border: InputBorder.none,
                  isDense: true,
                  contentPadding: EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 8,
                  ),
                ),
                onSubmitted: (_) => onSend(),
                minLines: 1,
                maxLines: 4,
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: sending
                  ? const SizedBox(
                      height: 18,
                      width: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.send),
              onPressed: sending ? null : onSend,
            ),
          ],
        ),
      ),
    );
  }
}
