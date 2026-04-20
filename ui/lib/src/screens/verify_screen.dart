import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

class VerifyScreen extends StatefulWidget {
  const VerifyScreen({super.key});

  @override
  State<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends State<VerifyScreen> {
  List<MxEmojiInfo> _emojis = [];
  String _status = 'Waiting for verification request…';
  bool _done = false;
  bool _canConfirm = false;

  @override
  void initState() {
    super.initState();
    _startVerify();
  }

  void _startVerify() {
    mxStartVerify().listen(
      (event) {
        if (!mounted) return;
        if (event is MxVerifyEvent_Waiting) {
          setState(() => _status = 'Waiting for verification request…');
        } else if (event is MxVerifyEvent_RequestReceived) {
          setState(() => _status = 'Request received — exchanging keys…');
        } else if (event is MxVerifyEvent_Emojis) {
          setState(() {
            _emojis = event.emojis;
            _status = 'Compare these emojis with the other device:';
            _canConfirm = true;
          });
        } else if (event is MxVerifyEvent_Done) {
          setState(() {
            _status = 'Verification complete ✓';
            _done = true;
            _canConfirm = false;
          });
        } else if (event is MxVerifyEvent_Cancelled) {
          setState(() {
            _status = 'Cancelled: ${event.reason}';
            _done = true;
            _canConfirm = false;
          });
        }
      },
      onError: (e) {
        if (mounted) {
          setState(() {
            _status = 'Error: $e';
            _done = true;
            _canConfirm = false;
          });
        }
      },
      onDone: () {
        if (mounted && !_done) {
          setState(() {
            _status = 'Verification ended.';
            _done = true;
          });
        }
      },
    );
  }

  Future<void> _confirm(bool accepted) async {
    setState(() => _canConfirm = false);
    try {
      await mxConfirmVerify(confirmed: accepted);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
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
        title: const Text('Verify Device'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              _status,
              style: TextStyle(
                fontSize: 14,
                color: cs.onSurface.withValues(alpha: 0.7),
              ),
              textAlign: TextAlign.center,
            ),
            if (_emojis.isNotEmpty) ...[
              const SizedBox(height: 24),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 12,
                runSpacing: 12,
                children: _emojis
                    .map((e) => _EmojiTile(emoji: e))
                    .toList(),
              ),
            ],
            const SizedBox(height: 32),
            if (_canConfirm) ...[
              FilledButton(
                onPressed: () => _confirm(true),
                child: const Text('They match — Confirm'),
              ),
              const SizedBox(height: 10),
              OutlinedButton(
                onPressed: () => _confirm(false),
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFFFF453A),
                  side: const BorderSide(color: Color(0xFFFF453A)),
                ),
                child: const Text('They don\'t match — Cancel'),
              ),
            ],
            if (_done) ...[
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Close'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _EmojiTile extends StatelessWidget {
  const _EmojiTile({required this.emoji});

  final MxEmojiInfo emoji;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 72,
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 6),
      decoration: BoxDecoration(
        color: const Color(0xFF2C2C2E),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF3A3A3C)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(emoji.symbol, style: const TextStyle(fontSize: 28)),
          const SizedBox(height: 4),
          Text(
            emoji.description,
            style: const TextStyle(fontSize: 10),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}
