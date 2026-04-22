import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'key_widgets.dart';

// ── Card-import sheet ─────────────────────────────────────────────────────────

class CardImportSheet extends StatefulWidget {
  const CardImportSheet({super.key, required this.onImported});
  final VoidCallback onImported;

  @override
  State<CardImportSheet> createState() => _CardImportSheetState();
}

class _CardImportSheetState extends State<CardImportSheet> {
  List<ConnectedCardInfo>? _cards;
  String? _loadError;
  String? _selectedIdent;

  final _uidCtrl = TextEditingController();
  final _pinCtrl = TextEditingController();
  String? _importError;
  bool _importing = false;

  @override
  void initState() {
    super.initState();
    _loadCards();
  }

  @override
  void dispose() {
    _uidCtrl.dispose();
    _pinCtrl.dispose();
    super.dispose();
  }

  Future<void> _loadCards() async {
    try {
      final cards = await listConnectedCards();
      if (!mounted) return;
      setState(() {
        _cards = cards;
        if (cards.isNotEmpty) {
          _selectCard(cards.first.ident, cards.first.cardholderName);
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _loadError = e.toString());
    }
  }

  void _selectCard(String ident, String cardholderName) {
    _selectedIdent = ident;
    final prev = _cards?.firstWhere(
      (c) => c.ident == _selectedIdent,
      orElse: () => ConnectedCardInfo(
        ident: '',
        cardholderName: '',
        sigFingerprint: null,
        authFingerprint: null,
      ),
    );
    final prevName = prev?.cardholderName ?? '';
    if (_uidCtrl.text.isEmpty || _uidCtrl.text == prevName) {
      _uidCtrl.text = cardholderName;
    }
  }

  Future<void> _doImport() async {
    final ident = _selectedIdent;
    if (ident == null) return;
    setState(() {
      _importing = true;
      _importError = null;
    });
    try {
      await importCard(
        cardIdent: ident,
        uid: _uidCtrl.text.trim(),
        pin: _pinCtrl.text,
      );
      if (!mounted) return;
      Navigator.pop(context);
      widget.onImported();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _importError = e.toString();
        _importing = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      minChildSize: 0.4,
      maxChildSize: 0.9,
      builder: (_, ctrl) => Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: cs.onSurface.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Row(
              children: [
                const Icon(Icons.contactless_outlined, size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Import from card',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                if (_importing)
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(child: _buildBody(ctrl, cs)),
        ],
      ),
    );
  }

  Widget _buildBody(ScrollController ctrl, ColorScheme cs) {
    if (_loadError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            _loadError!,
            style: const TextStyle(color: Color(0xFFFF453A), fontSize: 13),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    if (_cards == null) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_cards!.isEmpty) {
      return const Center(
        child: Text(
          'No OpenPGP cards connected.\nPlug in a YubiKey and try again.',
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
        ),
      );
    }

    return ListView(
      controller: ctrl,
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
      children: [
        const KeySectionLabel('Select card'),
        ..._cards!.map(
          (c) => CardTile(
            card: c,
            selected: _selectedIdent == c.ident,
            onTap: () => setState(() => _selectCard(c.ident, c.cardholderName)),
          ),
        ),
        const SizedBox(height: 16),

        const KeySectionLabel('User ID'),
        TextField(
          controller: _uidCtrl,
          style: const TextStyle(fontSize: 14),
          decoration: const InputDecoration(
            hintText: 'Alice <alice@example.com>',
            hintStyle: TextStyle(color: Color(0xFF8E8E93)),
            filled: true,
            fillColor: Color(0xFF2C2C2E),
            border: OutlineInputBorder(borderSide: BorderSide.none),
            contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
        ),
        const SizedBox(height: 4),
        const Text(
          'Leave blank to use the cardholder name stored on the card.',
          style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
        ),
        const SizedBox(height: 16),

        const KeySectionLabel('User Signing PIN'),
        TextField(
          controller: _pinCtrl,
          obscureText: true,
          style: const TextStyle(fontSize: 14),
          decoration: const InputDecoration(
            hintText: '······',
            hintStyle: TextStyle(color: Color(0xFF8E8E93)),
            filled: true,
            fillColor: Color(0xFF2C2C2E),
            border: OutlineInputBorder(borderSide: BorderSide.none),
            contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
          onSubmitted: (_) => _doImport(),
        ),
        const SizedBox(height: 4),
        const Text(
          'The card will create a self-signature — touch the YubiKey when prompted.',
          style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
        ),

        if (_importError != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFF3A0A0A),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFFFF453A)),
            ),
            child: Text(
              _importError!,
              style: const TextStyle(fontSize: 12, color: Color(0xFFFF453A)),
            ),
          ),
        ],
        const SizedBox(height: 20),

        FilledButton(
          onPressed: _importing ? null : _doImport,
          style: FilledButton.styleFrom(
            backgroundColor: const Color(0xFF0A84FF),
            minimumSize: const Size.fromHeight(44),
          ),
          child: _importing
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Colors.white,
                  ),
                )
              : const Text('Import key from card'),
        ),
      ],
    );
  }
}

// ── Card tile ─────────────────────────────────────────────────────────────────

class CardTile extends StatelessWidget {
  const CardTile({
    super.key,
    required this.card,
    required this.selected,
    required this.onTap,
  });

  final ConnectedCardInfo card;
  final bool selected;
  final VoidCallback onTap;

  String get _shortIdent {
    final id = card.ident;
    return id.length > 12 ? '…${id.substring(id.length - 12)}' : id;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: selected ? const Color(0xFF0A84FF) : const Color(0xFF3A3A3C),
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              Icons.contactless,
              size: 20,
              color: selected
                  ? const Color(0xFF0A84FF)
                  : const Color(0xFF8E8E93),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    card.cardholderName.isNotEmpty
                        ? card.cardholderName
                        : 'Unnamed card',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                      color: card.cardholderName.isNotEmpty
                          ? null
                          : const Color(0xFF8E8E93),
                    ),
                  ),
                  Text(
                    _shortIdent,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 10,
                      color: Color(0xFF8E8E93),
                    ),
                  ),
                ],
              ),
            ),
            if (selected)
              const Icon(
                Icons.check_circle,
                size: 18,
                color: Color(0xFF0A84FF),
              ),
          ],
        ),
      ),
    );
  }
}
