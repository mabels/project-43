// ── Key display helpers ────────────────────────────────────────────────────────
// Shared between key_list_screen.dart and agent_screen.dart.

/// Converts a card ident like `"0006:17684870"` to `"cardno:17_684_870"`.
/// Groups the serial digits in threes from the right, separated by underscores.
String cardnoFromIdent(String ident) {
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
String keyLabel(String uid, List<String> cardIdents) {
  if (cardIdents.isEmpty) return uid;
  final labels = cardIdents.map(cardnoFromIdent);
  return '$uid ${labels.join(', ')}';
}
