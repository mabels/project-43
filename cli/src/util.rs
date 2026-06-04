//! Shared CLI utilities used by multiple subcommand modules.

/// Print `data` in classic hexdump format (16 bytes per line).
///
/// ```text
///   00000000  7b 22 6d 65 6e 6f 22  3a 22 61 62 65 6c 73 22  |{"meno":"abels"|
/// ```
pub fn hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let left = hex[..hex.len().min(8)].join(" ");
        let right = hex[8.min(hex.len())..].join(" ");
        let hex_col = format!("{left:<23}  {right:<23}");
        println!("  {:08x}  {}  |{ascii}|", i * 16, hex_col);
    }
}
