pub fn try_remove_prefix(hex: &str) -> &str {
    if hex.starts_with("0x") {
        return &hex[2..];
    }
    hex
}