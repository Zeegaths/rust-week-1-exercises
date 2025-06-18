pub fn extract_tx_version(raw_tx_hex: &str) -> Result<u32, String> {
    // Checks if hex string has at least 8 characters (4 bytes)
    if raw_tx_hex.len() < 8 {
        return Err("Transaction data too short".to_string());
    }

    // Extracts first 8 hex characters (4 bytes)
    let version_hex = &raw_tx_hex[0..8];

    // Converts hex string to bytes
    let version_bytes = hex::decode(version_hex).map_err(|_| "Hex decode error".to_string())?;

    // Converts 4 bytes to u32 using little-endian byte order
    if version_bytes.len() != 4 {
        return Err("Version field must be exactly 4 bytes".to_string());
    }

    let version = u32::from_le_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);

    Ok(version)
}
