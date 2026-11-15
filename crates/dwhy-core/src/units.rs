//! Byte sizes: parsing `100M`-style arguments and compact IEC formatting.

/// Parses `0`, `512`, `100K`, `1.5G`, `2TiB`, `10MB` (all binary: K = 1024).
/// A trailing `%` is not handled here.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num
        .parse()
        .map_err(|_| format!("invalid size {s:?} (try 100M or 1G)"))?;
    let mult: u64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        "T" | "TB" | "TIB" => 1 << 40,
        _ => return Err(format!("invalid size unit in {s:?} (use K, M, G or T)")),
    };
    if !n.is_finite() || n < 0.0 {
        return Err(format!("invalid size {s:?}"));
    }
    Ok((n * mult as f64).round() as u64)
}

/// Compact binary size: `0B`, `512B`, `4.0K`, `182.4G`, `1.2T`.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    if bytes < 1024 {
        return format!("{bytes}B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 1000.0 {
        format!("{v:.0}{}", UNITS[i])
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

/// `12345678` -> `12,345,678`.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("512"), Ok(512));
        assert_eq!(parse_size("100M"), Ok(100 << 20));
        assert_eq!(parse_size("1.5G"), Ok(3 << 29));
        assert_eq!(parse_size("2TiB"), Ok(2 << 40));
        assert_eq!(parse_size("10mb"), Ok(10 << 20));
        assert!(parse_size("ten").is_err());
        assert!(parse_size("5X").is_err());
    }

    #[test]
    fn format() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(1023), "1023B");
        assert_eq!(human(4096), "4.0K");
        assert_eq!(human(195_891_408_896), "182.4G");
        assert_eq!(human(1023 << 20), "1023M");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(12), "12");
    }
}
