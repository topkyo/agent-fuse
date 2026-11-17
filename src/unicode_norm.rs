//! Pure-Rust Unicode NFD decomposition and Canonical Combining Class (CCC)
//! ordering for macOS APFS path equivalence comparisons without external links.

use std::path::Path;

fn combining_class(c: char) -> u8 {
    let u = c as u32;
    match u {
        0x0300..=0x0314 => 230,
        0x0315 => 232,
        0x0316..=0x0319 => 220,
        0x031A => 232,
        0x031B => 216,
        0x031C..=0x0320 => 220,
        0x0321..=0x0322 => 202,
        0x0323..=0x0326 => 220,
        0x0327..=0x0328 => 202,
        0x0329..=0x0333 => 220,
        0x0334..=0x0338 => 1,
        0x0339..=0x033C => 220,
        0x033D..=0x0344 => 230,
        0x0345 => 240,
        0x0346 => 230,
        0x0347..=0x0349 => 220,
        0x034A..=0x034C => 230,
        0x034D..=0x034E => 220,
        0x0350..=0x0352 => 230,
        0x0353..=0x0356 => 220,
        0x0357 => 230,
        0x0358 => 232,
        0x0359..=0x035A => 220,
        0x035B => 230,
        0x035C => 233,
        0x035D..=0x035E => 234,
        0x035F => 233,
        0x0360..=0x0361 => 234,
        0x0362 => 233,
        0x0363..=0x036F => 230,
        0x3099..=0x309A => 8,
        0x1DC0..=0x1DFF => 230,
        0x20D0..=0x20FF => 230,
        0xFE20..=0xFE2F => 230,
        _ => 0,
    }
}

fn decompose_precomposed(c: char) -> Option<&'static str> {
    match c {
        '\u{00C0}' => Some("A\u{0300}"), '\u{00C1}' => Some("A\u{0301}"),
        '\u{00C2}' => Some("A\u{0302}"), '\u{00C3}' => Some("A\u{0303}"),
        '\u{00C4}' => Some("A\u{0308}"), '\u{00C5}' => Some("A\u{030A}"),
        '\u{00C7}' => Some("C\u{0327}"), '\u{00C8}' => Some("E\u{0300}"),
        '\u{00C9}' => Some("E\u{0301}"), '\u{00CA}' => Some("E\u{0302}"),
        '\u{00CB}' => Some("E\u{0308}"), '\u{00CC}' => Some("I\u{0300}"),
        '\u{00CD}' => Some("I\u{0301}"), '\u{00CE}' => Some("I\u{0302}"),
        '\u{00CF}' => Some("I\u{0308}"), '\u{00D1}' => Some("N\u{0303}"),
        '\u{00D2}' => Some("O\u{0300}"), '\u{00D3}' => Some("O\u{0301}"),
        '\u{00D4}' => Some("O\u{0302}"), '\u{00D5}' => Some("O\u{0303}"),
        '\u{00D6}' => Some("O\u{0308}"), '\u{00D9}' => Some("U\u{0300}"),
        '\u{00DA}' => Some("U\u{0301}"), '\u{00DB}' => Some("U\u{0302}"),
        '\u{00DC}' => Some("U\u{0308}"), '\u{00DD}' => Some("Y\u{0301}"),
        '\u{00E0}' => Some("a\u{0300}"), '\u{00E1}' => Some("a\u{0301}"),
        '\u{00E2}' => Some("a\u{0302}"), '\u{00E3}' => Some("a\u{0303}"),
        '\u{00E4}' => Some("a\u{0308}"), '\u{00E5}' => Some("a\u{030A}"),
        '\u{00E7}' => Some("c\u{0327}"), '\u{00E8}' => Some("e\u{0300}"),
        '\u{00E9}' => Some("e\u{0301}"), '\u{00EA}' => Some("e\u{0302}"),
        '\u{00EB}' => Some("e\u{0308}"), '\u{00EC}' => Some("i\u{0300}"),
        '\u{00ED}' => Some("i\u{0301}"), '\u{00EE}' => Some("i\u{0302}"),
        '\u{00EF}' => Some("i\u{0308}"), '\u{00F1}' => Some("n\u{0303}"),
        '\u{00F2}' => Some("o\u{0300}"), '\u{00F3}' => Some("o\u{0301}"),
        '\u{00F4}' => Some("o\u{0302}"), '\u{00F5}' => Some("o\u{0303}"),
        '\u{00F6}' => Some("o\u{0308}"), '\u{00F9}' => Some("u\u{0300}"),
        '\u{00FA}' => Some("u\u{0301}"), '\u{00FB}' => Some("u\u{0302}"),
        '\u{00FC}' => Some("u\u{0308}"), '\u{00FD}' => Some("y\u{0301}"),
        '\u{00FF}' => Some("y\u{0308}"),
        '\u{0100}' => Some("A\u{0304}"), '\u{0101}' => Some("a\u{0304}"),
        '\u{0102}' => Some("A\u{0306}"), '\u{0103}' => Some("a\u{0306}"),
        '\u{0104}' => Some("A\u{0328}"), '\u{0105}' => Some("a\u{0328}"),
        '\u{0106}' => Some("C\u{0301}"), '\u{0107}' => Some("c\u{0301}"),
        '\u{010C}' => Some("C\u{030C}"), '\u{010D}' => Some("c\u{030C}"),
        '\u{010E}' => Some("D\u{030C}"), '\u{010F}' => Some("d\u{030C}"),
        '\u{0112}' => Some("E\u{0304}"), '\u{0113}' => Some("e\u{0304}"),
        '\u{011A}' => Some("E\u{030C}"), '\u{011B}' => Some("e\u{030C}"),
        '\u{011E}' => Some("G\u{0306}"), '\u{011F}' => Some("g\u{0306}"),
        '\u{012A}' => Some("I\u{0304}"), '\u{012B}' => Some("i\u{0304}"),
        '\u{0130}' => Some("I\u{0307}"),
        '\u{0143}' => Some("N\u{0301}"), '\u{0144}' => Some("n\u{0301}"),
        '\u{0147}' => Some("N\u{030C}"), '\u{0148}' => Some("n\u{030C}"),
        '\u{014C}' => Some("O\u{0304}"), '\u{014D}' => Some("o\u{0304}"),
        '\u{0150}' => Some("O\u{030B}"), '\u{0151}' => Some("o\u{030B}"),
        '\u{0158}' => Some("R\u{030C}"), '\u{0159}' => Some("r\u{030C}"),
        '\u{015A}' => Some("S\u{0301}"), '\u{015B}' => Some("s\u{0301}"),
        '\u{015E}' => Some("S\u{0327}"), '\u{015F}' => Some("s\u{0327}"),
        '\u{0160}' => Some("S\u{030C}"), '\u{0161}' => Some("s\u{030C}"),
        '\u{0164}' => Some("T\u{030C}"), '\u{0165}' => Some("t\u{030C}"),
        '\u{016A}' => Some("U\u{0304}"), '\u{016B}' => Some("u\u{0304}"),
        '\u{016E}' => Some("U\u{030A}"), '\u{016F}' => Some("u\u{030A}"),
        '\u{0170}' => Some("U\u{030B}"), '\u{0171}' => Some("u\u{030B}"),
        '\u{0178}' => Some("Y\u{0308}"),
        '\u{0179}' => Some("Z\u{0301}"), '\u{017A}' => Some("z\u{0301}"),
        '\u{017B}' => Some("Z\u{0307}"), '\u{017C}' => Some("z\u{0307}"),
        '\u{017D}' => Some("Z\u{030C}"), '\u{017E}' => Some("z\u{030C}"),
        '\u{01CD}' => Some("A\u{030C}"), '\u{01CE}' => Some("a\u{030C}"),
        '\u{01CF}' => Some("I\u{030C}"), '\u{01D0}' => Some("i\u{030C}"),
        '\u{01D1}' => Some("O\u{030C}"), '\u{01D2}' => Some("o\u{030C}"),
        '\u{01D3}' => Some("U\u{030C}"), '\u{01D4}' => Some("u\u{030C}"),
        '\u{01D5}' => Some("U\u{0308}\u{0304}"), '\u{01D6}' => Some("u\u{0308}\u{0304}"),
        '\u{01D7}' => Some("U\u{0308}\u{0301}"), '\u{01D8}' => Some("u\u{0308}\u{0301}"),
        '\u{01D9}' => Some("U\u{0308}\u{030C}"), '\u{01DA}' => Some("u\u{0308}\u{030C}"),
        '\u{01DB}' => Some("U\u{0308}\u{0300}"), '\u{01DC}' => Some("u\u{0308}\u{0300}"),
        '\u{0401}' => Some("\u{0415}\u{0308}"), '\u{0451}' => Some("\u{0435}\u{0308}"),
        '\u{0419}' => Some("\u{0418}\u{0306}"), '\u{0439}' => Some("\u{0438}\u{0306}"),
        '\u{1EA0}' => Some("A\u{0323}"), '\u{1EA1}' => Some("a\u{0323}"),
        '\u{1EBE}' => Some("E\u{0302}\u{0301}"), '\u{1EBF}' => Some("e\u{0302}\u{0301}"),
        '\u{1EC6}' => Some("E\u{0323}\u{0302}"), '\u{1EC7}' => Some("e\u{0323}\u{0302}"),
        '\u{2126}' => Some("\u{03A9}"), '\u{212A}' => Some("K"),
        '\u{212B}' => Some("A\u{030A}"),
        _ => None,
    }
}

fn decompose_kana_or_hangul(c: char, out: &mut Vec<(char, u8)>) {
    let u = c as u32;
    if (0xAC00..=0xD7A3).contains(&u) {
        let s_idx = u - 0xAC00;
        let l = 0x1100 + s_idx / 588;
        let v = 0x1161 + (s_idx % 588) / 28;
        let t_idx = s_idx % 28;
        if let Some(ch) = char::from_u32(l) { out.push((ch, 0)); }
        if let Some(ch) = char::from_u32(v) { out.push((ch, 0)); }
        if t_idx > 0 {
            if let Some(ch) = char::from_u32(0x11A7 + t_idx) { out.push((ch, 0)); }
        }
        return;
    }
    let kana_base = match u {
        0x304C | 0x304E | 0x3050 | 0x3052 | 0x3054 | 0x3056 | 0x3058 | 0x305A | 0x305C
        | 0x305E | 0x3060 | 0x3062 | 0x3065 | 0x3067 | 0x3069 | 0x3070 | 0x3073 | 0x3076
        | 0x3079 | 0x307C | 0x30AC | 0x30AE | 0x30B0 | 0x30B2 | 0x30B4 | 0x30B6 | 0x30B8
        | 0x30BA | 0x30BC | 0x30BE | 0x30C0 | 0x30C2 | 0x30C5 | 0x30C7 | 0x30C9 | 0x30D0
        | 0x30D3 | 0x30D6 | 0x30D9 | 0x30DC => Some((u - 1, '\u{3099}')),
        0x3071 | 0x3074 | 0x3077 | 0x307A | 0x307D | 0x30D1 | 0x30D4 | 0x30D7 | 0x30DA
        | 0x30DD => Some((u - 2, '\u{309A}')),
        0x3094 => Some((0x3046, '\u{3099}')),
        0x30F4 => Some((0x30A6, '\u{3099}')),
        _ => None,
    };
    if let Some((base, mark)) = kana_base {
        if let Some(ch) = char::from_u32(base) {
            out.push((ch, 0));
            out.push((mark, 8));
            return;
        }
    }
    if let Some(dec) = decompose_precomposed(c) {
        for ch in dec.chars() {
            out.push((ch, combining_class(ch)));
        }
    } else {
        out.push((c, combining_class(c)));
    }
}

/// Normalizes a UTF-8 string into canonical NFD order for NFC/NFD comparison.
pub fn to_nfd(input: &str) -> String {
    if input.is_ascii() {
        return input.to_string();
    }
    let mut seq: Vec<(char, u8)> = Vec::with_capacity(input.len());
    for c in input.chars() {
        decompose_kana_or_hangul(c, &mut seq);
    }
    let mut i = 0usize;
    while i < seq.len() {
        if seq[i].1 == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < seq.len() && seq[i].1 != 0 {
            i += 1;
        }
        seq[start..i].sort_by_key(|item| item.1);
    }
    seq.into_iter().map(|(c, _)| c).collect()
}

/// Returns a Unicode NFD-normalized path key with forward-slash separators.
pub fn canonical_rel_key(rel: &str) -> String {
    let norm = rel.trim_start_matches("./");
    if norm.is_ascii() {
        return norm.to_string();
    }
    norm.split('/')
        .map(to_nfd)
        .collect::<Vec<_>>()
        .join("/")
}

/// Checks Unicode NFD canonical equality between two path components.
pub fn components_equal_canonical(a: &Path, b: &Path) -> bool {
    to_nfd(&a.to_string_lossy()) == to_nfd(&b.to_string_lossy())
}

/// Checks case-insensitive Unicode NFD equality between two path components.
pub fn components_equal_casefold_nfd(a: &Path, b: &Path) -> bool {
    to_nfd(&a.to_string_lossy()).to_lowercase() == to_nfd(&b.to_string_lossy()).to_lowercase()
}
