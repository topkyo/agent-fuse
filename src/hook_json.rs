//! Claude Code PreToolUse JSON scanner and command-line path extractor.

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClaudeHookPayload {
    pub cwd: Option<String>,
    pub tool_name: Option<String>,
    pub bash_command: Option<String>,
    pub candidate_paths: Vec<String>,
}

fn push_unique_candidate(list: &mut Vec<String>, val: String) {
    let trimmed = val.trim();
    if !trimmed.is_empty() && !list.iter().any(|x| x == trimmed) {
        list.push(trimmed.to_string());
    }
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn parse_hex4(b: &[u8], idx: usize) -> Option<u32> {
    let hex = b.get(idx..idx + 4)?;
    std::str::from_utf8(hex)
        .ok()
        .and_then(|s| u32::from_str_radix(s, 16).ok())
}

fn parse_json_string(b: &[u8], i: &mut usize) -> Option<String> {
    if *i >= b.len() || b[*i] != b'"' {
        return None;
    }
    *i += 1;
    let mut s = String::new();
    while *i < b.len() {
        let ch = b[*i];
        *i += 1;
        if ch == b'"' {
            return Some(s);
        }
        if ch == b'\\' && *i < b.len() {
            let esc = b[*i];
            *i += 1;
            match esc {
                b'"' => s.push('"'),
                b'\\' => s.push('\\'),
                b'/' => s.push('/'),
                b'b' => s.push('\u{0008}'),
                b'f' => s.push('\u{000C}'),
                b'n' => s.push('\n'),
                b'r' => s.push('\r'),
                b't' => s.push('\t'),
                b'u' => {
                    if let Some(u1) = parse_hex4(b, *i) {
                        *i += 4;
                        if (0xD800..=0xDBFF).contains(&u1)
                            && b.get(*i..*i + 2) == Some(b"\\u")
                        {
                            if let Some(u2) = parse_hex4(b, *i + 2) {
                                if (0xDC00..=0xDFFF).contains(&u2) {
                                    *i += 6;
                                    let cp = 0x10000 + (((u1 - 0xD800) << 10) | (u2 - 0xDC00));
                                    s.push(char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER));
                                    continue;
                                }
                            }
                            s.push(char::REPLACEMENT_CHARACTER);
                        } else if (0xD800..=0xDFFF).contains(&u1) {
                            s.push(char::REPLACEMENT_CHARACTER);
                        } else if let Some(c) = char::from_u32(u1) {
                            s.push(c);
                        }
                    }
                }
                _ => s.push(esc as char),
            }
        } else {
            let start = *i - 1;
            while *i < b.len() && b[*i] != b'"' && b[*i] != b'\\' && b[*i] >= 0x80 {
                *i += 1;
            }
            if *i > start + 1 {
                if let Ok(utf8) = std::str::from_utf8(&b[start..*i]) {
                    s.push_str(utf8);
                } else {
                    s.push(char::REPLACEMENT_CHARACTER);
                }
            } else {
                s.push(ch as char);
            }
        }
    }
    None
}

fn is_candidate_path_key(key: &str) -> bool {
    matches!(
        key,
        "file_path"
            | "path"
            | "target_file"
            | "notebook_path"
            | "destination"
            | "old_path"
            | "new_path"
            | "target"
    )
}

pub fn parse_claude_hook_json(input: &str) -> ClaudeHookPayload {
    let mut out = ClaudeHookPayload::default();
    let b = input.as_bytes();
    let mut i = 0usize;
    let mut obj_depth = 0usize;
    let mut expect_value_for: Option<(usize, String)> = None;
    let mut in_tool_input = false;
    let mut in_paths_array_at: Option<usize> = None;

    while i < b.len() {
        skip_ws(b, &mut i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'{' => {
                obj_depth += 1;
                if obj_depth == 2
                    && matches!(&expect_value_for, Some((1, k)) if k == "tool_input")
                {
                    in_tool_input = true;
                }
                expect_value_for = None;
                i += 1;
            }
            b'}' => {
                if obj_depth == 2 {
                    in_tool_input = false;
                    in_paths_array_at = None;
                }
                obj_depth = obj_depth.saturating_sub(1);
                expect_value_for = None;
                i += 1;
            }
            b'[' => {
                if in_tool_input
                    && matches!(&expect_value_for, Some((d, k)) if *d >= 2 && (k == "paths" || k == "files"))
                {
                    in_paths_array_at = Some(obj_depth);
                }
                expect_value_for = None;
                i += 1;
            }
            b']' => {
                if in_paths_array_at == Some(obj_depth) {
                    in_paths_array_at = None;
                }
                expect_value_for = None;
                i += 1;
            }
            b',' => {
                if in_paths_array_at != Some(obj_depth) {
                    expect_value_for = None;
                }
                i += 1;
            }
            b':' => i += 1,
            b'"' => {
                if let Some(s) = parse_json_string(b, &mut i) {
                    if let Some((k_depth, ref key)) = expect_value_for {
                        if k_depth == 1 && key == "cwd" {
                            out.cwd = Some(s);
                        } else if k_depth == 1 && key == "tool_name" {
                            out.tool_name = Some(s);
                        } else if in_tool_input && k_depth == 2 && (key == "command" || key == "cmd") {
                            out.bash_command = Some(s);
                        } else if in_tool_input && k_depth >= 2 && is_candidate_path_key(key) {
                            push_unique_candidate(&mut out.candidate_paths, s);
                        }
                        expect_value_for = None;
                    } else if in_paths_array_at == Some(obj_depth) {
                        push_unique_candidate(&mut out.candidate_paths, s);
                    } else {
                        let mut peek = i;
                        skip_ws(b, &mut peek);
                        if peek < b.len() && b[peek] == b':' {
                            expect_value_for = Some((obj_depth, s));
                        }
                    }
                } else {
                    break;
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    out
}

fn split_shell_words(cmd: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if q == '"' && ch == '\\' {
                if let Some(next_c) = chars.next() {
                    cur.push(next_c);
                }
            } else {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next_c) = chars.next() {
                    cur.push(next_c);
                }
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            ';' | '|' | '&' => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                let mut sep = String::from(ch);
                if (ch == '|' || ch == '&') && chars.peek() == Some(&ch) {
                    sep.push(chars.next().unwrap());
                }
                words.push(sep);
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Extracts plausible file or folder tokens from a shell command line.
pub fn extract_bash_candidate_paths(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_cmd_verb = true;
    for raw in split_shell_words(cmd) {
        if matches!(raw.as_str(), "&&" | "||" | ";" | "|") {
            skip_cmd_verb = true;
            continue;
        }
        let trimmed_raw = raw.trim_matches(|c| c == '"' || c == '\'' || c == ';');
        let redir_target = trimmed_raw
            .strip_prefix(">>")
            .or_else(|| trimmed_raw.strip_prefix('>'))
            .or_else(|| trimmed_raw.strip_prefix("1>>"))
            .or_else(|| trimmed_raw.strip_prefix("1>"))
            .or_else(|| trimmed_raw.strip_prefix("2>>"))
            .or_else(|| trimmed_raw.strip_prefix("2>"))
            .or_else(|| trimmed_raw.strip_prefix("&>"));
        if let Some(target) = redir_target {
            let t = target.trim_matches(|c| c == '"' || c == '\'' || c == ';');
            if !t.is_empty() && t != "/dev/null" && !t.starts_with('&') && !t.starts_with('$') {
                push_unique_candidate(&mut out, t.to_string());
            }
            continue;
        }
        let tok = trimmed_raw;
        if tok.is_empty() || tok == "/dev/null" {
            continue;
        }
        if skip_cmd_verb {
            if !tok.contains('=') {
                skip_cmd_verb = false;
            }
            continue;
        }
        if tok.starts_with('-') || tok.starts_with('$') {
            continue;
        }
        push_unique_candidate(&mut out, tok.to_string());
    }
    out
}

pub fn is_supported_claude_tool(tool: &str) -> bool {
    if tool.is_empty()
        || matches!(tool, "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "Bash")
    {
        return true;
    }
    let Some(rest) = tool.strip_prefix("mcp__") else {
        return false;
    };
    let action = rest.rsplit("__").next().unwrap_or(rest);
    let mut norm = String::with_capacity(action.len() + 8);
    for ch in action.chars() {
        if ch.is_ascii_uppercase() && !norm.is_empty() && !norm.ends_with('_') {
            norm.push('_');
        }
        norm.push(if ch == '-' { '_' } else { ch.to_ascii_lowercase() });
    }
    let tokens: Vec<&str> = norm.split('_').filter(|t| !t.is_empty()).collect();
    if tokens.iter().any(|t| {
        matches!(
            *t,
            "write" | "edit" | "create" | "delete" | "del" | "remove" | "rm" | "unlink"
                | "move" | "mv" | "rename" | "mkdir" | "rmdir" | "patch" | "replace"
                | "truncate" | "append" | "overwrite" | "update" | "modify" | "save"
                | "exec" | "run" | "shell" | "bash" | "cmd" | "command" | "apply"
                | "reset" | "clean" | "checkout" | "restore"
        )
    }) {
        return true;
    }
    !( !tokens.is_empty()
        && tokens.iter().any(|t| {
            matches!(
                *t,
                "read" | "get" | "list" | "ls" | "search" | "find" | "grep" | "stat"
                    | "view" | "inspect" | "status" | "diff" | "log" | "show" | "info"
                    | "head" | "tail" | "tree" | "cat"
            )
        }) )
}
