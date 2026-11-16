use crate::apfs::real_home_dir;
use crate::error::{AfuseError, ERR_EINVAL};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const HOOK_MARKER_BEGIN: &str = "# >>> afuse hook v1 >>>";
pub(crate) const HOOK_MARKER_END: &str = "# <<< afuse hook <<<";
#[derive(Debug, Clone)]
pub struct UninstallAction {
    pub path: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub applied: bool,
    pub backup_path: Option<String>,
}
pub fn render_hook_snippet(target: &str) -> Result<String, AfuseError> {
    match target {
        "zsh" => Ok(format!(
            "{begin}\n\
             if [[ -n \"${{ZSH_VERSION:-}}\" ]]; then\n\
             \x20 if (( ! ${{+functions[_afuse_preexec]}} )); then\n\
             \x20   autoload -Uz add-zsh-hook\n\
             \x20   _afuse_preexec() {{\n\
             \x20     [[ \"${{AFUSE_HOOK_DISABLE:-0}}\" == \"1\" || \"${{AFUSE_GUARDED:-0}}\" == \"1\" ]] && return 0\n\
             \x20     [[ -n \"${{1:-}}\" && \"$1\" == *(claude|cursor-agent|codex|aider|gemini|opencode|goose)* ]] || return 0\n\
             \x20     local -a _af_w=(${{=1}})\n\
             \x20     local _af_i=1 _af_n=${{#_af_w}} _af_pkg=\"\"\n\
             \x20     while (( _af_i <= _af_n )); do\n\
             \x20       local _af_tok=\"${{_af_w[$_af_i]}}\"\n\
             \x20       if [[ \"$_af_tok\" == *=* && \"$_af_tok\" != -* ]]; then\n\
             \x20         _af_i=$((_af_i + 1))\n\
             \x20       elif [[ \"$_af_tok\" == (env|command|exec|nohup|time) ]]; then\n\
             \x20         local _af_wrap=\"$_af_tok\"\n\
             \x20         _af_i=$((_af_i + 1))\n\
             \x20         while (( _af_i <= _af_n )) && [[ \"${{_af_w[$_af_i]}}\" == -* ]]; do\n\
             \x20           [[ \"$_af_wrap\" == \"command\" && \"${{_af_w[$_af_i]}}\" == (-v|-V) ]] && return 0\n\
             \x20           [[ \"${{_af_w[$_af_i]}}\" == (-u|-S|-C) ]] && _af_i=$((_af_i + 1))\n\
             \x20           _af_i=$((_af_i + 1))\n\
             \x20         done\n\
             \x20       elif [[ \"$_af_tok\" == (npx|bunx|pnpx|uvx) ]]; then\n\
             \x20         _af_i=$((_af_i + 1))\n\
             \x20         while (( _af_i <= _af_n )) && [[ \"${{_af_w[$_af_i]}}\" == -* ]]; do\n\
             \x20           [[ \"${{_af_w[$_af_i]}}\" == (--from|--package|-p|-c) ]] && _af_i=$((_af_i + 1))\n\
             \x20           _af_i=$((_af_i + 1))\n\
             \x20         done\n\
             \x20         if (( _af_i <= _af_n )); then\n\
             \x20           local _af_p=\"${{_af_w[$_af_i]}}\"\n\
             \x20           _af_pkg=\"${{${{_af_p:t}}%@*}}\"\n\
             \x20         fi\n\
             \x20         break\n\
             \x20       else\n\
             \x20         break\n\
             \x20       fi\n\
             \x20     done\n\
             \x20     local _af_raw=\"${{_af_w[$_af_i]:-}}\"\n\
             \x20     local _af_cmd=\"${{_af_pkg:-${{_af_raw:t}}}}\"\n\
             \x20     case \"$_af_cmd\" in\n\
             \x20       claude|cursor-agent|codex|aider|gemini|opencode|goose|claude-code)\n\
             \x20         local _af_bin=\"\"\n\
             \x20         if command -v afuse >/dev/null 2>&1; then\n\
             \x20           _af_bin=\"afuse\"\n\
             \x20         elif [[ -x \"$HOME/.local/bin/afuse\" ]]; then\n\
             \x20           _af_bin=\"$HOME/.local/bin/afuse\"\n\
             \x20         elif [[ -x \"/Applications/AgentFuse.app/Contents/MacOS/afuse\" ]]; then\n\
             \x20           _af_bin=\"/Applications/AgentFuse.app/Contents/MacOS/afuse\"\n\
             \x20         fi\n\
             \x20         [[ -n \"$_af_bin\" ]] && command \"$_af_bin\" hook zsh --exec --cwd \"$PWD\" --tool \"$_af_cmd\" >/dev/null 2>&1 || true\n\
             \x20         ;;\n\
             \x20     esac\n\
             \x20   }}\n\
             \x20   add-zsh-hook preexec _afuse_preexec\n\
             \x20 fi\n\
             fi\n\
             {end}\n",
            begin = HOOK_MARKER_BEGIN,
            end = HOOK_MARKER_END
        )),
        "claude" => Ok(String::from(
            "{\n\
             \x20 \"hooks\": {\n\
             \x20   \"PreToolUse\": [\n\
             \x20     {\n\
             \x20       \"matcher\": \"Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*\",\n\
             \x20       \"hooks\": [\n\
             \x20         {\n\
             \x20           \"type\": \"command\",\n\
             \x20           \"command\": \"if command -v afuse >/dev/null 2>&1; then afuse hook claude --exec; elif [ -x \\\"$HOME/.local/bin/afuse\\\" ]; then \\\"$HOME/.local/bin/afuse\\\" hook claude --exec; elif [ -x \\\"/Applications/AgentFuse.app/Contents/MacOS/afuse\\\" ]; then \\\"/Applications/AgentFuse.app/Contents/MacOS/afuse\\\" hook claude --exec; fi || true\",\n\
             \x20           \"timeout\": 10\n\
             \x20         }\n\
             \x20       ]\n\
             \x20     }\n\
             \x20   ]\n\
             \x20 }\n\
             }\n",
        )),
        other => Err(AfuseError::new(
            ERR_EINVAL,
            format!(
                "unsupported hook target '{}': expected 'zsh', 'claude', or 'uninstall'",
                other
            ),
        )),
    }
}
pub fn uninstall_hooks(
    apply: bool,
    home_override: Option<&Path>,
    workspace: &Path,
) -> Result<Vec<UninstallAction>, AfuseError> {
    let home = match home_override {
        Some(h) => h.to_path_buf(),
        None => {
            if let Ok(custom) = env::var("AFUSE_UNINSTALL_HOME") {
                if !custom.trim().is_empty() {
                    PathBuf::from(custom)
                } else {
                    real_home_dir()?
                }
            } else {
                real_home_dir()?
            }
        }
    };

    let mut actions = Vec::new();
    let shell_files = [home.join(".zshrc"), home.join(".zprofile")];

    for sf in &shell_files {
        let Ok(raw) = fs::read_to_string(sf) else {
            continue;
        };
        let lines: Vec<&str> = raw.lines().collect();
        let mut blocks: Vec<(usize, usize)> = Vec::new();
        let mut cur_begin: Option<usize> = None;
        for (idx, line) in lines.iter().enumerate() {
            if line.trim() == HOOK_MARKER_BEGIN && cur_begin.is_none() {
                cur_begin = Some(idx);
            } else if line.trim() == HOOK_MARKER_END {
                if let Some(b) = cur_begin.take() {
                    blocks.push((b, idx));
                }
            }
        }
        if !blocks.is_empty() {
            let mut backup_path = None;
            let mut did_apply = false;
            if apply {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let bak = PathBuf::from(format!("{}.afuse-bak-{}", sf.display(), ts));
                fs::copy(sf, &bak).map_err(|err| {
                    AfuseError::new(
                        err.raw_os_error().unwrap_or(1),
                        format!("backup failed {}: {}", bak.display(), err),
                    )
                })?;
                let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
                for (idx, line) in lines.iter().enumerate() {
                    if !blocks.iter().any(|(b, e)| idx >= *b && idx <= *e) {
                        kept.push(*line);
                    }
                }
                let mut updated = kept.join("\n");
                if !updated.is_empty() && raw.ends_with('\n') {
                    updated.push('\n');
                }
                fs::write(sf, updated).map_err(|err| {
                    AfuseError::new(
                        err.raw_os_error().unwrap_or(1),
                        format!("write failed {}: {}", sf.display(), err),
                    )
                })?;
                backup_path = Some(bak.to_string_lossy().into_owned());
                did_apply = true;
            }
            for (b, e) in blocks {
                actions.push(UninstallAction {
                    path: sf.to_string_lossy().into_owned(),
                    kind: "zsh_marker_block".to_string(),
                    start_line: b + 1,
                    end_line: e + 1,
                    applied: did_apply,
                    backup_path: backup_path.clone(),
                });
            }
        } else {
            for (idx, line) in lines.iter().enumerate() {
                if line.contains("afuse hook") {
                    actions.push(UninstallAction {
                        path: sf.to_string_lossy().into_owned(),
                        kind: "manual_shell_line".to_string(),
                        start_line: idx + 1,
                        end_line: idx + 1,
                        applied: false,
                        backup_path: None,
                    });
                }
            }
        }
    }

    let claude_files = [
        home.join(".claude").join("settings.json"),
        workspace.join(".claude").join("settings.json"),
    ];
    for cf in &claude_files {
        let Ok(raw) = fs::read_to_string(cf) else {
            continue;
        };
        for (idx, line) in raw.lines().enumerate() {
            if line.contains("afuse") {
                actions.push(UninstallAction {
                    path: cf.to_string_lossy().into_owned(),
                    kind: "manual_claude_settings_json".to_string(),
                    start_line: idx + 1,
                    end_line: idx + 1,
                    applied: false,
                    backup_path: None,
                });
            }
        }
    }

    Ok(actions)
}
