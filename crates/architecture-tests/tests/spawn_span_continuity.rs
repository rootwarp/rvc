//! TRC-6c: pin production executor sites to tracing ADR-009.
//!
//! Scans **tracked** sources only:
//!
//! ```text
//! git -c core.quotePath=false ls-files -z -- 'crates/rvc/**/*.rs' 'bin/rvc/**/*.rs'
//! ```
//!
//! Paths are NUL-delimited. A non-UTF-8 path, or a file that cannot be read,
//! is an error. A path is kept when it ends in `.rs` and does not contain
//! `/tests/`. A site is a call whose receiver ident ends in `executor` and
//! whose method is `spawn`, `spawn_result`, `register`, `register_result`, or
//! `register_opt`. `register_opt` is a site unless its last argument is `None`,
//! or `None::<...>` whose `>` closes inside that argument and nothing follows
//! it. `None::<fn() -> u8>` is a site, because `->` supplies that `>`. A last
//! argument wrapped in `{}`, `()`, or `[]` is still that argument. Commas split
//! the list on `()` `[]` `{}` depth only; `<` and `>` do not nest.
//! `spawn_blocking` is not a site. `RawIdent` on a receiver or a method is that
//! ident with `r#` removed. `r#None` is not the `None` sentinel. Comments and
//! strings are not idents. The scan keeps reading inside a call's arguments, so
//! a nested call is visited too. A `::<` with no `>` inside the enclosing call
//! does not consume tokens past that call.
//!
//! The production cut is the first token `#[cfg(test)]` followed by `mod`
//! (`bn_test_cut`). A bare `#[cfg(test)]` does not end the region.
//! `liveness_loop.rs` has method-level attributes above the production spawn.
//! A call at or after the attribute is not a site. `bn_test_cut` errors when a
//! non-gap token follows the module. This scan returns that error when a call
//! it recognizes starts at or after the module end, including one nested in an
//! earlier call's arguments. A tail with no such call still uses the cut. The
//! production prefix is checked with the lexer mask, so a multibyte
//! char literal there fails the file. One inside the test module is outside
//! that prefix. A `///` or `//!` line is a comment, not a call, so the `run`
//! doc comment in `liveness_loop.rs` ("Spawns no tasks") is not a spawn.
//!
//! A site passes only when:
//!
//! 1. the immediately preceding non-empty line is a `// detached:` comment, or
//! 2. it is one of the five shape-B spawns in
//!    `plan/tracing-2026-08-06/spawn-census.md`, and the loop **file** named there
//!    contains `parent: None` and `follows_from` for that task.
//!
//! A window around the spawn line is not classification (2). `monitoring_push` and
//! `proposer_config_refresh` are spawned in `bootstrap/tasks.rs`; their loops live
//! in other files. The allow-list is empty. The pin is 16 (5 shape B, 11 detached,
//! shape A = 0).
//!
//! Census rows are content anchors. A production site is `(file, enclosing
//! item, task, call)`. A shape-B loop is `(loop file, item containing the
//! loop)`. A not-site is `(file, enclosing item, task)`. The task is the whole
//! first argument: a plain string literal, or the only `const` of that name in
//! the production prefix whose initializer is a plain string followed by `;`.
//! The next token after that argument is a comma. `enclosing_item` resolves
//! the item on that prefix. A hit inside an item whose name is declared twice,
//! an untrusted token stream, a raw ident the resolver refuses, or a hit
//! outside every fn and `macro_rules!` fails the file. The call scan still sees a call in that file; the anchor does not
//! return a successful list that omitted it. A blank line does not change an
//! anchor. A census path cell is repo-relative.
//!
//! `census_anchors_match_sources` checks those rows, the liveness content
//! shape, and the bn-manager section. The liveness shape is token order: the
//! first bare `#[cfg(test)]` sits on a function, a later bare `#[cfg(test)]`
//! does not, and a column-0 `#[cfg(test)]` is followed by `mod`. The production
//! spawn is after that first attribute and before the module attribute.
//!
//! The bn-manager section is separate. Its rows name the enclosing item.
//! An untrusted token stream fails that file. The production site list comes
//! from `find_production_sites`. Not-sites use the same `executor_calls` scan.

use ra_ap_rustc_lexer::{tokenize, FrontmatterAllowed, LiteralKind, TokenKind};
use rvc_architecture_tests::{non_code_spans, SourceItems};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Production-site pin. 5 shape B + 11 detached + shape A = 0.
const PIN: usize = 16;
const SHAPE_B_PIN: usize = 5;
const DETACHED_PIN: usize = 11;
const SHAPE_A_PIN: usize = 0;

const CENSUS: &str = "plan/tracing-2026-08-06/spawn-census.md";

/// Empty. A site is classified by a `// detached:` comment or a census shape-B
/// row. Entries are never an escape hatch.
const ALLOW_LIST: &[(&str, u32)] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Spawn,
    Register,
    RegisterOpt,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Register => "register",
            Self::RegisterOpt => "register_opt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    path: String,
    /// Diagnostic only. Census keys do not use it.
    line: usize,
    item: String,
    task: String,
    kind: Kind,
    /// Immediately preceding non-empty line is a `// detached:` comment.
    detached: bool,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NotSite {
    path: String,
    item: String,
    task: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShapeBRow {
    task: String,
    spawn_path: String,
    spawn_item: String,
    loop_path: String,
    loop_item: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Detached,
    ShapeB,
    /// Census row matched, but the loop file lacks `parent: None` / `follows_from`.
    ShapeBLoopMissing,
    /// Shape-B spawn line also carries `// detached:`.
    ShapeBWithDetached,
    Unclassified,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

// ---------------------------------------------------------------------------
// Tracked-file scan
// ---------------------------------------------------------------------------

fn tracked_rs_files(root: &Path) -> Result<Vec<String>, String> {
    tracked_nul(root, "executor", &["crates/rvc/**/*.rs", "bin/rvc/**/*.rs"])
}

// The production cut is `executor_cut`: the first `#[cfg(test)]` followed by `mod`.
// A bare attribute does not end the region.

#[derive(Debug)]
struct ExecHit {
    at: usize,
    /// Token index of the call's `(`.
    open: usize,
    kind: Kind,
    is_site: bool,
}

fn exec_method(name: &str) -> Option<Kind> {
    match name {
        "spawn" | "spawn_result" => Some(Kind::Spawn),
        "register" | "register_result" => Some(Kind::Register),
        "register_opt" => Some(Kind::RegisterOpt),
        _ => None,
    }
}

/// `None` or `None::<...>`, and nothing else, from `start` up to `end`.
fn none_sentinel(src: &str, toks: &[(usize, usize, TokenKind)], start: usize, end: usize) -> bool {
    let i = next_solid(toks, start);
    if i >= end || !word_is(src, toks, i, "None") {
        return false;
    }
    let mut j = next_solid(toks, i + 1);
    if j >= end {
        return true;
    }
    if !matches!(toks[j].2, TokenKind::Colon) {
        return false;
    }
    j = next_solid(toks, j + 1);
    if j >= end || !matches!(toks[j].2, TokenKind::Colon) {
        return false;
    }
    j = next_solid(toks, j + 1);
    if j >= end || !matches!(toks[j].2, TokenKind::Lt) {
        return false;
    }
    // The closing `>` has to sit inside this argument. `->` inside it still closes early.
    let Some(after) = skip_until_before(toks, j, end, TokenKind::Lt, TokenKind::Gt) else {
        return false;
    };
    next_solid(toks, after) >= end
}

/// Last argument, found from the end. `()` `[]` `{}` nest. `<` and `>` do not.
fn last_arg_is_none(
    src: &str,
    toks: &[(usize, usize, TokenKind)],
    open: usize,
    close: usize,
) -> bool {
    let mut paren = 0i32;
    let mut brack = 0i32;
    let mut brace = 0i32;
    let mut end = close;
    let mut saw = false;
    let mut i = close;
    while i > open {
        i -= 1;
        let kind = toks[i].2;
        let flat = paren == 0 && brack == 0 && brace == 0;
        // A closer at flat depth is part of the last argument (`{ Some(h) }`).
        if flat && !matches!(kind, TokenKind::Comma) && !is_gap(kind) {
            saw = true;
        }
        match kind {
            TokenKind::CloseParen => paren += 1,
            TokenKind::OpenParen => paren -= 1,
            TokenKind::CloseBracket => brack += 1,
            TokenKind::OpenBracket => brack -= 1,
            TokenKind::CloseBrace => brace += 1,
            TokenKind::OpenBrace => brace -= 1,
            TokenKind::Comma if flat => {
                if saw {
                    return none_sentinel(src, toks, i + 1, end);
                }
                end = i;
            }
            _ => {}
        }
    }
    saw && none_sentinel(src, toks, open + 1, end)
}

fn executor_calls(src: &str, toks: &[(usize, usize, TokenKind)]) -> Result<Vec<ExecHit>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    // Exclusive token index of the call whose arguments we are inside.
    let mut limit = vec![toks.len()];
    while i < toks.len() {
        while limit.len() > 1 && i >= *limit.last().unwrap() {
            limit.pop();
        }
        if !call_word(src, &toks[i]).is_some_and(|word| word.ends_with("executor")) {
            i += 1;
            continue;
        }
        let dot = next_solid(toks, i + 1);
        let name = next_solid(toks, dot + 1);
        let kind = toks.get(name).and_then(|tok| call_word(src, tok)).and_then(exec_method);
        if !matches!(toks.get(dot).map(|tok| tok.2), Some(TokenKind::Dot)) || kind.is_none() {
            i += 1;
            continue;
        }
        let mut open = next_solid(toks, name + 1);
        if matches!(toks.get(open).map(|tok| tok.2), Some(TokenKind::Colon)) {
            let colon2 = next_solid(toks, open + 1);
            let lt = next_solid(toks, colon2 + 1);
            if !matches!(toks.get(colon2).map(|tok| tok.2), Some(TokenKind::Colon))
                || !matches!(toks.get(lt).map(|tok| tok.2), Some(TokenKind::Lt))
            {
                i += 1;
                continue;
            }
            let end = *limit.last().unwrap();
            let Some(after) = skip_until_before(toks, lt, end, TokenKind::Lt, TokenKind::Gt) else {
                // No closer inside this call. At end of file that is an error.
                // Inside a call, keep scanning so a later spawn is not dropped.
                if end == toks.len() {
                    return Err("unclosed turbofish".to_string());
                }
                i += 1;
                continue;
            };
            open = next_solid(toks, after);
            if open >= end {
                i += 1;
                continue;
            }
        }
        if !matches!(toks.get(open).map(|tok| tok.2), Some(TokenKind::OpenParen)) {
            i += 1;
            continue;
        }
        let Some(after_close) = skip_until(toks, open, TokenKind::OpenParen, TokenKind::CloseParen)
        else {
            return Err("unclosed call".to_string());
        };
        let close = after_close - 1;
        let is_site = match kind.unwrap() {
            Kind::RegisterOpt => !last_arg_is_none(src, toks, open, close),
            Kind::Spawn | Kind::Register => true,
        };
        out.push(ExecHit { at: toks[i].0, open, kind: kind.unwrap(), is_site });
        // Keep scanning the argument list so a nested call is not skipped.
        // The turbofish skip above cannot run past this call.
        limit.push(after_close);
        i = open + 1;
    }
    Ok(out)
}

/// Attribute byte of the first `#[cfg(test)] mod`, and the byte after that module.
fn test_mod_span(src: &str, toks: &[(usize, usize, TokenKind)]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i].2, TokenKind::Pound) {
            if let Some(after) = cfg_test_attr_end(src, toks, i) {
                if let Some(mod_i) = mod_after(src, toks, after) {
                    if let Some(end) = module_end(toks, mod_i) {
                        return Some((toks[i].0, end));
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// `bn_test_cut`, except a non-gap token after the module is an error only
/// when a recognized call starts at or after the module end.
fn executor_cut(src: &str, toks: &[(usize, usize, TokenKind)]) -> Result<Option<usize>, String> {
    match bn_test_cut(src, toks) {
        Ok(cut) => Ok(cut),
        Err(msg) if msg == "production code follows the test module" => {
            let Some((cut, end)) = test_mod_span(src, toks) else {
                return Err(msg);
            };
            let calls = executor_calls(src, toks)?;
            if calls.iter().any(|hit| hit.at >= end) {
                Err(msg)
            } else {
                Ok(Some(cut))
            }
        }
        Err(msg) => Err(msg),
    }
}

type Lexed = Vec<(usize, usize, TokenKind)>;

/// Tokens for the whole file. The production prefix is checked with the mask.
fn executor_lex(src: &str) -> Result<(Lexed, Option<usize>), String> {
    let toks = lex_file(src, false)?;
    let cut = executor_cut(src, &toks)?;
    lex_file(&src[..cut.unwrap_or(src.len())], true)?;
    Ok((toks, cut))
}

fn is_detached_comment(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("// detached:") && !t.starts_with("///")
}

fn preceding_nonempty<'a>(lines: &[&'a str], line_1based: usize) -> Option<&'a str> {
    let mut i = line_1based;
    while i > 1 {
        i -= 1;
        if !lines[i - 1].trim().is_empty() {
            return Some(lines[i - 1]);
        }
    }
    None
}

enum TaskConst {
    Plain(String),
    Other,
}

/// A plain `"..."` literal. Escapes, raw strings, and byte strings are `Err`
/// so a caller can fail closed instead of treating them as a different token.
fn plain_task_string(src: &str, tok: &(usize, usize, TokenKind)) -> Result<Option<String>, String> {
    match tok.2 {
        TokenKind::Literal { kind: LiteralKind::Str { terminated: true }, .. } => {
            let text = src.get(tok.0..tok.1).ok_or("task string is not a char boundary")?;
            if text.contains('\\') {
                return Err("escaped task string".to_string());
            }
            text.strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .map(|inner| Some(inner.to_string()))
                .ok_or_else(|| "task string is not a plain literal".to_string())
        }
        TokenKind::Literal { kind: LiteralKind::RawStr { .. }, .. }
        | TokenKind::Literal { kind: LiteralKind::ByteStr { .. }, .. }
        | TokenKind::Literal { kind: LiteralKind::RawByteStr { .. }, .. }
        | TokenKind::Literal { kind: LiteralKind::CStr { .. }, .. }
        | TokenKind::Literal { kind: LiteralKind::RawCStr { .. }, .. } => {
            Err("task string is not a plain literal".to_string())
        }
        TokenKind::Literal { kind: LiteralKind::Str { terminated: false }, .. } => {
            Err("unterminated task string".to_string())
        }
        _ => Ok(None),
    }
}

/// `const NAME = "...";` in the production prefix. Two consts of one name fail.
/// The initializer counts only when the next token is `;`. Anything else is
/// other and rejected at the call that uses it, so an unused const does not
/// hide a later spawn.
fn const_strings(
    src: &str,
    toks: &[(usize, usize, TokenKind)],
    prefix: usize,
) -> Result<HashMap<String, TaskConst>, String> {
    let mut out = HashMap::new();
    let mut i = 0;
    while i < toks.len() {
        if toks[i].0 >= prefix || !word_is(src, toks, i, "const") {
            i += 1;
            continue;
        }
        let name_i = next_solid(toks, i + 1);
        let Some(name) = toks.get(name_i).and_then(|tok| call_word(src, tok)) else {
            i += 1;
            continue;
        };
        let colon = next_solid(toks, name_i + 1);
        if toks.get(colon).map(|tok| tok.2) != Some(TokenKind::Colon) || toks[colon].0 >= prefix {
            i += 1;
            continue;
        }
        let mut value_at = None;
        let mut j = colon + 1;
        while j < toks.len() && toks[j].0 < prefix {
            match toks[j].2 {
                TokenKind::Eq => {
                    value_at = Some(next_solid(toks, j + 1));
                    break;
                }
                TokenKind::Semi | TokenKind::OpenBrace => break,
                _ => j += 1,
            }
        }
        let kind = match value_at {
            Some(at) => {
                let Some(tok) = toks.get(at).filter(|tok| tok.0 < prefix) else {
                    i += 1;
                    continue;
                };
                match plain_task_string(src, tok) {
                    Ok(Some(text)) => {
                        let semi = next_solid(toks, at + 1);
                        if toks
                            .get(semi)
                            .is_some_and(|tok| tok.2 == TokenKind::Semi && tok.0 < prefix)
                        {
                            TaskConst::Plain(text)
                        } else {
                            TaskConst::Other
                        }
                    }
                    Ok(None) | Err(_) => TaskConst::Other,
                }
            }
            None => {
                i += 1;
                continue;
            }
        };
        let name = name.to_string();
        if out.insert(name.clone(), kind).is_some() {
            return Err(format!("ambiguous task const `{name}`"));
        }
        i += 1;
    }
    Ok(out)
}

fn task_of(
    src: &str,
    toks: &[(usize, usize, TokenKind)],
    open: usize,
    consts: &HashMap<String, TaskConst>,
) -> Result<String, String> {
    let i = next_solid(toks, open + 1);
    let Some(tok) = toks.get(i) else {
        return Err("call has no task argument".to_string());
    };
    let next = next_solid(toks, i + 1);
    let bare = matches!(toks.get(next).map(|tok| tok.2), Some(TokenKind::Comma));
    if let Some(text) = plain_task_string(src, tok)? {
        if !bare {
            return Err("task argument is not a bare string or ident".to_string());
        }
        return Ok(text);
    }
    let Some(name) = call_word(src, tok) else {
        return Err("unrecognised task argument".to_string());
    };
    if toks.get(next).map(|tok| tok.2) == Some(TokenKind::Bang) {
        return Err(format!("task macro `{name}`"));
    }
    if toks.get(next).map(|tok| tok.2) == Some(TokenKind::Colon) {
        let colon2 = next_solid(toks, next + 1);
        if toks.get(colon2).map(|tok| tok.2) == Some(TokenKind::Colon) {
            return Err(format!("task path `{name}`"));
        }
    }
    if !bare {
        return Err("task argument is not a bare string or ident".to_string());
    }
    match consts.get(name) {
        Some(TaskConst::Plain(text)) => Ok(text.clone()),
        Some(TaskConst::Other) => Err(format!("task const `{name}` is not a plain string")),
        None => Err(format!("unresolved task const `{name}`")),
    }
}

fn item_name(items: &SourceItems, path: &str, at: usize) -> Result<String, String> {
    match items.enclosing(at) {
        Ok(id) => Ok(id.as_str().to_string()),
        Err(err) => Err(format!("row {path}: {err}")),
    }
}

struct Prepared {
    toks: Lexed,
    prefix: usize,
    items: SourceItems,
    consts: HashMap<String, TaskConst>,
    calls: Vec<ExecHit>,
}

fn prepare_file(path: &str, src: &str) -> Result<Prepared, String> {
    let (toks, cut) = executor_lex(src).map_err(|err| format!("row {path}: {err}"))?;
    let prefix = cut.unwrap_or(src.len());
    let calls = executor_calls(src, &toks).map_err(|err| format!("row {path}: {err}"))?;
    let items = SourceItems::parse(&src[..prefix]).map_err(|err| format!("row {path}: {err}"))?;
    let consts = const_strings(src, &toks, prefix).map_err(|err| format!("row {path}: {err}"))?;
    Ok(Prepared { toks, prefix, items, consts, calls })
}

fn find_production_sites(path: &str, src: &str) -> Result<Vec<Site>, String> {
    let prepared = prepare_file(path, src)?;
    let lines: Vec<&str> = src.lines().collect();
    let starts = line_starts(src);
    let mut sites = Vec::new();
    for hit in &prepared.calls {
        if hit.at >= prepared.prefix || !hit.is_site {
            continue;
        }
        let line = starts.partition_point(|start| *start <= hit.at);
        let text = lines[line - 1].trim().to_string();
        let detached = preceding_nonempty(&lines, line).is_some_and(is_detached_comment);
        let item = item_name(&prepared.items, path, hit.at)?;
        let task = task_of(src, &prepared.toks, hit.open, &prepared.consts)
            .map_err(|err| format!("row {path}: {err}"))?;
        sites.push(Site {
            path: path.to_string(),
            line,
            item,
            task,
            kind: hit.kind,
            detached,
            text,
        });
    }
    Ok(sites)
}

fn not_site_anchors(path: &str, src: &str) -> Result<Vec<NotSite>, String> {
    let prepared = prepare_file(path, src)?;
    let mut out = Vec::new();
    for hit in &prepared.calls {
        if hit.at >= prepared.prefix || hit.is_site || hit.kind != Kind::RegisterOpt {
            continue;
        }
        let item = item_name(&prepared.items, path, hit.at)?;
        if item == "<module>" {
            return Err(format!("row {path}: refusing <module>"));
        }
        let task = task_of(src, &prepared.toks, hit.open, &prepared.consts)
            .map_err(|err| format!("row {path}: {err}"))?;
        out.push(NotSite { path: path.to_string(), item, task });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Census shape B
// ---------------------------------------------------------------------------

fn parse_shape_b(census: &str) -> Result<Vec<ShapeBRow>, String> {
    let mut rows = Vec::new();
    for cells in census_rows(&section_body(census, "Shape B loop sites"), 5)? {
        repo_rel(&cells[1])?;
        repo_rel(&cells[3])?;
        if rows.iter().any(|row: &ShapeBRow| {
            row.task == cells[0] && row.spawn_path == cells[1] && row.spawn_item == cells[2]
        }) {
            return Err(format!("duplicate shape-B row {}", cells.join(" | ")));
        }
        rows.push(ShapeBRow {
            task: cells[0].clone(),
            spawn_path: cells[1].clone(),
            spawn_item: cells[2].clone(),
            loop_path: cells[3].clone(),
            loop_item: cells[4].clone(),
        });
    }
    Ok(rows)
}

/// `parent: None` on the same line as the task string. `follows_from` anywhere.
/// Two such lines, or a string span that is not a char boundary, fail the file.
fn shape_b_parents(loop_src: &str, task: &str) -> Result<Vec<usize>, String> {
    let toks = lex_file(loop_src, false)?;
    let starts = line_starts(loop_src);
    let mut parents = Vec::new();
    let mut follows = false;
    let mut line = 0usize;
    let mut saw_pair = false;
    let mut saw_task = false;
    let mut pair_at = 0usize;
    for i in 0..toks.len() {
        let this = starts.partition_point(|at| *at <= toks[i].0);
        if this != line {
            if saw_pair && saw_task {
                parents.push(pair_at);
            }
            line = this;
            saw_pair = false;
            saw_task = false;
        }
        if word_is(loop_src, &toks, i, "parent") {
            let colon = next_solid(&toks, i + 1);
            let none = next_solid(&toks, colon + 1);
            let colon_line = toks.get(colon).map(|tok| starts.partition_point(|at| *at <= tok.0));
            let none_line = toks.get(none).map(|tok| starts.partition_point(|at| *at <= tok.0));
            if matches!(toks.get(colon).map(|tok| tok.2), Some(TokenKind::Colon))
                && word_is(loop_src, &toks, none, "None")
                && colon_line == Some(this)
                && none_line == Some(this)
            {
                saw_pair = true;
                pair_at = toks[i].0;
            }
        }
        if let TokenKind::Literal { kind: LiteralKind::Str { terminated: true }, .. } = toks[i].2 {
            let text = loop_src.get(toks[i].0..toks[i].1).ok_or_else(|| {
                format!("shape-B task string is not a char boundary at {}", toks[i].0)
            })?;
            let plain = text.strip_prefix('"').and_then(|rest| rest.strip_suffix('"'));
            if !text.contains('\\') && plain == Some(task) {
                saw_task = true;
            }
        }
        if word_is(loop_src, &toks, i, "follows_from") {
            follows = true;
        }
    }
    if saw_pair && saw_task {
        parents.push(pair_at);
    }
    if !follows {
        return Ok(Vec::new());
    }
    if parents.len() > 1 {
        return Err(format!("ambiguous shape-B parent for task `{task}`"));
    }
    Ok(parents)
}

fn loop_file_has_shape_b(loop_src: &str, task: &str) -> Result<bool, String> {
    Ok(!shape_b_parents(loop_src, task)?.is_empty())
}

/// Item containing the `loop` for this task. The `parent: None` line and the
/// `loop` keyword share that item. `<module>` is refused.
fn loop_item(path: &str, src: &str, task: &str) -> Result<String, String> {
    let parents = shape_b_parents(src, task)?;
    if parents.len() != 1 {
        return Err(format!("shape-B parent count for `{task}` is {}", parents.len()));
    }
    let at = parents[0];
    let prepared = prepare_file(path, src)?;
    if at >= prepared.prefix {
        return Err(format!(
            "row {path}: shape-B parent for `{task}` is outside the production prefix"
        ));
    }
    let item = item_name(&prepared.items, path, at)?;
    if item == "<module>" {
        return Err(format!("row {path}: refusing <module> for shape-B task `{task}`"));
    }
    let mut has_loop = false;
    let mut resolve_err = None;
    for (i, tok) in prepared.toks.iter().enumerate() {
        if tok.0 >= prepared.prefix || !word_is(src, &prepared.toks, i, "loop") {
            continue;
        }
        let brace = next_solid(&prepared.toks, i + 1);
        if prepared.toks.get(brace).map(|tok| tok.2) != Some(TokenKind::OpenBrace) {
            continue;
        }
        match prepared.items.enclosing(tok.0) {
            Ok(id) if id.as_str() == item => has_loop = true,
            Ok(_) => {}
            Err(err) => resolve_err = Some(format!("row {path}: {err}")),
        }
    }
    if !has_loop {
        if let Some(err) = resolve_err {
            return Err(err);
        }
        return Err(format!("row {path}: item `{item}` has no `loop` for task `{task}`"));
    }
    Ok(item)
}

fn classify(site: &Site, rows: &[ShapeBRow], mut loop_ok: impl FnMut(&ShapeBRow) -> bool) -> Class {
    if let Some(row) = rows.iter().find(|row| {
        row.spawn_path == site.path && row.spawn_item == site.item && row.task == site.task
    }) {
        if site.detached {
            return Class::ShapeBWithDetached;
        }
        if loop_ok(row) {
            return Class::ShapeB;
        }
        return Class::ShapeBLoopMissing;
    }
    if site.detached {
        Class::Detached
    } else {
        Class::Unclassified
    }
}

// ---------------------------------------------------------------------------
// Failure text (count drift)
// ---------------------------------------------------------------------------

fn pin_failure(found: usize, detail: &str) -> String {
    format!(
        "production executor site count is {found}, pin is {PIN} \
         ({SHAPE_B_PIN} shape B, {DETACHED_PIN} detached, shape A = {SHAPE_A_PIN}).\n\
         Exclusion rule: end each file's production region at the first token \
         `#[cfg(test)]` followed by `mod` (do not truncate at the first bare \
         `#[cfg(test)]`); a `///` or `//!` line is a comment, not a call; \
         `register_opt(..., None)` is not a site; drop paths containing `/tests/`.\n\
         A site passes only when (1) the immediately preceding non-empty line is a \
         `// detached:` comment, or (2) it is one of the five census shape-B spawns \
         and the loop file named in {CENSUS} contains `parent: None` and \
         `follows_from` for that task. A same-file window is not enough.\n\
         This pin is tracing ADR-009.\n\
         {detail}"
    )
}

fn load_executor(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for rel in tracked_rs_files(root)? {
        let src =
            std::fs::read_to_string(root.join(&rel)).map_err(|err| format!("row {rel}: {err}"))?;
        out.push((rel, src));
    }
    Ok(out)
}

fn scan_workspace(root: &Path) -> Result<(Vec<Site>, Vec<ShapeBRow>), String> {
    let files = load_executor(root)?;
    if files.len() <= 40 {
        return Err(format!(
            "scanned only {} tracked files under crates/rvc and bin/rvc; git ls-files likely broke",
            files.len()
        ));
    }
    let census =
        std::fs::read_to_string(root.join(CENSUS)).map_err(|err| format!("row {CENSUS}: {err}"))?;
    let rows = parse_shape_b(&census)?;
    let mut sites = collect_anchored_sites(&files)?;
    sites.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    Ok((sites, rows))
}

fn collect_anchored_sites(files: &[(String, String)]) -> Result<Vec<Site>, String> {
    let mut sites = Vec::new();
    for (rel, src) in files {
        for site in find_production_sites(rel, src)? {
            if site.item == "<module>" {
                return Err(format!("row {rel}: refusing <module> for task {}", site.task));
            }
            sites.push(site);
        }
    }
    Ok(sites)
}

fn loop_ok_for<'a>(root: &'a Path) -> impl Fn(&ShapeBRow) -> Result<bool, String> + 'a {
    move |row: &ShapeBRow| {
        let src = read_repo_file(root, &row.loop_path)?;
        if !loop_file_has_shape_b(&src, &row.task)? {
            return Ok(false);
        }
        let item = loop_item(&row.loop_path, &src, &row.task)?;
        if item != row.loop_item {
            return Err(format!(
                "row {}: shape-B task `{}` loop item is `{item}`, census says `{}`",
                row.loop_path, row.task, row.loop_item
            ));
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

#[test]
fn production_executor_sites_pin_sixteen() {
    assert!(
        ALLOW_LIST.is_empty(),
        "allow-list stays empty; classify with a // detached: comment or a census shape-B row"
    );

    let root = workspace_root();
    let (sites, rows) = scan_workspace(&root).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(
        rows.len(),
        SHAPE_B_PIN,
        "shape-B table in {CENSUS} must name {SHAPE_B_PIN} loop files; found {}",
        rows.len()
    );

    let loop_ok = loop_ok_for(&root);
    let mut detached = 0usize;
    let mut shape_b = 0usize;
    let shape_a = 0usize;
    let mut problems: Vec<String> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();

    for site in &sites {
        let class = classify(site, &rows, |row| match loop_ok(row) {
            Ok(ok) => ok,
            Err(err) => {
                problems.push(err);
                false
            }
        });
        let label = match class {
            Class::Detached => {
                detached += 1;
                "detached"
            }
            Class::ShapeB => {
                shape_b += 1;
                "shape-B"
            }
            Class::ShapeBLoopMissing => "shape-B-loop-missing",
            Class::ShapeBWithDetached => "shape-B-has-detached-comment",
            Class::Unclassified => "unclassified",
        };
        rendered.push(format!(
            "{} {} `{}` {} {label} (line {})",
            site.path,
            site.item,
            site.task,
            site.kind.as_str(),
            site.line
        ));
        if !matches!(class, Class::Detached | Class::ShapeB) {
            problems.push(format!(
                "{} {} `{}`: {label} (line {})",
                site.path, site.item, site.task, site.line
            ));
        }
    }

    for row in &rows {
        let seen = sites.iter().any(|site| {
            site.path == row.spawn_path && site.item == row.spawn_item && site.task == row.task
        });
        if !seen {
            problems.push(format!(
                "census shape-B row {} {} ({}) is not a production site",
                row.spawn_path, row.spawn_item, row.task
            ));
        }
    }

    let ok = sites.len() == PIN
        && detached == DETACHED_PIN
        && shape_b == SHAPE_B_PIN
        && shape_a == SHAPE_A_PIN
        && problems.is_empty();
    assert!(
        ok,
        "{}",
        pin_failure(
            sites.len(),
            &format!(
                "counted {detached} detached, {shape_b} shape B, shape A = {shape_a}.\n\
                 problems:\n  {}\n\
                 sites:\n  {}",
                if problems.is_empty() { "(none)".to_string() } else { problems.join("\n  ") },
                rendered.join("\n  ")
            )
        )
    );
}

#[test]
fn allow_list_stays_empty() {
    assert!(
        ALLOW_LIST.is_empty(),
        "allow-list stays empty under tracing ADR-009; do not seed exemptions"
    );
}

#[test]
fn failure_names_the_exclusion_rule_and_tracing_adr_009() {
    let msg = pin_failure(15, "synthetic count drift");
    assert!(msg.contains("tracing ADR-009"), "{msg}");
    assert!(msg.contains("#[cfg(test)]"), "{msg}");
    assert!(msg.contains("followed by `mod`"), "{msg}");
    assert!(msg.contains("///"), "{msg}");
    assert!(msg.contains("register_opt(..., None)"), "{msg}");
    assert!(msg.contains("// detached:"), "{msg}");
    assert!(msg.contains("parent: None"), "{msg}");
    assert!(msg.contains("follows_from"), "{msg}");
    assert!(msg.contains(CENSUS), "{msg}");
    assert!(msg.contains("same-file window is not enough"), "{msg}");
    // The phrase must be the tracing decision, not a bare ADR-009.
    assert!(!msg.contains("architecture ADR-009"), "{msg}");
}

#[test]
fn bare_cfg_test_does_not_hide_the_liveness_loop_spawn() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/rvc/src/liveness_loop.rs")).unwrap();
    liveness_shape(&src).unwrap();
    assert!(
        src.contains("Spawns no tasks"),
        "re-locate the run() doc comment; it must not be scanned as a spawn"
    );
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", &src).unwrap();
    assert_eq!(sites.len(), 1, "doc comment and test-module spawns must not count: {sites:?}");
    assert_eq!(sites[0].item, "spawn_liveness_loop");
    assert_eq!(sites[0].task, "liveness_loop");
    assert!(!sites[0].detached, "the shape-B spawn has no // detached: comment");
    let shifted = format!("\n{src}");
    liveness_shape(&shifted).unwrap();
    let again = find_production_sites("crates/rvc/src/liveness_loop.rs", &shifted).unwrap();
    assert_eq!(again[0].item, sites[0].item);
    assert_eq!(again[0].task, sites[0].task);
}

#[test]
fn doc_comment_mentioning_a_spawn_is_not_a_site() {
    let src = "\
/// Run until cancelled. Spawns no tasks — call from `tokio::spawn`.\n\
/// Also not a site: executor.spawn(\n\
//! module doc executor.register(\n\
pub async fn run(self) {}\n\
";
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", src).unwrap();
    assert!(sites.is_empty(), "doc comments are not spawns: {sites:?}");
}

#[test]
fn register_opt_none_is_not_a_site_and_some_is() {
    let src = "\
        executor.register_opt::<()>(SSE_TASK_NAME, ShutdownTier::Background, None);\n\
        executor.register_opt::<()>(\n\
            NAME,\n\
            ShutdownTier::Background,\n\
            None,\n\
        );\n\
        executor.register_opt(\"enabled\", ShutdownTier::Background, Some(handle));\n\
        executor.register_opt(\n\
            \"later\",\n\
            ShutdownTier::Background,\n\
            Some(handle),\n\
        );\n\
        executor.spawn_blocking(\"not-a-site\", || {});\n\
        executor.register_opt::<()>(\"typed\", tier, None::<()>);\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/tasks.rs", src).unwrap();
    assert_eq!(
        sites.len(),
        2,
        "None is excluded, Some counts, spawn_blocking is not a site: {sites:?}"
    );
    assert!(sites.iter().all(|s| s.kind == Kind::RegisterOpt));
    assert_eq!(sites[0].line, 7, "single-line Some");
    assert_eq!(sites[1].line, 8, "multiline Some");
}

/// RR1-09: result-bearing entry points are the same sites as `spawn` / `register`.
#[test]
fn spawn_result_and_register_result_are_sites() {
    let src = "\
        // detached: result-bearing task.\n\
        executor.spawn_result(\"duty_orchestrator\", ShutdownTier::Orchestrator, async move {});\n\
        executor.register_result(\"metrics_like\", ShutdownTier::Telemetry, handle);\n\
        executor.spawn_blocking(\"not-a-site\", || {});\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/run.rs", src).unwrap();
    assert_eq!(
        sites.len(),
        2,
        "spawn_result and register_result count; spawn_blocking does not: {sites:?}"
    );
    assert_eq!(sites[0].kind, Kind::Spawn);
    assert!(sites[0].detached, "preceding // detached: still classifies spawn_result");
    assert_eq!(sites[1].kind, Kind::Register);
    assert!(!sites[1].detached);
}

#[test]
fn cfg_test_mod_keeps_code_above_the_module_and_drops_the_module() {
    let src = "\
fn prod() {\n\
    #[cfg(test)]\n\
    async fn helper() {}\n\
    executor.spawn(\"liveness_loop\", ShutdownTier::Orchestrator, async move {});\n\
}\n\
#[cfg(test)]\n\
// gap\n\
#[allow(unsafe_code)]\n\
mod tests {\n\
    fn t() {\n\
        executor.spawn(\"hidden\", ShutdownTier::Background, async move {});\n\
    }\n\
}\n\
";
    let sites = find_production_sites("crates/rvc/src/liveness_loop.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].line, 4);
    assert!(sites[0].text.contains("liveness_loop"));
}

#[test]
fn shape_b_reads_the_census_loop_file_not_a_spawn_window() {
    let spawn_file = "\
        executor.spawn(\"monitoring_push\", ShutdownTier::Background, async move {});\n\
";
    // A same-file window that looks like shape B must not classify the spawn
    // when the census names a different loop file.
    let window_only = "\
        executor.spawn(\"monitoring_push\", ShutdownTier::Background, async move {});\n\
        let loop_span = tracing::info_span!(parent: None, \"monitoring_push\");\n\
        tick.follows_from(&loop_span);\n\
";
    let loop_file = "\
        let loop_span = tracing::info_span!(parent: None, \"monitoring_push\");\n\
        let tick = tracing::info_span!(parent: None, \"monitoring_push.tick\");\n\
        tick.follows_from(&loop_span);\n\
";
    let other_task = "\
        let loop_span = tracing::info_span!(parent: None, \"other\");\n\
        tick.follows_from(&loop_span);\n\
";
    let row = ShapeBRow {
        task: "monitoring_push".to_string(),
        spawn_path: "crates/rvc/src/bootstrap/tasks.rs".to_string(),
        spawn_item: "<module>".to_string(),
        loop_path: "crates/rvc/src/background_tasks/monitoring.rs".to_string(),
        loop_item: "start_monitoring_push".to_string(),
    };
    let site = find_production_sites(&row.spawn_path, spawn_file).unwrap().pop().unwrap();
    assert!(!site.detached);
    assert_eq!(
        classify(&site, std::slice::from_ref(&row), |_| {
            loop_file_has_shape_b(loop_file, "monitoring_push").unwrap()
        }),
        Class::ShapeB
    );
    assert_eq!(
        classify(&site, std::slice::from_ref(&row), |_| {
            loop_file_has_shape_b(other_task, "monitoring_push").unwrap()
        }),
        Class::ShapeBLoopMissing,
        "parent: None for a different task is not shape B"
    );
    let window_site = find_production_sites(&row.spawn_path, window_only).unwrap().pop().unwrap();
    assert_eq!(
        classify(&window_site, std::slice::from_ref(&row), |_| false),
        Class::ShapeBLoopMissing,
        "a same-file window is not enough when the census loop file does not carry the spans"
    );
    assert!(loop_file_has_shape_b(loop_file, "monitoring_push").unwrap());
    assert!(!loop_file_has_shape_b(other_task, "monitoring_push").unwrap());
}

#[test]
fn detached_comment_is_the_preceding_nonempty_line() {
    let src = "\
\n\
    // detached: metrics server; out of scope.\n\
    executor.spawn(\"metrics_server\", ShutdownTier::Telemetry, async move {});\n\
    executor.spawn(\"bare\", ShutdownTier::Background, async move {});\n\
";
    let sites = find_production_sites("crates/rvc/src/bootstrap/tasks.rs", src).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites[0].detached);
    assert!(!sites[1].detached);
    assert_eq!(classify(&sites[0], &[], |_| false), Class::Detached);
    assert_eq!(classify(&sites[1], &[], |_| false), Class::Unclassified);
}

#[test]
fn shape_b_spawn_must_not_carry_a_detached_comment() {
    let src = "\
    // detached: do not mark a shape-B spawn this way.\n\
    executor.spawn(\"liveness_loop\", ShutdownTier::Orchestrator, async move {});\n\
";
    let row = ShapeBRow {
        task: "liveness_loop".to_string(),
        spawn_path: "crates/rvc/src/liveness_loop.rs".to_string(),
        spawn_item: "<module>".to_string(),
        loop_path: "crates/rvc/src/liveness_loop.rs".to_string(),
        loop_item: "LivenessObservationLoop::run".to_string(),
    };
    let site = find_production_sites(&row.spawn_path, src).unwrap().pop().unwrap();
    assert!(site.detached);
    assert_eq!(classify(&site, &[row], |_| true), Class::ShapeBWithDetached);
}

#[test]
fn executor_keeps_a_spawn_after_a_raw_string_cfg_decoy() {
    let src = "\
fn item() {\n\
    let _ = r#\"\n\
#[cfg(test)]\n\
mod x\n\
\"#;\n\
    executor.spawn(\"kept\", tier, async {});\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains("kept"), "{sites:?}");
}

#[test]
fn executor_keeps_a_spawn_after_a_block_comment_cfg_decoy() {
    let src = "\
fn item() {\n\
    /*\n\
#[cfg(test)]\n\
mod x\n\
*/\n\
    executor.spawn(\"kept\", tier, async {});\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains("kept"), "{sites:?}");
}

#[test]
fn executor_accepts_r_hash_spawn_inside_a_macro() {
    let src = "macro_rules! m { () => { r#executor.r#spawn(\"t\", tier, async {}); }; }\n";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    let one = "macro_rules! m { () => { executor.r#spawn(\"t\", tier, async {}); }; }\n";
    let sites = find_production_sites("a.rs", one).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
}

#[test]
fn executor_rejects_production_code_after_the_test_module() {
    let src = "\
fn item() { executor.spawn(\"before\", tier, async {}); }\n\
#[cfg(test)]\n\
mod tests {}\n\
fn after() { executor.spawn(\"after\", tier, async {}); }\n\
";
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
    let semi = "fn item() { executor.spawn(\"before\", tier, async {}); }\n#[cfg(test)] mod tests;\nfn after() { executor.spawn(\"after\", tier, async {}); }\n";
    let err = find_production_sites("a.rs", semi).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn executor_rejects_a_production_multibyte_char_literal() {
    let src = "fn item() {\n    let _ = '€';\n    executor.spawn(\"t\", tier, async {});\n}\n";
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("lexer mask disagreed"), "{err}");
}

#[test]
fn executor_keeps_a_multibyte_char_literal_inside_the_test_module() {
    let src = "\
fn item() { executor.spawn(\"kept\", tier, async {}); }\n\
#[cfg(test)]\n\
mod tests {\n\
    fn t() { let _ = '€'; }\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains("kept"), "{sites:?}");
}

#[test]
fn executor_keeps_a_spawn_inside_a_non_test_cfg_module() {
    let unix = "\
fn item() { executor.spawn(\"outer\", tier, async {}); }\n\
#[cfg(unix)]\n\
mod p {\n\
    pub fn g() { executor.spawn(\"inner\", tier, async {}); }\n\
}\n\
";
    let sites = find_production_sites("a.rs", unix).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
    let not_test = "\
fn item() { executor.spawn(\"outer\", tier, async {}); }\n\
#[cfg(not(test))]\n\
mod p {\n\
    pub fn g() { executor.spawn(\"inner\", tier, async {}); }\n\
}\n\
";
    let sites = find_production_sites("a.rs", not_test).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
}

#[test]
fn executor_counts_a_receiver_whose_name_ends_in_executor() {
    let src = "\
fn item() {\n\
    task_executor.spawn(\"task\", tier, async {});\n\
    self.bg_executor.register(\"reg\", tier, handle);\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::Spawn);
    assert_eq!(sites[1].kind, Kind::Register);
}

#[test]
fn executor_rejects_a_nested_call_after_the_test_module() {
    let src = "\
fn f() {\n\
    executor.spawn(\"a\", tier, async move {\n\
        #[cfg(test)] mod t {}\n\
        executor.spawn(\"b\", tier, async {});\n\
    });\n\
}\n\
";
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn executor_counts_a_spawn_nested_in_register_opt_none() {
    let src = "\
fn item() {\n\
    executor.r#register_opt::<()>(\"n\", { executor.spawn(\"inner\", tier, async {}); tier }, None);\n\
}\n\
";
    let (toks, cut) = executor_lex(src).unwrap();
    assert!(cut.is_none());
    let calls = executor_calls(src, &toks).unwrap();
    let sites: Vec<_> = calls.iter().filter(|hit| hit.is_site).collect();
    assert_eq!(sites.len(), 1, "{calls:?}");
    // `enclosing_item` refuses a raw ident, so the anchor errors instead of
    // guessing an item or returning a successful list that dropped the spawn.
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("raw identifier"), "{err}");
}

#[test]
fn executor_counts_register_opt_past_a_comparison_in_an_earlier_arg() {
    let src = "\
fn item() {\n\
    executor.register_opt(\"t\", None.unwrap_or(if 0 < 1 { tier } else { tier }), Some(h));\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::RegisterOpt);
}

#[test]
fn executor_counts_register_opt_when_none_is_not_the_whole_last_arg() {
    let src = "\
fn item() {\n\
    executor.register_opt(\"t\", tier, None.or(Some(h)));\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::RegisterOpt);
}

#[test]
fn executor_does_not_nest_angles_when_splitting_arguments() {
    let src = "fn item() { executor.register_opt(\"t\", tier, None::<A, B>); }\n";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::RegisterOpt);
}

#[test]
fn executor_counts_a_grouped_last_argument() {
    let src = "\
fn item() {\n\
    executor.register_opt(\"t\", None, { Some(h) });\n\
    executor.register_opt(\"t\", None, (Some(h)),);\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites.iter().all(|s| s.kind == Kind::RegisterOpt), "{sites:?}");
}

#[test]
fn executor_counts_none_turbofish_when_the_closer_is_outside_the_argument() {
    let src = "\
fn item() {\n\
    executor.register_opt(\"t\", tier, None::<JoinHandle<[u8; (0 < 1) as usize]>>.or(Some(h)));\n\
    fn ret() -> u8 { 0 }\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::RegisterOpt);
}

#[test]
fn executor_counts_none_turbofish_closed_by_an_arrow() {
    let src = "fn item() { executor.register_opt(\"t\", tier, None::<fn() -> u8>); }\n";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(sites[0].kind, Kind::RegisterOpt);
}

#[test]
fn executor_keeps_a_spawn_after_an_unclosed_turbofish_in_an_argument() {
    let src = "\
fn f() {\n\
    executor.spawn(\"outer\", tier, async { stringify!(executor.register_opt::<); });\n\
    executor.spawn(\"real\", tier, async {});\n\
    let _ = Some(()) > (None);\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 2, "{sites:?}");
    assert!(sites.iter().any(|s| s.text.contains("\"real\"")), "{sites:?}");
}

#[test]
fn executor_rejects_a_post_module_spawn_past_an_unclosed_turbofish() {
    let src = "\
fn f() {\n\
    executor.spawn(\"outer\", tier, async { stringify!(executor.register_opt::<); });\n\
    #[cfg(test)]\n\
    mod t {}\n\
    executor.spawn(\"real\", tier, async {});\n\
    let _ = Some(()) > (None);\n\
}\n\
";
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn executor_keeps_a_none_turbofish_that_contains_a_nested_comma() {
    let src = "\
fn item() {\n\
    executor.register_opt(\"t\", tier, None::<u8>.or(Some(h)));\n\
    executor.register_opt(\"t\", tier, None::<JoinHandle<(u8, u8)>>);\n\
    executor.register_opt(\"t\", tier, None::<[A, B]>);\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains(".or("), "{sites:?}");
}

#[test]
fn executor_rejects_a_call_that_starts_on_the_module_end_byte() {
    let src = "fn f() {\n    #[cfg(test)] mod t {}executor.spawn(\"after\", tier, async {});\n}\n";
    let err = find_production_sites("a.rs", src).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn executor_keeps_a_call_inside_the_test_module_when_the_tail_has_none() {
    let src = "\
fn item() { executor.spawn(\"before\", tier, async {}); }\n\
#[cfg(test)]\n\
mod tests {\n\
    fn t() { executor.spawn(\"inside\", tier, async {}); }\n\
}\n\
fn after() {}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains("before"), "{sites:?}");
}

#[test]
fn shape_b_requires_follows_from() {
    let src = "let loop_span = tracing::info_span!(parent: None, \"monitoring_push\");\n";
    assert!(!loop_file_has_shape_b(src, "monitoring_push").unwrap());
}

#[test]
fn executor_requires_a_dot_before_the_method() {
    let src = "\
fn item() {\n\
    executor.spawn(\"kept\", tier, async {});\n\
    executor x spawn(\"no-dot\", tier, async {});\n\
}\n\
";
    let sites = find_production_sites("a.rs", src).unwrap();
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(sites[0].text.contains("kept"), "{sites:?}");
}

#[test]
fn executor_reads_non_ascii_and_quoted_tracked_paths() {
    let cafe = "crates/rvc/src/café.rs";
    let messy = "crates/rvc/src/q\"b\\c\td.rs";
    let body = "fn h() { executor.spawn(\"t\", tier, async {}); }\n";
    let root = init_bn_repo(&[(cafe, body), (messy, body)]);
    let files = tracked_rs_files(&root).unwrap();
    assert!(files.iter().any(|path| path.contains("café")), "{files:?}");
    assert!(
        files.iter().any(|path| path.contains('"') && path.contains('\\') && path.contains('\t')),
        "{files:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn executor_names_a_non_utf8_tracked_path() {
    use std::os::unix::ffi::OsStringExt;
    let root = init_bn_repo(&[]);
    let mut name = b"bad".to_vec();
    name.push(0xff);
    name.extend(b".rs");
    let path = root.join("crates/rvc/src").join(std::ffi::OsString::from_vec(name));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "fn h() { executor.spawn(\"t\", tier, async {}); }\n").unwrap();
    let out = Command::new("git").args(["add", "-A"]).current_dir(&root).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let err = tracked_rs_files(&root).unwrap_err();
    assert!(err.contains("non-utf8") && err.contains("executor") && err.contains("bad"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn executor_names_an_unreadable_tracked_file() {
    let rel = "crates/rvc/src/gone.rs";
    let root = init_bn_repo(&[(rel, "fn h() { executor.spawn(\"t\", tier, async {}); }\n")]);
    std::fs::remove_file(root.join(rel)).unwrap();
    let err = load_executor(&root).unwrap_err();
    assert!(err.contains(rel), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// Census line pins (first table, shape-B loop lines, liveness prose)
// ---------------------------------------------------------------------------

fn section_body(census: &str, heading_contains: &str) -> String {
    let mut collecting = false;
    let mut found = false;
    let mut out = String::new();
    for line in census.lines() {
        if line.starts_with("## ") {
            if collecting {
                break;
            }
            if line.contains(heading_contains) {
                collecting = true;
                found = true;
            }
            continue;
        }
        if collecting {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(found, "census section containing {heading_contains:?} not found");
    out
}

fn markdown_table(section: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for line in section.lines() {
        if !line.starts_with('|') || line.contains("---") {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_string())
            .collect();
        if cells.iter().any(|c| c == "File" || c == "Task") || cells.iter().all(|c| c.is_empty()) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

/// A census path is repo-relative. Empty, absolute, `.`, and `..` fail before `join`.
fn repo_rel(cell: &str) -> Result<(), String> {
    if cell.is_empty()
        || Path::new(cell).is_absolute()
        || cell.split(['/', '\\']).any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(format!("census path is not repo-relative: {cell}"));
    }
    Ok(())
}

fn read_repo_file(root: &Path, rel: &str) -> Result<String, String> {
    repo_rel(rel)?;
    std::fs::read_to_string(root.join(rel)).map_err(|err| format!("row {rel}: {err}"))
}

fn line_cell(cell: &str) -> bool {
    if is_line_number(cell) {
        return true;
    }
    match cell.rsplit_once(':') {
        Some((_, tail)) => is_line_number(tail),
        None => false,
    }
}

fn cites_line(text: &str) -> bool {
    text.split(':').skip(1).any(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

/// Data rows of one markdown table. The header is skipped. A short row, an
/// empty cell, or a line pin is an error, not a skipped row.
fn census_rows(section: &str, columns: usize) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    let mut header = false;
    for line in section.lines() {
        if !line.starts_with('|') || line.contains("---") {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().trim_matches('`').to_string())
            .collect();
        if !header {
            header = true;
            if cells.iter().any(|cell| cell == "Line") {
                return Err(format!("census table still has a Line column: {line}"));
            }
            continue;
        }
        if cells.len() != columns || cells.iter().any(|cell| cell.is_empty()) {
            return Err(format!("unrecognised census row: {line}"));
        }
        if cells.iter().any(|cell| line_cell(cell)) {
            return Err(format!("census row uses a line pin: {line}"));
        }
        rows.push(cells);
    }
    if !header {
        return Err("census table missing".to_string());
    }
    Ok(rows)
}

fn attr_on_fn(src: &str, toks: &[(usize, usize, TokenKind)], mut i: usize) -> bool {
    loop {
        let n = next_solid(toks, i);
        if !matches!(toks.get(n).map(|tok| tok.2), Some(TokenKind::Pound)) {
            i = n;
            break;
        }
        let bracket = next_solid(toks, n + 1);
        if !matches!(toks.get(bracket).map(|tok| tok.2), Some(TokenKind::OpenBracket)) {
            return false;
        }
        let Some(after) =
            skip_until(toks, bracket, TokenKind::OpenBracket, TokenKind::CloseBracket)
        else {
            return false;
        };
        i = after;
    }
    if word_is(src, toks, i, "pub") {
        let next = next_solid(toks, i + 1);
        if matches!(toks.get(next).map(|tok| tok.2), Some(TokenKind::OpenParen)) {
            let Some(after) = skip_until(toks, next, TokenKind::OpenParen, TokenKind::CloseParen)
            else {
                return false;
            };
            i = next_solid(toks, after);
        } else {
            i = next;
        }
    }
    if word_is(src, toks, i, "async")
        || word_is(src, toks, i, "unsafe")
        || word_is(src, toks, i, "const")
    {
        i = next_solid(toks, i + 1);
    }
    word_is(src, toks, i, "fn")
}

struct CfgAttr {
    at: usize,
    column0: bool,
    is_mod: bool,
    on_fn: bool,
}

/// First bare `#[cfg(test)]` on a function, a later one that is not, and a
/// column-0 `#[cfg(test)]` followed by `mod`, with the one production spawn
/// between the first attribute and that module attribute.
fn liveness_shape(src: &str) -> Result<(), String> {
    let (toks, cut) = executor_lex(src)?;
    let prefix = cut.unwrap_or(src.len());
    let starts = line_starts(src);
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if let Some(after) = cfg_test_attr_end(src, &toks, i) {
            let column0 = starts.binary_search(&toks[i].0).is_ok();
            let is_mod = mod_after(src, &toks, after).is_some();
            let on_fn = !is_mod && attr_on_fn(src, &toks, after);
            attrs.push(CfgAttr { at: toks[i].0, column0, is_mod, on_fn });
            i = after;
            continue;
        }
        i += 1;
    }
    let Some(first) = attrs.first() else {
        return Err("no bare #[cfg(test)]".to_string());
    };
    if first.column0 || first.is_mod || !first.on_fn {
        return Err(
            "first bare #[cfg(test)] is not an indented attribute on a function".to_string()
        );
    }
    let Some(mod_at) = attrs.iter().find(|attr| attr.column0 && attr.is_mod).map(|attr| attr.at)
    else {
        return Err("no column-0 #[cfg(test)] followed by mod".to_string());
    };
    if !attrs.iter().any(|attr| {
        attr.at > first.at && attr.at < mod_at && !attr.column0 && !attr.is_mod && !attr.on_fn
    }) {
        return Err("no later bare #[cfg(test)] off a function before the module".to_string());
    }
    let hits: Vec<_> = executor_calls(src, &toks)?
        .into_iter()
        .filter(|hit| hit.is_site && hit.at < prefix)
        .collect();
    if hits.len() != 1 {
        return Err(format!("liveness production site count is {}", hits.len()));
    }
    if !(first.at < hits[0].at && hits[0].at < mod_at) {
        return Err(
            "production spawn is not between the first bare attribute and the module attribute"
                .to_string(),
        );
    }
    Ok(())
}

fn push_unique(
    keys: &mut Vec<(String, String, String, String)>,
    key: (String, String, String, String),
) -> Result<(), String> {
    if keys.iter().any(|have| have == &key) {
        return Err(format!("duplicate anchor {key:?}"));
    }
    keys.push(key);
    Ok(())
}

fn census_anchors_match(census: &str, root: &Path) -> Result<(), String> {
    if census.contains("| Line |") {
        return Err("census still has a Line column".to_string());
    }
    if !census.contains(&format!("## Production sites ({PIN})")) {
        return Err(format!("production-sites heading must name the pin {PIN}"));
    }
    let (sites, _) = scan_workspace(root)?;
    let rows = parse_shape_b(census)?;
    if rows.len() != SHAPE_B_PIN {
        return Err(format!("shape-B table has {} rows, pin is {SHAPE_B_PIN}", rows.len()));
    }
    let mut scanned = Vec::new();
    for site in &sites {
        push_unique(
            &mut scanned,
            (
                site.path.clone(),
                site.item.clone(),
                site.task.clone(),
                site.kind.as_str().to_string(),
            ),
        )?;
    }
    let mut table = Vec::new();
    let mut buckets = Vec::new();
    for cells in census_rows(&section_body(census, "Production sites"), 6)? {
        repo_rel(&cells[0])?;
        let call = cells[3].as_str();
        if call != "spawn" && call != "register" {
            return Err(format!("unrecognised production call `{call}`"));
        }
        let bucket = cells[4].as_str();
        if bucket != "detached" && bucket != "B" {
            return Err(format!("unrecognised bucket `{bucket}`"));
        }
        let key = (cells[0].clone(), cells[1].clone(), cells[2].clone(), cells[3].clone());
        push_unique(&mut table, key)?;
        buckets.push(bucket.to_string());
    }
    let mut left = scanned.clone();
    let mut right = table.clone();
    left.sort();
    right.sort();
    if left != right {
        return Err(format!("production anchors differ\nscanned: {left:?}\ntable: {right:?}"));
    }
    for site in &sites {
        let shape_b = rows.iter().any(|row| {
            row.spawn_path == site.path && row.spawn_item == site.item && row.task == site.task
        });
        let expect = match (site.detached, shape_b) {
            (true, false) => "detached",
            (false, true) => "B",
            (true, true) => {
                return Err(format!(
                    "{} {} `{}` is shape B and also detached",
                    site.path, site.item, site.task
                ));
            }
            (false, false) => {
                return Err(format!(
                    "{} {} `{}` is not detached and has no shape-B row",
                    site.path, site.item, site.task
                ));
            }
        };
        let found = table.iter().zip(&buckets).find(|(key, _)| {
            key.0 == site.path
                && key.1 == site.item
                && key.2 == site.task
                && key.3 == site.kind.as_str()
        });
        match found {
            Some((_, bucket)) if bucket == expect => {}
            Some((_, bucket)) => {
                return Err(format!(
                    "{} {} `{}` bucket is `{bucket}`, classification is `{expect}`",
                    site.path, site.item, site.task
                ));
            }
            None => return Err(format!("missing bucket for {} {}", site.path, site.task)),
        }
    }
    for row in &rows {
        let src = read_repo_file(root, &row.loop_path)?;
        let item = loop_item(&row.loop_path, &src, &row.task)?;
        if item != row.loop_item {
            return Err(format!(
                "row {}: loop item is `{item}`, census says `{}`",
                row.loop_path, row.loop_item
            ));
        }
    }
    let mut not_scanned = Vec::new();
    for (rel, src) in load_executor(root)? {
        for site in not_site_anchors(&rel, &src)? {
            push_unique(
                &mut not_scanned,
                (site.path, site.item, site.task, "register_opt".to_string()),
            )?;
        }
    }
    let mut not_table = Vec::new();
    for cells in census_rows(&section_body(census, "Not sites"), 4)? {
        repo_rel(&cells[0])?;
        if cells[3] != "register_opt" {
            return Err(format!("not-site call must be register_opt: {}", cells.join(" | ")));
        }
        push_unique(
            &mut not_table,
            (cells[0].clone(), cells[1].clone(), cells[2].clone(), cells[3].clone()),
        )?;
    }
    not_scanned.sort();
    not_table.sort();
    if not_scanned != not_table {
        return Err(format!(
            "not-site anchors differ\nscanned: {not_scanned:?}\ntable: {not_table:?}"
        ));
    }
    let live_path = "crates/rvc/src/liveness_loop.rs";
    let live = read_repo_file(root, live_path)?;
    liveness_shape(&live).map_err(|err| format!("row {live_path}: {err}"))?;
    let prose = section_body(census, "liveness_loop.rs");
    if cites_line(&prose) {
        return Err("liveness prose still cites a line number".to_string());
    }
    let bn = load_bn(root)?;
    bn_section_matches(census, &bn)?;
    Ok(())
}

fn anchor_keys(
    files: &[(String, String)],
) -> Result<Vec<(String, String, String, String)>, String> {
    let mut keys = Vec::new();
    for site in collect_anchored_sites(files)? {
        push_unique(&mut keys, (site.path, site.item, site.task, site.kind.as_str().to_string()))?;
    }
    for (path, src) in files {
        for site in not_site_anchors(path, src)? {
            push_unique(&mut keys, (site.path, site.item, site.task, "register_opt".to_string()))?;
        }
    }
    keys.sort();
    Ok(keys)
}

#[test]
fn census_anchors_match_sources() {
    let root = workspace_root();
    let census = std::fs::read_to_string(root.join(CENSUS))
        .unwrap_or_else(|err| panic!("row {CENSUS}: {err}"));
    census_anchors_match(&census, &root).unwrap_or_else(|err| panic!("{err}"));
}

#[test]
fn census_anchor_survives_a_blank_line_insert() {
    let root = workspace_root();
    let files = load_executor(&root).unwrap_or_else(|err| panic!("{err}"));
    let before = anchor_keys(&files).unwrap_or_else(|err| panic!("{err}"));
    let mut shifted = files.clone();
    for (path, src) in &mut shifted {
        if path.ends_with("bootstrap/tasks.rs") || path.ends_with("liveness_loop.rs") {
            src.insert(0, '\n');
        }
    }
    let after = anchor_keys(&shifted).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(before, after, "a leading blank line changed an anchor");
    let live = shifted.iter().find(|(path, _)| path.ends_with("liveness_loop.rs")).unwrap();
    liveness_shape(&live.1).unwrap();
}

#[test]
fn liveness_content_shape_fails_closed() {
    let ok = "fn prod() {\n    #[cfg(test)]\n    async fn helper() {}\n    #[cfg(test)]\n    let _x = 1;\n    executor.spawn(\"liveness_loop\", tier, async {});\n}\n#[cfg(test)]\nmod tests {}\n";
    liveness_shape(ok).unwrap();
    let no_inner = "fn prod() {\n    #[cfg(test)]\n    async fn helper() {}\n    executor.spawn(\"liveness_loop\", tier, async {});\n}\n#[cfg(test)]\nmod tests {}\n";
    let err = liveness_shape(no_inner).unwrap_err();
    assert!(err.contains("off a function"), "{err}");
    let indented_mod = "fn prod() {\n    #[cfg(test)]\n    async fn helper() {}\n    #[cfg(test)]\n    let _x = 1;\n    executor.spawn(\"liveness_loop\", tier, async {});\n    #[cfg(test)]\n    mod tests {}\n}\n";
    let err = liveness_shape(indented_mod).unwrap_err();
    assert!(err.contains("column-0"), "{err}");
    let first_not_fn = "fn prod() {\n    #[cfg(test)]\n    let _x = 1;\n    #[cfg(test)]\n    async fn helper() {}\n    executor.spawn(\"liveness_loop\", tier, async {});\n}\n#[cfg(test)]\nmod tests {}\n";
    let err = liveness_shape(first_not_fn).unwrap_err();
    assert!(err.contains("not an indented attribute on a function"), "{err}");
    let column0 = "fn prod() {\n#[cfg(test)]\nasync fn helper() {}\n    #[cfg(test)]\n    let _x = 1;\n    executor.spawn(\"liveness_loop\", tier, async {});\n}\n#[cfg(test)]\nmod tests {}\n";
    let err = liveness_shape(column0).unwrap_err();
    assert!(err.contains("not an indented attribute on a function"), "{err}");
    let early = "fn prod() {\n    executor.spawn(\"liveness_loop\", tier, async {});\n    #[cfg(test)]\n    async fn helper() {}\n    #[cfg(test)]\n    let _x = 1;\n}\n#[cfg(test)]\nmod tests {}\n";
    let err = liveness_shape(early).unwrap_err();
    assert!(err.contains("not between"), "{err}");
    let two = "fn prod() {\n    #[cfg(test)]\n    async fn helper() {}\n    #[cfg(test)]\n    let _x = 1;\n    executor.spawn(\"liveness_loop\", tier, async {});\n    executor.spawn(\"other\", tier, async {});\n}\n#[cfg(test)]\nmod tests {}\n";
    let err = liveness_shape(two).unwrap_err();
    assert!(err.contains("site count"), "{err}");
}

#[test]
fn task_argument_fails_closed() {
    let resolved = "\
const NAME: &str = \"bn.sse\";\n\
fn f() { executor.spawn(NAME, tier, async {}); }\n\
";
    let sites = find_production_sites("a.rs", resolved).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].item, "f");
    assert_eq!(sites[0].task, "bn.sse");
    let missing = "fn f() { executor.spawn(MISSING, tier, async {}); }\n";
    let err = find_production_sites("a.rs", missing).unwrap_err();
    assert!(
        err.contains("unresolved task const") && err.contains("MISSING") && err.contains("a.rs"),
        "{err}"
    );
    let path = "fn f() { executor.spawn(crate::NAME, tier, async {}); }\n";
    let err = find_production_sites("a.rs", path).unwrap_err();
    assert!(err.contains("task path") && err.contains("crate"), "{err}");
    let raw = "fn f() { executor.spawn(r#\"bn.sse\"#, tier, async {}); }\n";
    let err = find_production_sites("a.rs", raw).unwrap_err();
    assert!(err.contains("not a plain literal"), "{err}");
    let mac = "fn f() { executor.spawn(name!(), tier, async {}); }\n";
    let err = find_production_sites("a.rs", mac).unwrap_err();
    assert!(err.contains("task macro"), "{err}");
    let trimmed =
        "const NAME: &str = \"bn.sse\".trim();\nfn f() { executor.spawn(NAME, tier, async {}); }\n";
    let err = find_production_sites("a.rs", trimmed).unwrap_err();
    assert!(err.contains("not a plain string") && err.contains("NAME"), "{err}");
    let expr = "fn f() { executor.spawn(\"bn.sse\".trim(), tier, async {}); }\n";
    let err = find_production_sites("a.rs", expr).unwrap_err();
    assert!(err.contains("not a bare string or ident"), "{err}");
    let method =
        "const NAME: &str = \"bn.sse\";\nfn f() { executor.spawn(NAME.trim(), tier, async {}); }\n";
    let err = find_production_sites("a.rs", method).unwrap_err();
    assert!(err.contains("not a bare string or ident"), "{err}");
    let escaped = "fn f() { executor.spawn(\"a\\nb\", tier, async {}); }\n";
    let err = find_production_sites("a.rs", escaped).unwrap_err();
    assert!(err.contains("escaped task string"), "{err}");
    let dup = "const NAME: &str = \"a\";\nconst NAME: &str = \"b\";\nfn f() { executor.spawn(NAME, tier, async {}); }\n";
    let err = find_production_sites("a.rs", dup).unwrap_err();
    assert!(err.contains("ambiguous task const") && err.contains("NAME"), "{err}");
}

#[test]
fn loop_item_surfaces_a_resolve_error() {
    let src = "fn parent_ok() {\n    let loop_span = tracing::info_span!(parent: None, \"t\");\n    follows_from();\n}\nfn f() { loop {} }\nfn f() { let _ = 1; }\n";
    let err = loop_item("a.rs", src, "t").unwrap_err();
    assert!(err.contains("ambiguous") && !err.contains("has no `loop`"), "{err}");
}

#[test]
fn shape_b_path_stays_inside_the_repo() {
    let header = "## Shape B loop sites\n\n| Task | Spawn file | Spawn item | Loop file | Loop item |\n|---|---|---|---|---|\n";
    let err = parse_shape_b(&format!("{header}| `t` | `../outside.rs` | `f` | `a.rs` | `g` |\n"))
        .unwrap_err();
    assert!(err.contains("not repo-relative") && err.contains(".."), "{err}");
    let err = parse_shape_b(&format!("{header}| `t` | `/etc/passwd` | `f` | `a.rs` | `g` |\n"))
        .unwrap_err();
    assert!(err.contains("not repo-relative") && err.contains("/etc/passwd"), "{err}");
}

#[test]
fn census_bucket_follows_the_shape_b_row() {
    let root = workspace_root();
    let census = std::fs::read_to_string(root.join(CENSUS)).unwrap();
    let line = "| `index.resolve` | `crates/rvc/src/index_resolver.rs` | `spawn_index_resolver` | `crates/rvc/src/index_resolver.rs` | `IndexResolver::run` |";
    let missing = census.replace(
        line,
        "| `index.resolve` | `crates/rvc/src/index_resolver.rs` | `other_item` | `crates/rvc/src/index_resolver.rs` | `IndexResolver::run` |",
    );
    let err = census_anchors_match(&missing, &root).unwrap_err();
    assert!(err.contains("no shape-B row") && err.contains("index.resolve"), "{err}");
    let both = census.replace(
        line,
        "| `metrics_server` | `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `crates/rvc/src/index_resolver.rs` | `IndexResolver::run` |",
    );
    let err = census_anchors_match(&both, &root).unwrap_err();
    assert!(err.contains("shape B and also detached") && err.contains("metrics_server"), "{err}");
}

#[test]
fn push_unique_rejects_a_duplicate_anchor() {
    let mut keys = Vec::new();
    let key = ("a".into(), "b".into(), "c".into(), "spawn".into());
    push_unique(&mut keys, key.clone()).unwrap();
    let err = push_unique(&mut keys, key).unwrap_err();
    assert!(err.contains("duplicate anchor"), "{err}");
}

#[test]
fn executor_anchor_rejects_an_ambiguous_item_and_module_level() {
    let ambiguous = "\
fn f() { executor.spawn(\"t\", tier, async {}); }\n\
fn f() { let _ = 1; }\n\
";
    let err = find_production_sites("a.rs", ambiguous).unwrap_err();
    assert!(err.contains("ambiguous") && err.contains("a.rs"), "{err}");
    let module = "executor.spawn(\"t\", tier, async {});\n";
    let sites = find_production_sites("a.rs", module).unwrap();
    assert_eq!(sites[0].item, "<module>");
    let err = collect_anchored_sites(&[("a.rs".to_string(), module.to_string())]).unwrap_err();
    assert!(err.contains("refusing <module>") && err.contains("a.rs"), "{err}");
    let good = "fn f() { executor.spawn(\"kept\", tier, async {}); }\n";
    let bad = "fn g() { executor.spawn(\"u\", tier, async {}); let _ = \"open; }\n";
    let err = collect_anchored_sites(&[
        ("good.rs".to_string(), good.to_string()),
        ("bad.rs".to_string(), bad.to_string()),
    ])
    .unwrap_err();
    assert!(err.contains("bad.rs"), "{err}");
    let none = "executor.register_opt::<()>(\"t\", tier, None);\n";
    let err = not_site_anchors("a.rs", none).unwrap_err();
    assert!(err.contains("refusing <module>"), "{err}");
    let unterminated = "fn f() { executor.spawn(\"t\", tier, async {}); let _ = \"open; }\n";
    let err = not_site_anchors("bad.rs", unterminated).unwrap_err();
    assert!(err.contains("bad.rs"), "{err}");
}

// ---------------------------------------------------------------------------
// bn-manager census: (file, enclosing item), lexer tokens only
// ---------------------------------------------------------------------------

fn tracked_nul(root: &Path, label: &str, specs: &[&str]) -> Result<Vec<String>, String> {
    let mut args = vec!["-c", "core.quotePath=false", "ls-files", "-z", "--"];
    args.extend(specs.iter().copied());
    let output = Command::new("git")
        .args(&args)
        .current_dir(root)
        .output()
        .map_err(|err| format!("git ls-files: {err}"))?;
    if !output.status.success() {
        return Err(format!("git ls-files failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8(raw.to_vec())
            .map_err(|_| format!("non-utf8 {label} path: {}", String::from_utf8_lossy(raw)))?;
        if path.ends_with(".rs") && !path.contains("/tests/") {
            files.push(path);
        }
    }
    Ok(files)
}

fn tracked_bn_files(root: &Path) -> Result<Vec<String>, String> {
    tracked_nul(root, "bn-manager", &["crates/bn-manager/**/*.rs"])
}

fn lit_unterminated(kind: LiteralKind) -> Option<bool> {
    match kind {
        LiteralKind::Char { terminated }
        | LiteralKind::Byte { terminated }
        | LiteralKind::Str { terminated }
        | LiteralKind::ByteStr { terminated }
        | LiteralKind::CStr { terminated } => Some(!terminated),
        LiteralKind::RawStr { n_hashes }
        | LiteralKind::RawByteStr { n_hashes }
        | LiteralKind::RawCStr { n_hashes } => Some(n_hashes.is_none()),
        LiteralKind::Int { .. } | LiteralKind::Float { .. } => None,
    }
}

/// Lexer tokens, or why the file cannot be trusted.
///
/// Spans come from the lexer. A length that is not a char boundary is an
/// error, not a slice. Comment and string tokens are masked; a disagreement
/// with [`non_code_spans`] fails the file.
fn lex_file(src: &str, check_mask: bool) -> Result<Vec<(usize, usize, TokenKind)>, String> {
    let first = src.lines().next().unwrap_or("");
    if first.starts_with("#!") && !first.starts_with("#![") {
        return Err("shebang".to_string());
    }
    let mut pos = 0usize;
    let mut toks = Vec::new();
    let mut masked = Vec::new();
    for tok in tokenize(src, FrontmatterAllowed::No) {
        let len = tok.len as usize;
        let end = pos.saturating_add(len);
        if len == 0 || end > src.len() || !src.is_char_boundary(end) {
            return Err("token stream broke".to_string());
        }
        let (mask, bad) = match tok.kind {
            TokenKind::LineComment { .. } => (true, false),
            TokenKind::BlockComment { terminated, .. } => (true, !terminated),
            TokenKind::Unknown
            | TokenKind::InvalidIdent
            | TokenKind::GuardedStrPrefix
            | TokenKind::UnknownPrefix
            | TokenKind::UnknownPrefixLifetime => (false, true),
            TokenKind::Literal { kind, .. } => match lit_unterminated(kind) {
                Some(bad) => (true, bad),
                None => (false, false),
            },
            _ => (false, false),
        };
        if bad {
            return Err("unterminated or unknown token".to_string());
        }
        if mask {
            masked.push((pos, end));
        }
        toks.push((pos, end, tok.kind));
        pos = end;
    }
    if pos != src.len() {
        return Err("token stream did not cover the file".to_string());
    }
    if check_mask && masked != non_code_spans(src) {
        return Err("lexer mask disagreed".to_string());
    }
    Ok(toks)
}

fn is_gap(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Whitespace | TokenKind::LineComment { .. } | TokenKind::BlockComment { .. }
    )
}

fn next_solid(toks: &[(usize, usize, TokenKind)], mut i: usize) -> usize {
    while i < toks.len() && is_gap(toks[i].2) {
        i += 1;
    }
    i
}

fn word_is(src: &str, toks: &[(usize, usize, TokenKind)], i: usize, want: &str) -> bool {
    toks.get(i)
        .is_some_and(|tok| matches!(tok.2, TokenKind::Ident) && src.get(tok.0..tok.1) == Some(want))
}

/// `Ident` or `RawIdent` with the `r#` prefix removed. Keywords stay `Ident` only.
fn call_word<'a>(src: &'a str, tok: &(usize, usize, TokenKind)) -> Option<&'a str> {
    let text = src.get(tok.0..tok.1)?;
    match tok.2 {
        TokenKind::Ident => Some(text),
        TokenKind::RawIdent => text.strip_prefix("r#").filter(|rest| !rest.is_empty()),
        _ => None,
    }
}

/// Byte offset of each `tokio::spawn(` call. Comments and strings are not idents.
fn tokio_spawn_calls(src: &str, toks: &[(usize, usize, TokenKind)]) -> Vec<usize> {
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if call_word(src, &toks[i]) != Some("tokio") {
            continue;
        }
        let colon = next_solid(toks, i + 1);
        let colon2 = next_solid(toks, colon + 1);
        let name = next_solid(toks, colon2 + 1);
        let open = next_solid(toks, name + 1);
        if open < toks.len()
            && matches!(toks[colon].2, TokenKind::Colon)
            && matches!(toks[colon2].2, TokenKind::Colon)
            && toks.get(name).is_some_and(|tok| call_word(src, tok) == Some("spawn"))
            && matches!(toks[open].2, TokenKind::OpenParen)
        {
            out.push(toks[i].0);
        }
    }
    out
}

fn line_starts(src: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    starts.push(0);
    for (i, b) in src.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn line_text_at(src: &str, starts: &[usize], at: usize) -> String {
    let line = starts.partition_point(|start| *start <= at);
    let from = starts[line - 1];
    let to = starts.get(line).copied().unwrap_or(src.len());
    src[from..to].trim().to_string()
}

fn cfg_test_attr_end(src: &str, toks: &[(usize, usize, TokenKind)], i: usize) -> Option<usize> {
    if !matches!(toks.get(i)?.2, TokenKind::Pound) {
        return None;
    }
    let bracket = next_solid(toks, i + 1);
    if !matches!(toks.get(bracket)?.2, TokenKind::OpenBracket) {
        return None;
    }
    let cfg = next_solid(toks, bracket + 1);
    if !word_is(src, toks, cfg, "cfg") {
        return None;
    }
    let open = next_solid(toks, cfg + 1);
    if !matches!(toks.get(open)?.2, TokenKind::OpenParen) {
        return None;
    }
    let test = next_solid(toks, open + 1);
    if !word_is(src, toks, test, "test") {
        return None;
    }
    let close = next_solid(toks, test + 1);
    if !matches!(toks.get(close)?.2, TokenKind::CloseParen) {
        return None;
    }
    let end = next_solid(toks, close + 1);
    if !matches!(toks.get(end)?.2, TokenKind::CloseBracket) {
        return None;
    }
    Some(end + 1)
}

fn skip_until(
    toks: &[(usize, usize, TokenKind)],
    from: usize,
    open: TokenKind,
    close: TokenKind,
) -> Option<usize> {
    skip_until_before(toks, from, toks.len(), open, close)
}

/// Like [`skip_until`], but a closer at index `end` or later does not count.
fn skip_until_before(
    toks: &[(usize, usize, TokenKind)],
    from: usize,
    end: usize,
    open: TokenKind,
    close: TokenKind,
) -> Option<usize> {
    if end <= from {
        return None;
    }
    let mut depth = 0usize;
    for (n, tok) in toks.iter().enumerate().take(end).skip(from) {
        if tok.2 == open {
            depth += 1;
        } else if tok.2 == close {
            depth -= 1;
            if depth == 0 {
                return Some(n + 1);
            }
        }
    }
    None
}

fn mod_after(src: &str, toks: &[(usize, usize, TokenKind)], mut i: usize) -> Option<usize> {
    loop {
        i = next_solid(toks, i);
        if matches!(toks.get(i)?.2, TokenKind::Pound) {
            let bracket = next_solid(toks, i + 1);
            if !matches!(toks.get(bracket)?.2, TokenKind::OpenBracket) {
                return None;
            }
            i = skip_until(toks, bracket, TokenKind::OpenBracket, TokenKind::CloseBracket)?;
            continue;
        }
        break;
    }
    if word_is(src, toks, i, "pub") {
        let next = next_solid(toks, i + 1);
        if matches!(toks.get(next).map(|tok| tok.2), Some(TokenKind::OpenParen)) {
            i = next_solid(
                toks,
                skip_until(toks, next, TokenKind::OpenParen, TokenKind::CloseParen)?,
            );
        } else {
            i = next;
        }
    }
    word_is(src, toks, i, "mod").then_some(i)
}

fn module_end(toks: &[(usize, usize, TokenKind)], mod_i: usize) -> Option<usize> {
    let name = next_solid(toks, mod_i + 1);
    toks.get(name)?;
    let after = next_solid(toks, name + 1);
    match toks.get(after).map(|tok| tok.2) {
        Some(TokenKind::Semi) => Some(toks[after].1),
        Some(TokenKind::OpenBrace) => {
            skip_until(toks, after, TokenKind::OpenBrace, TokenKind::CloseBrace)
                .map(|idx| toks[idx - 1].1)
        }
        _ => None,
    }
}

/// Byte where the test module's `#[cfg(test)]` starts, or an error when code follows it.
fn bn_test_cut(src: &str, toks: &[(usize, usize, TokenKind)]) -> Result<Option<usize>, String> {
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i].2, TokenKind::Pound) {
            if let Some(after) = cfg_test_attr_end(src, toks, i) {
                if let Some(mod_i) = mod_after(src, toks, after) {
                    let end = module_end(toks, mod_i).ok_or("unclosed test module")?;
                    let follows = toks.iter().any(|tok| tok.0 >= end && !is_gap(tok.2));
                    if follows {
                        return Err("production code follows the test module".to_string());
                    }
                    return Ok(Some(toks[i].0));
                }
            }
        }
        i += 1;
    }
    Ok(None)
}

#[derive(Debug)]
struct BnHit {
    file: String,
    item: String,
    fp: String,
}

#[derive(Debug)]
struct BnRow {
    file: String,
    item: String,
    raw: String,
}

fn bn_hits(files: &[(String, String)]) -> Result<Vec<BnHit>, String> {
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    for (path, src) in files {
        let toks = match lex_file(src, true) {
            Ok(toks) => toks,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        let items = match SourceItems::parse(src) {
            Ok(items) => items,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        let starts = line_starts(src);
        let cut = match bn_test_cut(src, &toks) {
            Ok(cut) => cut,
            Err(err) => {
                errors.push(format!("row {path}: {err}"));
                continue;
            }
        };
        for at in tokio_spawn_calls(src, &toks) {
            if cut.is_some_and(|cut| at >= cut) {
                continue;
            }
            let fp = line_text_at(src, &starts, at);
            match items.enclosing(at) {
                Err(err) => errors.push(format!("row {path} fingerprint {fp:?}: {err}")),
                Ok(id) if id.as_str().is_empty() || id.as_str() == "<module>" => {
                    errors.push(format!("row {path} fingerprint {fp:?}: refusing <module>"));
                }
                Ok(id) => {
                    hits.push(BnHit { file: path.clone(), item: id.as_str().to_string(), fp })
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(hits)
    } else {
        Err(errors.join("\n"))
    }
}

fn is_line_number(cell: &str) -> bool {
    !cell.is_empty() && cell.chars().all(|c| c.is_ascii_digit())
}

fn parse_bn_rows(section: &str) -> Result<Vec<BnRow>, String> {
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    for cells in markdown_table(section) {
        let raw = cells.join(" | ");
        if cells.len() < 3 {
            errors.push(format!("bn-manager row needs file, item, call: {raw}"));
            continue;
        }
        if is_line_number(&cells[1]) {
            errors.push(format!("bn-manager row uses a line number as the item: {raw}"));
            continue;
        }
        if cells[2] != "tokio::spawn" {
            errors.push(format!("bn-manager row call must be tokio::spawn: {raw}"));
            continue;
        }
        rows.push(BnRow { file: cells[0].clone(), item: cells[1].clone(), raw });
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors.join("\n"))
    }
}

fn reconcile_bn(rows: &[BnRow], hits: &[BnHit]) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut expected: HashMap<String, String> = HashMap::new();
    for row in rows {
        let detail = format!("bn-manager {} item `{}` ({})", row.file, row.item, row.raw);
        let key = format!("{}\n{}", row.file, row.item);
        if expected.insert(key, detail.clone()).is_some() {
            errors.push(format!("duplicate {detail}"));
        }
    }
    let mut seen: HashMap<String, String> = HashMap::new();
    for hit in hits {
        let detail =
            format!("bn-manager {} item `{}` fingerprint {:?}", hit.file, hit.item, hit.fp);
        let key = format!("{}\n{}", hit.file, hit.item);
        if let Some(prev) = seen.insert(key.clone(), detail.clone()) {
            errors.push(format!("duplicate hit {detail}; also {prev}"));
            continue;
        }
        if !expected.contains_key(&key) {
            errors.push(format!("extra {detail}"));
        }
    }
    for (key, detail) in &expected {
        if !seen.contains_key(key) {
            errors.push(format!("missing {detail}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn bn_section_matches(census: &str, files: &[(String, String)]) -> Result<(), String> {
    let rows = parse_bn_rows(&section_body(census, "bn-manager raw"))?;
    reconcile_bn(&rows, &bn_hits(files)?)
}

fn check_bn(rows: &[(&str, &str)], files: &[(&str, &str)]) -> Result<(), String> {
    let owned: Vec<(String, String)> =
        files.iter().map(|(path, src)| ((*path).to_string(), (*src).to_string())).collect();
    let content: Vec<BnRow> = rows
        .iter()
        .map(|(file, item)| BnRow {
            file: (*file).to_string(),
            item: (*item).to_string(),
            raw: format!("{file} {item}"),
        })
        .collect();
    reconcile_bn(&content, &bn_hits(&owned)?)
}

fn load_bn(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for rel in tracked_bn_files(root)? {
        let src =
            std::fs::read_to_string(root.join(&rel)).map_err(|err| format!("row {rel}: {err}"))?;
        out.push((rel, src));
    }
    Ok(out)
}

#[test]
fn census_bn_manager_rows_match_sources() {
    let root = workspace_root();
    let census = std::fs::read_to_string(root.join(CENSUS)).unwrap();
    let files = load_bn(&root).unwrap_or_else(|err| panic!("{err}"));
    bn_section_matches(&census, &files).unwrap_or_else(|err| panic!("{err}"));
}

#[test]
fn census_accepts_a_spawn_inside_a_closure() {
    let src = "fn outer() {\n    let _ = || { tokio::spawn(async {}); };\n}\n";
    check_bn(&[("a.rs", "outer")], &[("a.rs", src)]).unwrap();
    let err = check_bn(&[("a.rs", "<closure>")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("<closure>") && err.contains("outer"), "{err}");
}

#[test]
fn census_accepts_a_spawn_inside_a_macro() {
    let src = "macro_rules! m {\n    () => { tokio::spawn(async {}); };\n}\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_accepts_a_spawn_inside_a_nested_mod() {
    let src = "mod outer {\n    fn inner() {\n        tokio::spawn(async {});\n    }\n}\n";
    check_bn(&[("a.rs", "outer::inner")], &[("a.rs", src)]).unwrap();
    let err = check_bn(&[("a.rs", "inner")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("inner") && err.contains("outer::inner"), "{err}");
}

#[test]
fn census_accepts_spaced_tokio_spawn_tokens() {
    let src = "fn item() {\n    tokio /* gap */ :: spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_tokio_spawn_in_a_comment_or_string() {
    let src = "fn item() {\n    // tokio::spawn(async {});\n    let _ = \"tokio::spawn\";\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_a_spawn_inside_a_cfg_test_module() {
    let src = "\
fn item() {\n\
    tokio::spawn(async {});\n\
}\n\
#[cfg(test)]\n\
mod tests {\n\
    fn hidden() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_ignores_a_use_of_tokio_spawn() {
    let src = "use tokio::spawn;\nfn item() {\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_rejects_a_row_whose_item_is_gone() {
    let src = "fn now() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "gone")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("gone") && err.contains("now"), "{err}");
}

#[test]
fn census_rejects_a_duplicated_row() {
    let src = "fn item() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item"), ("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("duplicate"), "{err}");
    let twin = "fn item() {\n    tokio::spawn(async {});\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", twin)]).unwrap_err();
    assert!(err.contains("duplicate hit"), "{err}");
}

#[test]
fn census_rejects_a_row_moved_to_another_file() {
    let src = "fn item() {\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("b.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("b.rs"), "{err}");
}

#[test]
fn census_rejects_an_ambiguous_item() {
    let src = "fn f() {\n    tokio::spawn(async {});\n}\nfn f() {}\n";
    let err = check_bn(&[("a.rs", "f")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("ambiguous"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_rejects_an_untrusted_file() {
    let src = "fn f() {\n    tokio::spawn(async {});\n    let _ = \"unterminated;\n}\n";
    let err = check_bn(&[("a.rs", "f")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("unclosed") || err.contains("unterminated"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_rejects_a_shebang_file() {
    let src = "#!/usr/bin/env rust\nfn item() { tokio::spawn(async {}); }\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("shebang"), "{err}");
}

#[test]
fn census_rejects_a_module_level_spawn() {
    let src = "tokio::spawn(async {});\n";
    let err = check_bn(&[("a.rs", "<module>")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("refusing <module>"), "{err}");
}

#[test]
fn census_rejects_a_line_numbered_item() {
    let section = "\
| File | Item | Call |\n\
|---|---|---|\n\
| `crates/bn-manager/src/manager.rs` | 785 | `tokio::spawn` in `start_sse` |\n\
";
    let err = parse_bn_rows(section).unwrap_err();
    assert!(
        err.contains("line number") && err.contains("785") && err.contains("start_sse"),
        "{err}"
    );
}

#[test]
fn census_rejects_a_production_multibyte_char_literal() {
    let src = "fn item() {\n    let _ = '€';\n    tokio::spawn(async {});\n}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap_err();
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("lexer mask disagreed"), "{err}");
    assert!(!err.contains("<module>"), "{err}");
}

#[test]
fn census_accepts_a_multibyte_char_inside_a_string() {
    let src = "fn item() {\n    let _ = \"€\";\n    tokio::spawn(async {});\n}\n";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

fn init_bn_repo(files: &[(&str, &str)]) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "bn-census-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("crates/bn-manager/src")).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).current_dir(&root).output().expect("git");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    git(&["init", "-q"]);
    for (rel, src) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, src).unwrap();
    }
    git(&["add", "-A"]);
    root
}

#[test]
fn census_reads_non_ascii_and_quoted_tracked_paths() {
    let cafe = "crates/bn-manager/src/café.rs";
    let messy = "crates/bn-manager/src/q\"b\\c\td.rs";
    let body = "fn h() { tokio::spawn(async {}); }\n";
    let root = init_bn_repo(&[(cafe, body), (messy, body)]);
    let hits = bn_hits(&load_bn(&root).unwrap()).unwrap();
    assert!(hits.iter().any(|hit| hit.file.contains("café")), "dropped non-ascii: {hits:?}");
    assert!(
        hits.iter().any(|hit| hit.file.contains('"')
            && hit.file.contains('\\')
            && hit.file.contains('\t')),
        "dropped quoted path: {hits:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_names_a_non_utf8_tracked_path() {
    use std::os::unix::ffi::OsStringExt;
    let root = init_bn_repo(&[]);
    let mut name = b"bad".to_vec();
    name.push(0xff);
    name.extend(b".rs");
    let path = root.join("crates/bn-manager/src").join(std::ffi::OsString::from_vec(name));
    std::fs::write(&path, "fn h() { tokio::spawn(async {}); }\n").unwrap();
    let out = Command::new("git").args(["add", "-A"]).current_dir(&root).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let err = tracked_bn_files(&root).unwrap_err();
    assert!(err.contains("non-utf8") && err.contains("bad"), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_names_an_unreadable_tracked_file() {
    let rel = "crates/bn-manager/src/gone.rs";
    let root = init_bn_repo(&[(rel, "fn h() { tokio::spawn(async {}); }\n")]);
    std::fs::remove_file(root.join(rel)).unwrap();
    let err = load_bn(&root).unwrap_err();
    assert!(err.contains(rel), "{err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn census_accepts_r_hash_tokio_spawn_inside_a_macro() {
    let src = "macro_rules! m { () => { r#tokio::spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
    let both = "macro_rules! m { () => { r#tokio::r#spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", both)]).unwrap();
}

#[test]
fn census_accepts_r_hash_spawn_inside_a_macro() {
    let src = "macro_rules! m { () => { tokio::r#spawn(async {}); }; }\n";
    check_bn(&[("a.rs", "macro_rules!m")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_keeps_a_spawn_after_a_raw_string_cfg_decoy() {
    let src = "\
fn item() {\n\
    let _ = r#\"\n\
#[cfg(test)]\n\
mod x\n\
\"#;\n\
    tokio::spawn(async {});\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_keeps_a_spawn_after_a_block_comment_cfg_decoy() {
    let src = "\
fn item() {\n\
    /*\n\
#[cfg(test)]\n\
mod x\n\
*/\n\
    tokio::spawn(async {});\n\
}\n\
";
    check_bn(&[("a.rs", "item")], &[("a.rs", src)]).unwrap();
}

#[test]
fn census_rejects_production_code_after_the_test_module() {
    let braced = "\
fn item() {\n\
    tokio::spawn(async {});\n\
}\n\
#[cfg(test)]\n\
mod tests {\n\
    fn hidden() { tokio::spawn(async {}); }\n\
}\n\
fn after() {}\n\
";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", braced)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
    let semi = "fn item() { tokio::spawn(async {}); }\n#[cfg(test)] mod tests;\nfn after() {}\n";
    let err = check_bn(&[("a.rs", "item")], &[("a.rs", semi)]).unwrap_err();
    assert!(err.contains("a.rs") && err.contains("follows the test module"), "{err}");
}

#[test]
fn census_keeps_a_spawn_inside_a_non_test_cfg_module() {
    let unix = "\
fn item() { tokio::spawn(async {}); }\n\
#[cfg(unix)]\n\
mod p {\n\
    pub fn g() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item"), ("a.rs", "p::g")], &[("a.rs", unix)]).unwrap();
    let not_test = "\
fn item() { tokio::spawn(async {}); }\n\
#[cfg(not(test))]\n\
mod p {\n\
    pub fn g() { tokio::spawn(async {}); }\n\
}\n\
";
    check_bn(&[("a.rs", "item"), ("a.rs", "p::g")], &[("a.rs", not_test)]).unwrap();
}
