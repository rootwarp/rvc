//! String- and comment-aware Rust lexer and qualified-item resolver.
//!
//! [`mask_comments_and_strings`] blanks comments and strings without moving
//! bytes. [`enclosing_item`] is the innermost function (`outer::inner`,
//! `Type::method`, `<Type as Trait>::method`, `tests::name`). A `macro_rules!`
//! body resolves to `macro_rules!m`. A closure stays with its function. A byte
//! outside every function and `macro_rules!` body resolves to `<module>`. A repeated qualified name is
//! [`ResolveError::Ambiguous`].

use std::collections::BTreeMap;

const MAX_NESTING: usize = 256;
const MAX_ITEMS: usize = 20_000;
const MAX_ANGLE_SCAN: usize = 100_000;

/// Whitespace rustc accepts between tokens: space, tab, LF, VT (`0x0B`), FF, CR.
/// `u8::is_ascii_whitespace` omits VT. A byte `>= 0x80` is not whitespace.
pub fn is_rust_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

fn push_masked(out: &mut Vec<u8>, byte: u8) {
    out.push(if byte == b'\n' { b'\n' } else { b' ' });
}

/// True when `i` is at the start of an identifier.
pub fn ident_boundary_before(bytes: &[u8], i: usize) -> bool {
    i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
}

/// `r"…"`, `r#"…"#`, `br"…"`, `cr#"…"#`. `Some(false)` is an unclosed raw string.
fn try_mask_raw_string_closed(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> Option<bool> {
    if !ident_boundary_before(bytes, *i) {
        return None;
    }
    let mut j = *i;
    if matches!(bytes.get(j), Some(b'b' | b'B' | b'c' | b'C')) {
        j += 1;
    }
    if !matches!(bytes.get(j), Some(b'r' | b'R')) {
        return None;
    }
    j += 1;
    let mut hashes = 0usize;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while *i < j {
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    let closer = {
        let mut c = vec![b'"'];
        c.extend(std::iter::repeat_n(b'#', hashes));
        c
    };
    while *i < bytes.len() {
        if bytes[*i..].starts_with(&closer) {
            for _ in 0..closer.len() {
                push_masked(out, bytes[*i]);
                *i += 1;
            }
            return Some(true);
        }
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    Some(false)
}

/// `r"…"`, `r#"…"#`, `br"…"`, `cr#"…"#`. Advances `i` when a raw string starts there.
pub fn try_mask_raw_string(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> bool {
    try_mask_raw_string_closed(bytes, out, i).is_some()
}

/// Cooked `"…"` or `b"…"`, including escapes. The opener is at `i`.
/// False when the closing quote is missing.
pub fn mask_cooked_string(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> bool {
    if matches!(bytes.get(*i), Some(b'b' | b'B')) && bytes.get(*i + 1) == Some(&b'"') {
        push_masked(out, bytes[*i]);
        *i += 1;
    }
    debug_assert_eq!(bytes.get(*i), Some(&b'"'));
    push_masked(out, b'"');
    *i += 1;
    while *i < bytes.len() {
        let ch = bytes[*i];
        if ch == b'\\' {
            push_masked(out, ch);
            *i += 1;
            if *i < bytes.len() {
                push_masked(out, bytes[*i]);
                *i += 1;
            }
            continue;
        }
        push_masked(out, ch);
        *i += 1;
        if ch == b'"' {
            return true;
        }
    }
    false
}

/// `'x'`, `'\n'`, `'"'`, `b'"'`. Lifetimes (`'a`, `'static`) return false.
pub fn try_mask_char_literal(bytes: &[u8], out: &mut Vec<u8>, i: &mut usize) -> bool {
    if !ident_boundary_before(bytes, *i) {
        return false;
    }
    let mut j = *i;
    if matches!(bytes.get(j), Some(b'b' | b'B')) {
        j += 1;
    }
    if bytes.get(j) != Some(&b'\'') {
        return false;
    }
    let body = j + 1;
    if bytes.get(body) == Some(&b'\\') {
        let mut k = body + 2;
        while k < bytes.len() && bytes[k] != b'\'' {
            if bytes[k] == b'\n' {
                return false;
            }
            k += 1;
        }
        if k >= bytes.len() {
            return false;
        }
        while *i <= k {
            push_masked(out, bytes[*i]);
            *i += 1;
        }
        return true;
    }
    if bytes.get(body).is_some()
        && bytes.get(body) != Some(&b'\'')
        && bytes.get(body + 1) == Some(&b'\'')
    {
        let end = body + 1;
        while *i <= end {
            push_masked(out, bytes[*i]);
            *i += 1;
        }
        return true;
    }
    false
}

/// Blank comments and string/char/raw-string contents. Newlines and length stay.
pub fn mask_comments_and_strings(src: &str) -> String {
    mask_source(src).0
}

/// Half-open ranges the masker treated as a comment or a string or char literal.
/// Sorted, non-overlapping. The hazard scanner drops hits inside these ranges.
pub fn non_code_spans(src: &str) -> Vec<(usize, usize)> {
    mask_source(src).2
}

/// `at` is code when it sits in no span from [`non_code_spans`].
pub fn byte_in_code(non_code: &[(usize, usize)], at: usize) -> bool {
    non_code
        .binary_search_by(|&(start, end)| {
            if at < start {
                std::cmp::Ordering::Greater
            } else if at >= end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_err()
}

/// Mask, whether every string and block comment is closed, and the non-code spans.
fn mask_source(src: &str) -> (String, bool, Vec<(usize, usize)>) {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut non_code = Vec::new();
    let mut i = 0;
    let mut closed = true;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            non_code.push((start, i));
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let start = i;
            out.push(b' ');
            out.push(b' ');
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    depth += 1;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    depth -= 1;
                } else {
                    push_masked(&mut out, bytes[i]);
                    i += 1;
                }
            }
            closed &= depth == 0;
            non_code.push((start, i));
            continue;
        }
        let start = i;
        if let Some(ok) = try_mask_raw_string_closed(bytes, &mut out, &mut i) {
            non_code.push((start, i));
            closed &= ok;
            continue;
        }
        if matches!(bytes.get(i), Some(b'b' | b'B'))
            && bytes.get(i + 1) == Some(&b'"')
            && ident_boundary_before(bytes, i)
        {
            closed &= mask_cooked_string(bytes, &mut out, &mut i);
            non_code.push((start, i));
            continue;
        }
        if bytes[i] == b'"' {
            closed &= mask_cooked_string(bytes, &mut out, &mut i);
            non_code.push((start, i));
            continue;
        }
        if try_mask_char_literal(bytes, &mut out, &mut i) {
            non_code.push((start, i));
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    debug_assert_eq!(out.len(), bytes.len());
    (String::from_utf8(out).expect("masking preserves UTF-8"), closed, non_code)
}

/// Qualified enclosing item. See the module docs for the name shapes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemId(String);

impl ItemId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hit outside every function and `macro_rules!` body.
    pub fn module() -> Self {
        Self("<module>".to_string())
    }
}

impl std::fmt::Display for ItemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One function or `macro_rules!` span. `end` is the closing delimiter's byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSpan {
    pub qualified: String,
    pub start: usize,
    pub end: usize,
}

/// Why a byte offset could not be given a single item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `qualified` is declared more than once. `lines` are 1-based and name every copy.
    Ambiguous {
        qualified: String,
        lines: Vec<usize>,
    },
    OffsetOutOfRange {
        offset: usize,
        len: usize,
    },
    /// Brace nesting passed [`MAX_NESTING`].
    NestingTooDeep {
        limit: usize,
    },
    /// An impl generic-argument scan passed [`MAX_ANGLE_SCAN`] bytes.
    AngleScanTooLong {
        limit: usize,
    },
    /// `r#` plus an ASCII ident start, on a word this scanner reads (a name or
    /// a body ident). A raw ident inside a header is not read. `r#é` is
    /// [`ResolveError::NonAscii`]: the non-ASCII byte is rejected in
    /// [`SourceItems::parse`] before this arm runs.
    RawIdent,
    /// The file declared more items than [`MAX_ITEMS`].
    TooManyItems {
        limit: usize,
    },
    /// A `{` never closed, or a header ran off the end of the file.
    Unclosed {
        depth: usize,
    },
    /// A string, block comment, or `#[` attribute never closed.
    Unterminated,
    Unbalanced,
    UnreadableImpl,
    /// Masked length differs from the source, so offsets would not match.
    MaskLength {
        masked: usize,
        source: usize,
    },
    /// The scanner did not advance. Treated as a broken file, not a skip.
    Stalled {
        offset: usize,
    },
    /// Non-ASCII outside a comment or string. Not read as a name.
    NonAscii,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ambiguous { qualified, lines } => {
                let at = lines.iter().map(|n| format!("line {n}")).collect::<Vec<_>>().join(", ");
                write!(f, "ambiguous qualified item `{qualified}` at {at}")
            }
            Self::OffsetOutOfRange { offset, len } => {
                write!(f, "byte offset {offset} is outside source of length {len}")
            }
            Self::NestingTooDeep { limit } => write!(f, "rust item nesting exceeds {limit}"),
            Self::AngleScanTooLong { limit } => {
                write!(f, "angle-bracket scan exceeds {limit} bytes")
            }
            Self::RawIdent => write!(f, "raw identifier"),
            Self::TooManyItems { limit } => write!(f, "rust item count exceeds {limit}"),
            Self::Unclosed { depth } => write!(f, "unclosed brace at depth {depth}"),
            Self::Unterminated => write!(f, "unclosed string, comment, or attribute"),
            Self::Unbalanced => write!(f, "closing brace without an open brace"),
            Self::UnreadableImpl => write!(f, "impl header has no type"),
            Self::MaskLength { masked, source } => {
                write!(f, "masked length {masked} != source length {source}")
            }
            Self::Stalled { offset } => write!(f, "item scanner stalled at byte {offset}"),
            Self::NonAscii => write!(f, "non-ascii byte"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Items in one source file. Build with [`SourceItems::parse`], then resolve
/// every hit against that value.
#[derive(Debug, Clone)]
pub struct SourceItems {
    len: usize,
    spans: Vec<ItemSpan>,
    /// Qualified name → 1-based lines of each declaration, ascending.
    name_lines: BTreeMap<String, Vec<usize>>,
}

impl SourceItems {
    pub fn parse(src: &str) -> Result<Self, ResolveError> {
        let (masked, closed, _) = mask_source(src);
        if !closed {
            return Err(ResolveError::Unterminated);
        }
        if masked.len() != src.len() {
            return Err(ResolveError::MaskLength { masked: masked.len(), source: src.len() });
        }
        // One check, after comments and strings are blanked. Macro bodies and
        // attributes are included; they are not special-cased below.
        if masked.bytes().any(|b| b >= 0x80) {
            return Err(ResolveError::NonAscii);
        }
        let mut parser = Parser { src: &masked, i: 0, depth: 0, items: Vec::new() };
        parser.parse_until(&Ctx::default(), false)?;
        let mut name_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut spans = Vec::with_capacity(parser.items.len());
        for item in parser.items {
            name_lines.entry(item.name.clone()).or_default().push(line_of(src, item.start));
            spans.push(ItemSpan { qualified: item.name, start: item.start, end: item.end });
        }
        for lines in name_lines.values_mut() {
            lines.sort_unstable();
        }
        Ok(Self { len: src.len(), spans, name_lines })
    }

    /// Innermost function or `macro_rules!` containing `offset`.
    ///
    /// `offset` is a byte index into the same `src` passed to [`parse`](Self::parse).
    pub fn enclosing(&self, offset: usize) -> Result<ItemId, ResolveError> {
        if offset >= self.len {
            return Err(ResolveError::OffsetOutOfRange { offset, len: self.len });
        }
        let mut best: Option<&ItemSpan> = None;
        for span in &self.spans {
            if span.start <= offset && offset <= span.end {
                let replace = match best {
                    None => true,
                    Some(cur) => {
                        span.start > cur.start || (span.start == cur.start && span.end < cur.end)
                    }
                };
                if replace {
                    best = Some(span);
                }
            }
        }
        let Some(span) = best else {
            return Ok(ItemId::module());
        };
        let lines = &self.name_lines[&span.qualified];
        if lines.len() > 1 {
            return Err(ResolveError::Ambiguous {
                qualified: span.qualified.clone(),
                lines: lines.clone(),
            });
        }
        Ok(ItemId(span.qualified.clone()))
    }
}

/// Qualified item containing `offset`, or [`ItemId::module`] when none does.
///
/// ```
/// use rvc_architecture_tests::enclosing_item;
/// let src = "impl Foo { fn bar(&self) { let ANCHOR = 1; } }\n";
/// let at = src.find("ANCHOR").unwrap();
/// assert_eq!(enclosing_item(src, at).unwrap().as_str(), "Foo::bar");
/// ```
pub fn enclosing_item(src: &str, offset: usize) -> Result<ItemId, ResolveError> {
    SourceItems::parse(src)?.enclosing(offset)
}

fn line_of(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

#[derive(Clone, Default)]
struct Ctx {
    modules: Vec<String>,
    impl_prefix: Option<String>,
    fns: Vec<String>,
}

impl Ctx {
    fn qual(&self, name: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        parts.extend(self.modules.iter().map(String::as_str));
        if let Some(prefix) = &self.impl_prefix {
            parts.push(prefix);
        }
        parts.extend(self.fns.iter().map(String::as_str));
        parts.push(name);
        parts.join("::")
    }

    fn child_fn(&self, name: &str) -> Self {
        let mut ctx = self.clone();
        ctx.fns.push(name.to_string());
        ctx
    }

    fn child_mod(&self, name: String) -> Self {
        let mut modules = self.modules.clone();
        modules.push(name);
        Self { modules, impl_prefix: None, fns: Vec::new() }
    }

    fn child_impl(&self, prefix: String) -> Self {
        Self { modules: self.modules.clone(), impl_prefix: Some(prefix), fns: Vec::new() }
    }

    fn qual_macro(&self, name: &str) -> String {
        let mut parts = self.modules.clone();
        parts.push(format!("macro_rules!{name}"));
        parts.join("::")
    }
}

struct RawItem {
    name: String,
    start: usize,
    end: usize,
}

struct Parser<'a> {
    src: &'a str,
    i: usize,
    depth: usize,
    items: Vec<RawItem>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Brace,
    Semi,
}

impl<'a> Parser<'a> {
    fn bytes(&self) -> &'a [u8] {
        self.src.as_bytes()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes().get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_rust_ws) {
            self.i += 1;
        }
    }

    fn read_ident(&mut self) -> Result<Option<String>, ResolveError> {
        self.skip_ws();
        let bytes = self.bytes();
        if bytes.get(self.i) == Some(&b'r') && bytes.get(self.i + 1) == Some(&b'#') {
            let next = bytes.get(self.i + 2).copied();
            if next.is_some_and(is_ident_start) {
                return Err(ResolveError::RawIdent);
            }
        }
        let start = self.i;
        if !self.peek().is_some_and(is_ident_start) {
            return Ok(None);
        }
        self.i += 1;
        while self.peek().is_some_and(is_ident_continue) {
            self.i += 1;
        }
        Ok(Some(self.src[start..self.i].to_string()))
    }

    fn try_attribute(&mut self) -> Result<bool, ResolveError> {
        if self.peek() != Some(b'#') {
            return Ok(false);
        }
        let bytes = self.bytes();
        let mut j = self.i + 1;
        while bytes.get(j).is_some_and(|b| is_rust_ws(*b)) {
            j += 1;
        }
        if bytes.get(j) == Some(&b'!') {
            j += 1;
            while bytes.get(j).is_some_and(|b| is_rust_ws(*b)) {
                j += 1;
            }
        }
        if bytes.get(j) != Some(&b'[') {
            return Ok(false);
        }
        self.i = j + 1;
        let mut depth = 1i32;
        while self.i < bytes.len() && depth > 0 {
            match self.bytes()[self.i] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            self.i += 1;
        }
        if depth > 0 {
            return Err(ResolveError::Unterminated);
        }
        Ok(true)
    }

    fn push_item(&mut self, name: String, start: usize, end: usize) -> Result<(), ResolveError> {
        if self.items.len() >= MAX_ITEMS {
            return Err(ResolveError::TooManyItems { limit: MAX_ITEMS });
        }
        self.items.push(RawItem { name, start, end });
        Ok(())
    }

    fn enter(&mut self) -> Result<(), ResolveError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(ResolveError::NestingTooDeep { limit: MAX_NESTING });
        }
        Ok(())
    }

    fn parse_until(&mut self, ctx: &Ctx, in_block: bool) -> Result<usize, ResolveError> {
        loop {
            let before = self.i;
            self.skip_ws();
            if self.i >= self.bytes().len() {
                if in_block {
                    return Err(ResolveError::Unclosed { depth: self.depth });
                }
                return Ok(self.src.len());
            }
            if self.try_attribute()? {
                self.advanced(before)?;
                continue;
            }
            let b = self.bytes()[self.i];
            if b == b'}' {
                if !in_block {
                    return Err(ResolveError::Unbalanced);
                }
                let end = self.i;
                self.i += 1;
                return Ok(end);
            }
            if b == b'{' {
                self.i += 1;
                self.enter()?;
                self.parse_until(ctx, true)?;
                self.depth -= 1;
                self.advanced(before)?;
                continue;
            }
            if is_ident_start(b) {
                let at = self.i;
                let Some(word) = self.read_ident()? else {
                    return Err(ResolveError::Stalled { offset: at });
                };
                match word.as_str() {
                    "fn" => self.parse_fn(at, ctx)?,
                    "mod" => self.parse_mod(ctx)?,
                    "impl" => self.parse_impl(ctx)?,
                    "trait" => self.parse_trait(ctx)?,
                    "macro_rules" => self.parse_macro(at, ctx)?,
                    _ => {}
                }
                self.advanced(before)?;
                continue;
            }
            self.i += 1;
            self.advanced(before)?;
        }
    }

    fn advanced(&self, before: usize) -> Result<(), ResolveError> {
        if self.i > before {
            Ok(())
        } else {
            Err(ResolveError::Stalled { offset: before })
        }
    }

    fn parse_fn(&mut self, kw: usize, ctx: &Ctx) -> Result<(), ResolveError> {
        let Some(name) = self.read_ident()? else {
            return Ok(());
        };
        if self.skip_until_brace_or_semi()? != Stop::Brace {
            return Ok(());
        }
        let qual = ctx.qual(&name);
        let nested = ctx.child_fn(&name);
        let end = self.consume_block(&nested)?;
        self.push_item(qual, kw, end)
    }

    fn parse_mod(&mut self, ctx: &Ctx) -> Result<(), ResolveError> {
        let Some(name) = self.read_ident()? else {
            return Ok(());
        };
        self.skip_ws();
        if self.peek() == Some(b'{') {
            let nested = ctx.child_mod(name);
            self.consume_block(&nested)?;
        } else if self.peek() == Some(b';') {
            self.i += 1;
        }
        Ok(())
    }

    fn parse_trait(&mut self, ctx: &Ctx) -> Result<(), ResolveError> {
        let Some(name) = self.read_ident()? else {
            return Ok(());
        };
        if self.skip_until_brace_or_semi()? != Stop::Brace {
            return Ok(());
        }
        let nested = ctx.child_impl(name);
        self.consume_block(&nested)?;
        Ok(())
    }

    fn parse_impl(&mut self, ctx: &Ctx) -> Result<(), ResolveError> {
        let Some(prefix) = self.read_impl_prefix()? else {
            return Ok(());
        };
        if self.peek() != Some(b'{') {
            return Ok(());
        }
        let nested = ctx.child_impl(prefix);
        self.consume_block(&nested)?;
        Ok(())
    }

    fn parse_macro(&mut self, kw: usize, ctx: &Ctx) -> Result<(), ResolveError> {
        self.skip_ws();
        if self.peek() != Some(b'!') {
            return Ok(());
        }
        self.i += 1;
        let Some(name) = self.read_ident()? else {
            return Ok(());
        };
        self.skip_ws();
        let qual = ctx.qual_macro(&name);
        let end = match self.peek() {
            Some(b'{') => {
                self.i += 1;
                self.enter()?;
                self.skip_opaque_braces()?
            }
            Some(b'(') => self.skip_balanced(b'(', b')')?,
            Some(b'[') => self.skip_balanced(b'[', b']')?,
            _ => return Ok(()),
        };
        self.push_item(qual, kw, end)
    }

    fn consume_block(&mut self, ctx: &Ctx) -> Result<usize, ResolveError> {
        // Caller leaves `i` on `{`.
        self.i += 1;
        self.enter()?;
        let end = self.parse_until(ctx, true)?;
        self.depth -= 1;
        Ok(end)
    }

    fn skip_opaque_braces(&mut self) -> Result<usize, ResolveError> {
        // Opening `{` is already consumed. No nested items.
        let mut depth = 1i32;
        while self.i < self.bytes().len() && depth > 0 {
            match self.bytes()[self.i] {
                b'{' => {
                    self.enter()?;
                    depth += 1;
                }
                b'}' => {
                    depth -= 1;
                    self.depth -= 1;
                    if depth == 0 {
                        let end = self.i;
                        self.i += 1;
                        return Ok(end);
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        Err(ResolveError::Unclosed { depth: self.depth })
    }

    fn skip_balanced(&mut self, open: u8, close: u8) -> Result<usize, ResolveError> {
        if self.peek() != Some(open) {
            return Err(ResolveError::Unclosed { depth: self.depth });
        }
        self.i += 1;
        let mut depth = 1i32;
        while self.i < self.bytes().len() && depth > 0 {
            let b = self.bytes()[self.i];
            if b == open {
                depth += 1;
            } else if b == close {
                depth -= 1;
                if depth == 0 {
                    let end = self.i;
                    self.i += 1;
                    return Ok(end);
                }
            }
            self.i += 1;
        }
        Err(ResolveError::Unclosed { depth: self.depth })
    }

    fn skip_until_brace_or_semi(&mut self) -> Result<Stop, ResolveError> {
        let bytes = self.src.as_bytes();
        let mut i = self.i;
        let mut scan = HeaderScan::default();
        while i < bytes.len() {
            let b = bytes[i];
            if scan.at_header_end() && (b == b'{' || b == b';') {
                self.i = i;
                return Ok(if b == b'{' {
                    Stop::Brace
                } else {
                    self.i += 1;
                    Stop::Semi
                });
            }
            let before = i;
            scan.bump(bytes, &mut i);
            if i <= before {
                self.i = i;
                return Err(ResolveError::Stalled { offset: before });
            }
        }
        self.i = i;
        Err(ResolveError::Unclosed { depth: self.depth })
    }

    fn advance_header(&mut self, scan: &mut HeaderScan) -> Result<(), ResolveError> {
        let mut i = self.i;
        let before = i;
        scan.bump(self.src.as_bytes(), &mut i);
        self.i = i;
        if i <= before {
            Err(ResolveError::Stalled { offset: before })
        } else {
            Ok(())
        }
    }

    fn read_impl_prefix(&mut self) -> Result<Option<String>, ResolveError> {
        self.skip_impl_generics()?;
        self.skip_ws();
        let start = self.i;
        let mut for_at: Option<usize> = None;
        let mut type_from: Option<usize> = None;
        let mut where_at: Option<usize> = None;
        let mut scan = HeaderScan::default();
        while self.i < self.src.len() {
            let b = self.src.as_bytes()[self.i];
            if scan.at_header_end() && (b == b'{' || b == b';') {
                break;
            }
            if scan.at_header_end() && is_ident_start(b) {
                let at = self.i;
                let Some(word) = self.read_ident()? else {
                    return Err(ResolveError::Stalled { offset: at });
                };
                if word == "where" && where_at.is_none() {
                    where_at = Some(at);
                } else if word == "for" && where_at.is_none() && for_at.is_none() {
                    let mut j = self.i;
                    let bytes = self.bytes();
                    while bytes.get(j).is_some_and(|c| is_rust_ws(*c)) {
                        j += 1;
                    }
                    if bytes.get(j) != Some(&b'<') {
                        for_at = Some(at);
                        type_from = Some(self.i);
                    }
                }
                continue;
            }
            self.advance_header(&mut scan)?;
        }
        if self.peek() == Some(b';') {
            self.i += 1;
            return Ok(None);
        }
        if self.peek() != Some(b'{') {
            return Err(ResolveError::Unclosed { depth: self.depth });
        }
        let end = where_at.unwrap_or(self.i);
        let prefix = if let Some(for_at) = for_at {
            let tr = normalize_type(&self.src[start..for_at]);
            let ty = normalize_type(&self.src[type_from.unwrap_or(for_at)..end]);
            if tr.is_empty() || ty.is_empty() {
                return Err(ResolveError::UnreadableImpl);
            }
            format!("<{ty} as {tr}>")
        } else {
            let ty = normalize_type(&self.src[start..end]);
            if ty.is_empty() {
                return Err(ResolveError::UnreadableImpl);
            }
            ty
        };
        Ok(Some(prefix))
    }

    fn skip_impl_generics(&mut self) -> Result<(), ResolveError> {
        self.skip_ws();
        if self.peek() != Some(b'<') {
            return Ok(());
        }
        let save = self.i;
        let Some(end) = self.find_matching_angle(self.i)? else {
            return Ok(());
        };
        let bytes = self.bytes();
        let mut j = end;
        while bytes.get(j).is_some_and(|b| is_rust_ws(*b)) {
            j += 1;
        }
        if bytes.get(j) == Some(&b':') && bytes.get(j + 1) == Some(&b':') {
            self.i = save;
            return Ok(());
        }
        self.i = end;
        Ok(())
    }

    fn find_matching_angle(&self, start: usize) -> Result<Option<usize>, ResolveError> {
        let bytes = self.bytes();
        if bytes.get(start) != Some(&b'<') {
            return Ok(None);
        }
        let mut scan = HeaderScan::default();
        let mut i = start;
        while i < bytes.len() {
            let before = i;
            scan.bump(bytes, &mut i);
            if i <= before {
                return Err(ResolveError::Stalled { offset: before });
            }
            if scan.angle == 0 && !scan.const_expr && !scan.nested() {
                return Ok(Some(i));
            }
            if i - start >= MAX_ANGLE_SCAN {
                return Err(ResolveError::AngleScanTooLong { limit: MAX_ANGLE_SCAN });
            }
        }
        Err(ResolveError::Unclosed { depth: self.depth })
    }
}

/// Angle brackets in an impl/fn header. `<` and `>` are generic delimiters only
/// when no `()`, `[]`, or `{}` is open. Inside those, and in a `const` default,
/// they are operators.
#[derive(Default)]
struct HeaderScan {
    angle: i32,
    paren: i32,
    bracket: i32,
    brace: i32,
    const_expr: bool,
    saw_const: Option<i32>,
}

impl HeaderScan {
    fn nested(&self) -> bool {
        self.paren > 0 || self.bracket > 0 || self.brace > 0
    }

    fn at_header_end(&self) -> bool {
        !self.const_expr && !self.nested() && self.angle == 0
    }

    fn bump(&mut self, bytes: &[u8], i: &mut usize) {
        match bytes[*i] {
            b'(' => {
                self.paren += 1;
                *i += 1;
                return;
            }
            b')' => {
                if self.paren > 0 {
                    self.paren -= 1;
                }
                *i += 1;
                return;
            }
            b'[' => {
                self.bracket += 1;
                *i += 1;
                return;
            }
            b']' => {
                if self.bracket > 0 {
                    self.bracket -= 1;
                }
                *i += 1;
                return;
            }
            b'{' => {
                self.brace += 1;
                *i += 1;
                return;
            }
            b'}' => {
                if self.brace > 0 {
                    self.brace -= 1;
                }
                *i += 1;
                return;
            }
            _ => {}
        }
        if self.nested() || self.const_expr {
            self.bump_operator(bytes, i);
            return;
        }
        match bytes[*i] {
            b'<' => {
                self.angle += 1;
                *i += 1;
            }
            b'>' => {
                if self.angle > 0 && !angle_closer_is_operator(bytes, *i) {
                    self.angle -= 1;
                    self.saw_const = None;
                }
                *i += 1;
            }
            b',' => {
                self.saw_const = None;
                *i += 1;
            }
            b'=' => {
                let prev = prev_non_ws_at(bytes, *i);
                let next = bytes.get(*i + 1).copied();
                if self.saw_const == Some(self.angle)
                    && !matches!(prev, Some(b'=' | b'!' | b'<' | b'>'))
                    && !matches!(next, Some(b'=' | b'>'))
                {
                    self.const_expr = true;
                    self.saw_const = None;
                }
                *i += 1;
            }
            _ => {
                // `<const`, `, const`, or `#[…] const`. `*const` is a type.
                if word_at(bytes, *i, b"const") && self.angle > 0 && const_param(bytes, *i) {
                    self.saw_const = Some(self.angle);
                }
                *i += 1;
            }
        }
    }

    /// `<` / `>` while nested, or inside a const default. A lone `>` at generic
    /// depth ends the default and closes one angle.
    fn bump_operator(&mut self, bytes: &[u8], i: &mut usize) {
        match bytes[*i] {
            b'<' => {
                if matches!(bytes.get(*i + 1), Some(b'=' | b'<')) {
                    *i += 2;
                } else {
                    *i += 1;
                }
            }
            b'>' => {
                if bytes.get(*i + 1) == Some(&b'=') {
                    *i += 2;
                    return;
                }
                if self.const_expr && !self.nested() {
                    self.const_expr = false;
                    if self.angle > 0 {
                        self.angle -= 1;
                    }
                }
                *i += 1;
            }
            b',' if !self.nested() => {
                self.const_expr = false;
                *i += 1;
            }
            _ => *i += 1,
        }
    }
}

/// `->` and `=>` only when `-` or `=` is the adjacent byte.
fn angle_closer_is_operator(bytes: &[u8], index: usize) -> bool {
    index > 0 && matches!(bytes[index - 1], b'-' | b'=')
}

/// `const` at `i` is a const generic: after `<`, `,`, or `]` whose `[` follows `#`.
fn const_param(bytes: &[u8], i: usize) -> bool {
    let mut j = i;
    let mut depth = 0i32;
    while j > 0 {
        j -= 1;
        match bytes[j] {
            b if is_rust_ws(b) => {}
            b'<' | b',' if depth == 0 => return true,
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return prev_non_ws_at(bytes, j) == Some(b'#');
                }
            }
            _ if depth == 0 => return false,
            _ => {}
        }
    }
    false
}

fn word_at(bytes: &[u8], i: usize, word: &[u8]) -> bool {
    ident_boundary_before(bytes, i)
        && bytes[i..].starts_with(word)
        && bytes.get(i + word.len()).is_none_or(|b| !is_ident_continue(*b))
}

fn prev_non_ws_at(bytes: &[u8], index: usize) -> Option<u8> {
    let mut j = index;
    while j > 0 {
        j -= 1;
        if !is_rust_ws(bytes[j]) {
            return Some(bytes[j]);
        }
    }
    None
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn normalize_type(raw: &str) -> String {
    let mut collapsed = String::new();
    let mut prev_space = false;
    for c in raw.chars() {
        if c.is_ascii() && is_rust_ws(c as u8) {
            if !prev_space && !collapsed.is_empty() {
                collapsed.push(' ');
                prev_space = true;
            }
        } else {
            collapsed.push(c);
            prev_space = false;
        }
    }
    let collapsed = collapsed.trim();
    let chars: Vec<char> = collapsed.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if *c == ' ' {
            let prev = i.checked_sub(1).map(|p| chars[p]);
            let next = chars.get(i + 1).copied();
            // Keep the space after a comma (`Service<C, S>`). Drop the rest.
            let drop = matches!(next, Some('<' | '>' | ',' | ':' | '\''))
                || matches!(prev, Some('<' | '(' | ':' | '\''));
            if drop {
                continue;
            }
        }
        out.push(*c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(src: &str, needle: &str) -> usize {
        src.find(needle).unwrap_or_else(|| panic!("missing {needle} in {src}"))
    }

    #[test]
    fn enclosing_item_resolves_qualified_items() {
        let cases = [
            ("fn free_item() {\n    let ANCHOR = 1;\n}\n", "ANCHOR", "free_item"),
            (
                "impl Inherent {\n    fn method(&self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "Inherent::method",
            ),
            (
                "impl Trait for Type {\n    fn method(&self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "<Type as Trait>::method",
            ),
            ("fn outer() {\n    fn inner() { let ANCHOR = 1; }\n}\n", "ANCHOR", "outer::inner"),
            (
                "fn outer() {\n    let _ = move |grpc| async move { let ANCHOR = 1; };\n}\n",
                "ANCHOR",
                "outer",
            ),
            (
                "#[cfg(test)]\nmod tests {\n    fn name() { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "tests::name",
            ),
            ("const ANCHOR: usize = 1;\nfn other() {}\n", "ANCHOR", "<module>"),
            (
                "macro_rules! name {\n    () => { match x { ANCHOR => 1, } };\n}\n",
                "ANCHOR",
                "macro_rules!name",
            ),
            (
                "impl<T: Fn() -> u8> Wrapper<T> {\n    fn method(&self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "Wrapper<T>::method",
            ),
            (
                "impl Drop for EnvelopeSlotGuard<'_> {\n    fn drop(&mut self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "<EnvelopeSlotGuard<'_> as Drop>::drop",
            ),
            (
                "impl<C, S> Service<C, S> where C: Clone {\n    fn method(&self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "Service<C, S>::method",
            ),
            (
                "impl Foo<Bar<u8>> {\n    fn method(&self) { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "Foo<Bar<u8>>::method",
            ),
        ];
        for (src, needle, expect) in cases {
            let got =
                enclosing_item(src, at(src, needle)).unwrap_or_else(|e| panic!("{e} for {src}"));
            assert_eq!(got.as_str(), expect, "{src}");
        }

        let twins = "impl A {\n    fn new() { let ANCHOR_A = 1; }\n}\nimpl B {\n    fn new() { let ANCHOR_B = 1; }\n}\n";
        assert_eq!(enclosing_item(twins, at(twins, "ANCHOR_A")).unwrap().as_str(), "A::new");
        assert_eq!(enclosing_item(twins, at(twins, "ANCHOR_B")).unwrap().as_str(), "B::new");
    }

    #[test]
    fn resolver_ignores_braces_in_strings_chars_and_comments() {
        let src = concat!(
            "fn outer() {\n",
            "    let _ = r#\"{\"#;\n",
            "    let _ = br##\"}\"##;\n",
            "    let _ = \"\\\"{\";\n",
            "    let _ = \"\\\\\";\n",
            "    let _ = '{';\n",
            "    let _ = 'a;\n",
            "    /* /* } */ { */\n",
            "    /// docs { braces }\n",
            "    let ANCHOR = 1;\n",
            "}\n",
            "fn decoy() { let ANCHOR_DECOY = 1; }\n",
        );
        assert_eq!(enclosing_item(src, at(src, "let ANCHOR")).unwrap().as_str(), "outer");
        assert_eq!(enclosing_item(src, at(src, "ANCHOR_DECOY")).unwrap().as_str(), "decoy");
    }

    #[test]
    fn duplicate_qualified_items_are_ambiguous() {
        let src = "#[cfg(test)]\nfn f() { let ANCHOR = 1; }\n#[cfg(not(test))]\nfn f() { let OTHER = 2; }\n";
        let err = enclosing_item(src, at(src, "ANCHOR")).unwrap_err();
        match err {
            ResolveError::Ambiguous { qualified, lines } => {
                assert_eq!(qualified, "f");
                assert_eq!(lines, vec![2, 4], "{lines:?}");
            }
            other => panic!("expected Ambiguous, got {other}"),
        }
        let msg = enclosing_item(src, at(src, "OTHER")).unwrap_err().to_string();
        assert!(msg.contains("ambiguous qualified item `f`"), "{msg}");
        assert!(msg.contains("line 2") && msg.contains("line 4"), "{msg}");
    }

    #[test]
    fn const_expr_angles_do_not_swallow_the_next_fn() {
        let cases = [
            (
                "struct Foo<T>(std::marker::PhantomData<T>);\nimpl Foo<[u8; 1 << 2]> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Foo<[u8; 1<<2]>::method",
            ),
            (
                "struct Foo<const N: bool>;\nimpl Foo<{ 1 < 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Foo<{ 1<2 }>::method",
            ),
            (
                "struct Foo<const N: bool>;\nimpl Foo<{ 1 >= 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Foo<{ 1>= 2 }>::method",
            ),
            (
                "trait Keep<const N: usize = { 1 << 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Keep::method",
            ),
            (
                "trait Keep<const N: bool = { 1 < 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Keep::method",
            ),
            (
                "trait Keep<const N: bool = { 1 >= 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Keep::method",
            ),
            (
                "trait T<const C: char = 'x'> {\n    fn m() { let ANCHOR = 1; }\n}\nconst OK: bool = 2 > 1;\nfn later() { let NEXT = 1; }\n",
                "T::m",
            ),
        ];
        for (src, expect) in cases {
            let anchor =
                enclosing_item(src, at(src, "ANCHOR")).unwrap_or_else(|e| panic!("{e} in {src}"));
            let later =
                enclosing_item(src, at(src, "NEXT")).unwrap_or_else(|e| panic!("{e} in {src}"));
            assert_eq!(anchor.as_str(), expect, "{src}");
            assert_eq!(later.as_str(), "later", "{src}");
        }
    }

    #[test]
    fn const_generic_defaults_keep_the_method() {
        let heads = [
            "trait T<#[allow(x)] const C: char = 'x'>",
            "trait T<#[allow(x)] const C: u8 = b'>'>",
            "trait T<#[allow(reason = \"<>,\")] const C: u8 = 1>",
            "trait T<T, #[a] const C: u8 = b'<'>",
            "trait T<A, #[a] const C: u8 = b'>'>",
            "type Same<T> = T;\ntrait T<const C: Same<char> = 'a'>",
            "trait T<const C: char = '>'>",
            "trait T<\x0Cconst C: char = 'x'>",
            "trait T<A,\x0Cconst C: char = 'x'>",
            "trait T<# [cfg(all())] const C: char = 'x'>",
            "trait T<#\n[cfg(all())] const C: char = 'x'>",
            "trait T<# /* c */ [cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
            "trait T<#/*c*/[cfg(all())] const C: char = 'x'>",
            "trait T<U, const C: char = 'x'>",
            "trait T<'a, const P1: u8, P2 = fn(char)->char, const P3: bool = { 2 > 1 }>",
            "trait T<const P: bool = true, Q = Vec<u8>, const R: bool = { 2 > 1 }>",
            "#[cfg(any())] trait T<A, const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
            "trait T<#[cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
            "trait T<A, #[cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
            "trait T<#[cfg(any())] const B: dyn Iterator<Item = [u8; 1]>, const C: char = 'x'>",
            "trait T<#[cfg(any())] const B: u8 = b'>', const C: bool = { 2 > 1 }>",
            "trait T<#[a] # [b] const C: char = 'x'>",
            "type Char<const N: usize> = char;\ntype Byte<const N: usize> = u8;\ntrait T<const C: Char<0> = 'a', const D: Byte<0> = 1>",
            "trait T<const A: bool = { 2 > 1 }, const B: usize = { 3 }>",
        ];
        let body = " { fn m() { let HIT = 1; } }";
        let with = "\nconst OK: bool = 2 > 1;\nfn later() { let NEXT = 1; }\n";
        for head in heads {
            for tail in [with, ""] {
                let src = format!("{head}{body}{tail}");
                let hit = enclosing_item(&src, at(&src, "HIT")).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(hit.as_str(), "T::m", "{src}");
                if tail.is_empty() {
                    continue;
                }
                let close = enclosing_item(&src, at(&src, "const OK")).unwrap();
                assert_eq!(close.as_str(), "<module>", "{src}");
                assert_eq!(enclosing_item(&src, at(&src, "NEXT")).unwrap().as_str(), "later");
            }
        }
    }

    #[test]
    fn nested_header_delimiters_do_not_misattribute() {
        let cases = [
            (
                "fn first(_: [u8; 1 << 2]) {}\nfn second(_: [u8; 4 >> 1]) { let ANCHOR = 1; }\n",
                "second",
            ),
            (
                "fn first(_: [u8; (1 < 2) as usize]) {}\nfn second(_: [u8; 4 >> 1]) { let ANCHOR = 1; }\n",
                "second",
            ),
            ("fn f(x: [u8; 1 << 2]) { let ANCHOR = 1; }\n", "f"),
            (
                "struct Foo<const N: bool>;\nimpl Foo<{ 1 < 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nconst X: bool = 2 > 1;\n",
                "Foo<{ 1<2 }>::method",
            ),
            (
                "struct F<const N: bool>;\nfn f() -> F<{ 1 < 2 }> { let ANCHOR = 1; F }\nfn later() { let NEXT = 1; }\n",
                "f",
            ),
            (
                "trait Trait<const N: bool> {}\nstruct Foo<T>(std::marker::PhantomData<T>);\nimpl<T: Trait<{ 2 > 1 }>> Foo<T> {\n    fn method() { let ANCHOR = 1; }\n}\n",
                "Foo<T>::method",
            ),
            (
                "struct Foo<const N: bool>;\nimpl Foo<{ 1 <= 2 }> {\n    fn method() { let ANCHOR = 1; }\n}\nfn later() { let NEXT = 1; }\n",
                "Foo<{ 1<= 2 }>::method",
            ),
        ];
        for (src, expect) in cases {
            let got =
                enclosing_item(src, at(src, "ANCHOR")).unwrap_or_else(|e| panic!("{e} in {src}"));
            assert_eq!(got.as_str(), expect, "{src}");
            if src.contains("fn later") {
                let later = enclosing_item(src, at(src, "NEXT")).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(later.as_str(), "later", "{src}");
            }
            if src.contains("const X") {
                let hit = enclosing_item(src, at(src, "const X")).unwrap_or_else(|e| panic!("{e}"));
                assert_eq!(hit.as_str(), "<module>", "{src}");
            }
        }
    }

    #[test]
    fn pointer_and_assoc_type_headers_keep_the_fn() {
        let cases = [
            (
                concat!(
                    "struct Foo<T, const N: usize>(T);\n",
                    "fn f<T>() -> *const u8\n",
                    "where\n",
                    "    T: Iterator<Item = Foo<Vec<u8>, { 1 }>>,\n",
                    "{\n",
                    "    let HIT = 1;\n",
                    "    std::ptr::null()\n",
                    "}\n",
                ),
                "let HIT",
                "f",
            ),
            (
                concat!(
                    "struct Foo<T, const N: usize>(T);\n",
                    "trait Tr {\n",
                    "    fn m();\n",
                    "}\n",
                    "impl<T> Tr for *const T\n",
                    "where\n",
                    "    T: Iterator<Item = Foo<Vec<u8>, { 1 }>>,\n",
                    "{\n",
                    "    fn m() {}\n",
                    "}\n",
                    "fn later() {\n",
                    "    let HIT = 1;\n",
                    "}\n",
                ),
                "let HIT",
                "later",
            ),
            (
                concat!(
                    "struct Foo<T, const N: usize>(T);\n",
                    "fn g<T>(x: T) -> *const T\n",
                    "where\n",
                    "    T: IntoIterator<Item = Foo<Option<u8>, { 2 }>>,\n",
                    "{\n",
                    "    let HIT = 1;\n",
                    "    std::ptr::null()\n",
                    "}\n",
                ),
                "let HIT",
                "g",
            ),
            (
                concat!(
                    "struct Foo<T, const N: usize>(T);\n",
                    "fn f<T>()\n",
                    "where\n",
                    "    *const T: IntoIterator<Item = Foo<Vec<u8>, { 1 }>>,\n",
                    "{\n",
                    "    let HIT = 1;\n",
                    "}\n",
                ),
                "let HIT",
                "f",
            ),
            (
                concat!(
                    "struct Pair<T, const N: usize>(T);\n",
                    "fn f<T>() -> *const u8\n",
                    "where\n",
                    "    T: Iterator<Item = Pair<fn() -> u8, { 1 + 1 }>>,\n",
                    "{\n",
                    "    let anchor = 1;\n",
                    "    let _ = anchor;\n",
                    "    std::ptr::null()\n",
                    "}\n",
                ),
                "let anchor",
                "f",
            ),
            (
                concat!(
                    "trait Family { type Item<T>; }\n",
                    "fn f<T: Family<Item<u8>=u8>>() {}\n",
                    "const CLOSE: bool = 2 > 1;\n",
                ),
                "() {}",
                "f",
            ),
            (
                "fn before() {\n    let HIT = 1;\n}\nconst C: char = '>';\nfn later() {\n    let NEXT = 1;\n}\n",
                "let HIT",
                "before",
            ),
            (
                concat!(
                    "struct Foo<F>(std::marker::PhantomData<F>);\n",
                    "impl<F: Fn() -> *const u8 + Iterator<Item = Vec<u8>>> Foo<F> {\n",
                    "    fn m() { let HIT = 1; }\n",
                    "}\n",
                ),
                "let HIT",
                "Foo<F>::m",
            ),
            (
                concat!(
                    "trait Tr<T: Into<u8>= u8> {\n",
                    "    fn m() { let HIT = 1; }\n",
                    "}\n",
                    "static OK: bool = 2 > 1;\n",
                ),
                "let HIT",
                "Tr::m",
            ),
        ];
        for (src, needle, expect) in cases {
            let got =
                enclosing_item(src, at(src, needle)).unwrap_or_else(|e| panic!("{e} in {src}"));
            assert_eq!(got.as_str(), expect, "{src}");
        }
        let impl_src = cases[1].0;
        assert_eq!(
            enclosing_item(impl_src, at(impl_src, "fn m() {}")).unwrap().as_str(),
            "<*const T as Tr>::m",
        );
        let family = cases[5].0;
        assert_eq!(enclosing_item(family, at(family, "const CLOSE")).unwrap().as_str(), "<module>");
        let ch = cases[6].0;
        assert_eq!(enclosing_item(ch, at(ch, "let NEXT")).unwrap().as_str(), "later");
        assert_eq!(enclosing_item(ch, at(ch, "const C:")).unwrap().as_str(), "<module>");
        let f4 = cases[8].0;
        assert_eq!(enclosing_item(f4, at(f4, "static OK")).unwrap().as_str(), "<module>");
    }

    #[test]
    fn fn_and_impl_headers_fail_closed_at_eof() {
        let fn_err = SourceItems::parse("fn f() -> u8").unwrap_err();
        assert!(matches!(fn_err, ResolveError::Unclosed { .. }), "{fn_err}");
        let impl_err = SourceItems::parse("impl Foo").unwrap_err();
        assert!(matches!(impl_err, ResolveError::Unclosed { .. }), "{impl_err}");
    }

    #[test]
    fn offset_past_end_is_rejected() {
        let src = "fn f() { let ANCHOR = 1; }\n";
        let end = enclosing_item(src, src.len()).unwrap_err();
        assert!(
            matches!(end, ResolveError::OffsetOutOfRange { offset, len } if offset == len && len == src.len()),
            "{end}"
        );
        let past = enclosing_item(src, src.len() + 1).unwrap_err();
        assert!(matches!(past, ResolveError::OffsetOutOfRange { .. }), "{past}");
    }

    #[test]
    fn unclosed_and_unbalanced_braces_fail_closed() {
        let open = SourceItems::parse("fn f() { let ANCHOR = 1;").unwrap_err();
        assert!(matches!(open, ResolveError::Unclosed { .. }), "{open}");
        let extra = SourceItems::parse("fn f() { let ANCHOR = 1; }\n}").unwrap_err();
        assert!(matches!(extra, ResolveError::Unbalanced), "{extra}");
    }

    #[test]
    fn angle_scan_cap_accepts_100_000_and_rejects_100_001() {
        let ok = impl_with_angle_span(100_000);
        assert_eq!(enclosing_item(&ok, at(&ok, "ANCHOR")).unwrap().as_str(), "Foo<T>::method");
        let over = impl_with_angle_span(100_001);
        let err = SourceItems::parse(&over).unwrap_err();
        assert!(matches!(err, ResolveError::AngleScanTooLong { limit: 100_000 }), "{err}");
        assert!(!err.to_string().contains("256"), "{err}");
        let short = SourceItems::parse("impl<T").unwrap_err();
        assert!(matches!(short, ResolveError::Unclosed { .. }), "{short}");
    }

    #[test]
    fn non_ascii_names_and_char_literals_fail_closed() {
        let raw = "fn r#é() { let ANCHOR = 1; }\n";
        let err = enclosing_item(raw, at(raw, "ANCHOR")).unwrap_err();
        assert!(matches!(err, ResolveError::NonAscii), "{err}");
        let name = "fn é() { let ANCHOR = 1; }\n";
        let err = enclosing_item(name, at(name, "ANCHOR")).unwrap_err();
        assert!(matches!(err, ResolveError::NonAscii), "{err}");
        let ch = "fn f() { let _ = ('é','}'); let ANCHOR = 1; }\n";
        let err = enclosing_item(ch, at(ch, "ANCHOR")).unwrap_err();
        assert!(matches!(err, ResolveError::NonAscii), "{err}");
        for src in [
            "fn f(é: u8) { let ANCHOR = 1; }\n",
            "impl é { fn m() { let ANCHOR = 1; } }\n",
            "struct Foo<T>(T);\nimpl<é> Foo<T> { fn m() { let ANCHOR = 1; } }\n",
        ] {
            let err = enclosing_item(src, at(src, "ANCHOR")).unwrap_err();
            assert!(matches!(err, ResolveError::NonAscii), "{src} -> {err}");
        }
        let leak = "macro_rules! a {()=>{('é','{')};}\nfn f(){let HAZ = 1;}\nmacro_rules! b {()=>{('é','}')};}\n";
        let err = enclosing_item(leak, at(leak, "HAZ")).unwrap_err();
        assert!(matches!(err, ResolveError::NonAscii), "{err}");
        assert_ne!(err.to_string(), "macro_rules!a");
        for src in [
            "#[doc = 'é']\nfn f() { let ANCHOR = 1; }\n",
            "#[cfg(é)]\nfn f() { let ANCHOR = 1; }\n",
        ] {
            let err = enclosing_item(src, at(src, "ANCHOR")).unwrap_err();
            assert!(matches!(err, ResolveError::NonAscii), "{src} -> {err}");
        }
        let kept = "#[doc = \"é\"]\nfn f() { let ANCHOR = 1; }\n";
        assert_eq!(enclosing_item(kept, at(kept, "ANCHOR")).unwrap().as_str(), "f");
    }

    #[test]
    fn vertical_tab_keeps_the_owner() {
        let cases = [
            ("fn\x0Bf() { let ANCHOR = 1; }\n", "ANCHOR", "f"),
            ("mod\x0Btests { fn f() { let ANCHOR = 1; } }\n", "ANCHOR", "tests::f"),
            (
                "struct Foo<T>(std::marker::PhantomData<T>);\nimpl\x0B<T> Foo<T> { fn m() { let ANCHOR = 1; } }\n",
                "ANCHOR",
                "Foo<T>::m",
            ),
            ("trait\x0BT { fn m() { let ANCHOR = 1; } }\n", "ANCHOR", "T::m"),
            ("macro_rules!\x0Bm { () => { let ANCHOR = 1; }; }\n", "ANCHOR", "macro_rules!m"),
            ("macro_rules! m { () =>\x0B{ let ANCHOR = 1; }; }\n", "ANCHOR", "macro_rules!m"),
            (
                "fn reject_gloas_version_pre_gloas() {\n    let slot_fork = 1;\n    if\x0Bslot_fork >= 1 { let ANCHOR = 1; }\n}\n",
                "ANCHOR",
                "reject_gloas_version_pre_gloas",
            ),
        ];
        for (src, needle, expect) in cases {
            let got =
                enclosing_item(src, at(src, needle)).unwrap_or_else(|e| panic!("{e} in {src:?}"));
            assert_eq!(got.as_str(), expect, "{src:?}");
            assert_ne!(got.as_str(), "<module>", "{src:?}");
            rustc_lib(src).unwrap_or_else(|e| panic!("rustc rejected\n{src:?}\n{e}"));
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../block-service/src/service/mod.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fn_at = src.find("fn reject_gloas_version_pre_gloas").expect("fn");
        // Split so this test file is not itself a `>= ForkName::` hazard hit.
        let needle = format!("if slot_fork {} {}", ">=", "ForkName::Gloas");
        let rel = src[fn_at..].find(&needle).expect("slot_fork line");
        let space = fn_at + rel + 2;
        assert_eq!(src.as_bytes()[space], b' ', "space between if and slot_fork");
        let mut edited = src.into_bytes();
        edited[space] = 0x0B;
        let edited = String::from_utf8(edited).unwrap();
        let item = enclosing_item(&edited, space + 1).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(item.as_str(), "reject_gloas_version_pre_gloas");
        assert_ne!(item.as_str(), "<module>");
    }

    #[test]
    fn keyword_form_feed_keeps_the_name() {
        let cases = [
            ("fn\x0Cf() { let ANCHOR = 1; }\n", "ANCHOR", "f"),
            ("mod\x0Ctests { fn f() { let ANCHOR = 1; } }\n", "ANCHOR", "tests::f"),
            (
                "struct Foo<T>(std::marker::PhantomData<T>);\nimpl\x0C<T> Foo<T> { fn m() { let ANCHOR = 1; } }\n",
                "ANCHOR",
                "Foo<T>::m",
            ),
        ];
        for (src, needle, expect) in cases {
            let got =
                enclosing_item(src, at(src, needle)).unwrap_or_else(|e| panic!("{e} in {src}"));
            assert_eq!(got.as_str(), expect, "{src}");
        }
    }

    fn rustc_lib(src: &str) -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("rvc-hdr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rs = dir.join("case.rs");
        std::fs::write(&rs, src).unwrap();
        let out = std::process::Command::new("rustc")
            .args(["--edition", "2021", "--crate-type", "lib", "--error-format", "short"])
            .arg(&rs)
            .arg("-o")
            .arg(dir.join("case.rlib"))
            .output()
            .expect("spawn rustc");
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }

    /// Headers this resolver claims, checked against `rustc --edition 2021`.
    /// `compile` is whether rustc must accept the program. The resolver result
    /// is checked either way. `#[a]` is a token shape rustc rejects.
    #[test]
    fn rustc_differential_on_claimed_headers() {
        let cases: &[(&str, &str, &str, bool)] = &[
            ("fn\x0Cf() { let ANCHOR = 1; }\n", "ANCHOR", "f", true),
            ("mod\x0Ctests { fn f() { let ANCHOR = 1; } }\n", "ANCHOR", "tests::f", true),
            (
                "struct Foo<T>(std::marker::PhantomData<T>);\nimpl\x0C<T> Foo<T> { fn m() { let ANCHOR = 1; } }\n",
                "ANCHOR",
                "Foo<T>::m",
                true,
            ),
            (
                "trait T<'a, const P1: u8, P2 = fn(char)->char, const P3: bool = { 2 > 1 }> { fn m() { let HIT = 1; } }\nconst OK: bool = 2 > 1;\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<const P: bool = true, Q = Vec<u8>, const R: bool = { 2 > 1 }> { fn m() { let HIT = 1; } }\nconst OK: bool = 2 > 1;\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "#[cfg(any())] trait T<A, const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<#[cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<A, #[cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<#[cfg(any())] const B: dyn Iterator<Item = [u8; 1]>, const C: char = 'x'> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<#[cfg(any())] const B: u8 = b'>', const C: bool = { 2 > 1 }> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            (
                "trait T<#[a] # [b] const C: char = 'x'> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                false,
            ),
            (
                "type Char<const N: usize> = char;\ntype Byte<const N: usize> = u8;\ntrait T<const C: Char<0> = 'a', const D: Byte<0> = 1> { fn m() { let HIT = 1; } }\n",
                "HIT",
                "T::m",
                true,
            ),
            ("#[doc = \"é\"]\nfn f() { let ANCHOR = 1; }\n", "ANCHOR", "f", true),
        ];
        for (src, needle, expect, compile) in cases {
            let got =
                enclosing_item(src, at(src, needle)).unwrap_or_else(|e| panic!("{e} in {src}"));
            assert_eq!(got.as_str(), *expect, "{src}");
            let rustc = rustc_lib(src);
            let detail = rustc.as_ref().err().map(String::as_str).unwrap_or("");
            assert_eq!(rustc.is_ok(), *compile, "{src}\n{detail}");
        }
        // rustc accepts these. The resolver fails closed instead of guessing
        // `r`, `<module>`, or a function that swallowed the char literal.
        for src in [
            "fn r#é() { let ANCHOR = 1; }\n",
            "fn é() { let ANCHOR = 1; }\n",
            "fn f() { let _ = ('é','}'); let ANCHOR = 1; }\n",
            "macro_rules! a {()=>{('é','{')};}\nfn f(){let HAZ = 1;}\nmacro_rules! b {()=>{('é','}')};}\n",
            "#[doc = 'é']\nfn f() { let ANCHOR = 1; }\n",
            "#[cfg(é)]\nfn f() { let ANCHOR = 1; }\n",
        ] {
            let needle = if src.contains("HAZ") { "HAZ" } else { "ANCHOR" };
            assert!(enclosing_item(src, at(src, needle)).is_err(), "{src}");
            rustc_lib(src).unwrap_or_else(|e| panic!("rustc rejected\n{src}\n{e}"));
        }
    }

    /// Seeded grammar of trait heads. Every program must compile and keep `m`.
    #[test]
    fn seeded_trait_grammar_matches_rustc() {
        let choices = [
            "const P{i}: u8 = 1",
            "const P{i}: bool = true",
            "const P{i}: bool = { 2 > 1 }",
            "const P{i}: char = 'x'",
            "const P{i}: char = '>'",
            "P{i} = Vec<u8>",
            "P{i} = fn(char)->char",
            "#[cfg(any())] const P{i}: u8 = b'>'",
            "#[cfg(any())] const P{i}: dyn Iterator<Item = Vec<u8>>",
        ];
        let pasted = [
            "#[cfg(any())] trait T<A, const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
            "trait T<A, #[cfg(any())] const B: dyn Iterator<Item = Vec<u8>>, const C: usize = { 1 }>",
        ];
        for head in pasted {
            let src = format!(
                "{head} {{ fn m() {{ let HIT = 1; }} }}\nconst OK: bool = 2 > 1;\nfn later() {{ let NEXT = 1; }}\n"
            );
            let hit =
                enclosing_item(&src, at(&src, "HIT")).unwrap_or_else(|e| panic!("{e}\n{src}"));
            assert_eq!(hit.as_str(), "T::m", "{src}");
            assert_eq!(enclosing_item(&src, at(&src, "const OK")).unwrap().as_str(), "<module>");
            assert_eq!(enclosing_item(&src, at(&src, "NEXT")).unwrap().as_str(), "later");
            rustc_lib(&src).unwrap_or_else(|e| panic!("rustc rejected\n{src}\n{e}"));
        }
        let mut state = 0x714u64;
        for _ in 0..24 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let count = 1 + (state % 3) as usize;
            let mut params = Vec::new();
            for i in 0..count {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                params
                    .push(choices[(state as usize) % choices.len()].replace("{i}", &i.to_string()));
            }
            let src = format!(
                "trait T<\x0B{}> {{ fn m() {{ let HIT = 1; }} }}\nconst OK: bool = 2 > 1;\nfn later() {{ let NEXT = 1; }}\n",
                params.join(", ")
            );
            let hit =
                enclosing_item(&src, at(&src, "HIT")).unwrap_or_else(|e| panic!("{e}\n{src}"));
            assert_eq!(hit.as_str(), "T::m", "{src}");
            assert_eq!(
                enclosing_item(&src, at(&src, "const OK")).unwrap().as_str(),
                "<module>",
                "{src}"
            );
            assert_eq!(enclosing_item(&src, at(&src, "NEXT")).unwrap().as_str(), "later", "{src}");
            rustc_lib(&src).unwrap_or_else(|e| panic!("rustc rejected\n{src}\n{e}"));
        }
    }

    #[test]
    fn raw_ident_item_names_fail_closed() {
        for src in [
            "fn outer() { fn r#as() { let ANCHOR = 1; } }\n",
            "fn r#impl() { let ANCHOR = 1; }\n",
            "struct r#for;\nimpl r#for { fn method() { let ANCHOR = 1; } }\n",
        ] {
            let err = enclosing_item(src, at(src, "ANCHOR")).unwrap_err();
            assert!(matches!(err, ResolveError::RawIdent), "{src} -> {err}");
        }
    }

    fn impl_with_angle_span(span: usize) -> String {
        let src = format!(
            "struct Foo<T>(std::marker::PhantomData<T>);\nimpl<T{}> Foo<T> {{\n    fn method() {{ let ANCHOR = 1; }}\n}}\n",
            " ".repeat(span - 3)
        );
        let angle = src.find("impl<").expect("impl header") + 4;
        assert_eq!(src[angle..].find('>').unwrap() + 1, span);
        src
    }

    #[test]
    fn raw_string_hash_count_masks_the_brace() {
        let src = "fn outer() { let _ = r##\" \"# } \"##; let ANCHOR = 1; }\nfn decoy() { let ANCHOR_DECOY = 1; }\n";
        assert_eq!(enclosing_item(src, at(src, "let ANCHOR")).unwrap().as_str(), "outer");
        assert_eq!(enclosing_item(src, at(src, "ANCHOR_DECOY")).unwrap().as_str(), "decoy");
    }

    #[test]
    fn unterminated_string_comment_and_attribute_fail_closed() {
        for src in [
            "fn f() { let ANCHOR = 1; }\n\"open",
            "fn f() { let ANCHOR = 1; }\n/* open",
            "#[open\nfn f() { let ANCHOR = 1; }\n",
            "fn f() { let ANCHOR = 1; }\nr#\"open",
        ] {
            let err = enclosing_item(src, at(src, "ANCHOR")).unwrap_err();
            assert!(matches!(err, ResolveError::Unterminated), "{src} -> {err}");
        }
    }

    #[test]
    fn char_literal_brace_is_not_a_delimiter() {
        let src =
            "fn outer() { let _ = '{'; let ANCHOR = 1; }\nfn decoy() { let ANCHOR_DECOY = 1; }\n";
        assert_eq!(enclosing_item(src, at(src, "let ANCHOR")).unwrap().as_str(), "outer");
        assert_eq!(enclosing_item(src, at(src, "ANCHOR_DECOY")).unwrap().as_str(), "decoy");
    }

    #[test]
    fn nesting_cap_accepts_256_and_rejects_257() {
        let ok = nested_fn(256);
        assert_eq!(enclosing_item(&ok, at(&ok, "ANCHOR")).unwrap().as_str(), "f");
        let too_deep = nested_fn(257);
        let err = enclosing_item(&too_deep, 0).unwrap_err();
        assert!(matches!(err, ResolveError::NestingTooDeep { limit: 256 }), "{err}");
    }

    #[test]
    fn item_cap_accepts_20_000_and_rejects_20_001() {
        let ok = repeated_fns(20_000);
        assert!(SourceItems::parse(&ok).is_ok());
        let too_many = repeated_fns(20_001);
        let err = SourceItems::parse(&too_many).unwrap_err();
        assert!(matches!(err, ResolveError::TooManyItems { limit: 20_000 }), "{err}");
    }

    fn nested_fn(depth: usize) -> String {
        let mut src = String::from("fn f() ");
        src.extend(std::iter::repeat_n('{', depth));
        src.push_str("let ANCHOR = 1;");
        src.extend(std::iter::repeat_n('}', depth));
        src
    }

    fn repeated_fns(n: usize) -> String {
        "fn f(){}\n".repeat(n)
    }
}
