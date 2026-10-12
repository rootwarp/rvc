//! Bounded SSE framer.
//!
//! `reqwest-eventsource` 0.6.0 pulls `eventsource-stream` 0.2.3, which is still
//! the latest crates.io release. That parser grows its line buffer and `data`
//! field without a cap, and it strips a leading U+FEFF with `&str[1..]`. The
//! BOM is three UTF-8 bytes, so the index panics. This framer replaces it.
//!
//! The pending line and the `data`, `event`, and `id` fields each stop at
//! `max_event_bytes`. Bytes past the cap are not copied in. A leading BOM is
//! removed by matching the three-byte prefix, including when those bytes arrive
//! in separate chunks.
//!
//! Completed messages are yielded to a callback as they are parsed. The framer
//! keeps the last `id` for stream state but does not copy it onto each message,
//! so a hostile max-length `id` cannot amplify memory with the frame count.
//!
//! Pending line bytes are checked for UTF-8 as they arrive. A definite invalid
//! sequence closes the stream immediately; an incomplete trailing character may
//! wait for the next chunk. Waiting for a newline is not required.

use thiserror::Error;

/// One SSE message, dispatched on a blank line.
///
/// The stream `id` is retained only on the framer. Callers that only need
/// `event` and `data` must not pay `O(frames × id)` for a cloned copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SseMessage {
    pub event: String,
    pub data: String,
}

/// Recoverable framing failure. Callers close the connection.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum FrameError {
    /// A line or field would grow past [`SseFramer::max_event_bytes`].
    #[error("SSE {field} field exceeded {cap} byte cap")]
    Oversize { cap: usize, field: &'static str },
    /// The stream contained a definite invalid UTF-8 sequence.
    #[error("SSE stream is not valid UTF-8")]
    InvalidUtf8,
}

/// Incremental SSE parser with a hard cap on every buffer it owns.
pub(super) struct SseFramer {
    max_event_bytes: usize,
    /// Incomplete line, or a 1–2 byte BOM prefix before the stream has started.
    pending: Vec<u8>,
    /// `true` until the optional leading BOM has been decided.
    at_start: bool,
    /// A `\r` was the last byte seen and the following byte is not yet known.
    held_cr: bool,
    event: String,
    data: String,
    id: String,
    saw_data: bool,
}

impl SseFramer {
    pub(super) fn new(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            pending: Vec::new(),
            at_start: true,
            held_cr: false,
            event: String::new(),
            data: String::new(),
            id: String::new(),
            saw_data: false,
        }
    }

    /// Feed the next body chunk, invoking `on_message` for each completed message.
    ///
    /// Messages are not retained by the framer. Peak memory beyond the caller's
    /// handling of one message is the framer's own `O(max_event_bytes)` buffers.
    ///
    /// On [`FrameError::Oversize`] every buffer this framer owns is still at
    /// most `max_event_bytes`. The rest of `chunk` is not retained.
    ///
    /// Returns `Ok(false)` if `on_message` returned `false` (caller asked to
    /// stop). Remaining bytes in `chunk` are not consumed in that case.
    pub(super) fn push(
        &mut self,
        mut chunk: &[u8],
        mut on_message: impl FnMut(SseMessage) -> bool,
    ) -> Result<bool, FrameError> {
        if self.at_start {
            self.consume_bom(&mut chunk);
            if self.at_start {
                return Ok(true);
            }
        }
        self.feed(chunk, &mut on_message)
    }

    /// Flush a line that ended with a lone `\r` when the stream ends.
    ///
    /// Without this, a completed line whose terminator was a trailing `\r` at
    /// the end of the last chunk stays in `pending` and is lost at EOF.
    pub(super) fn finish(
        &mut self,
        mut on_message: impl FnMut(SseMessage) -> bool,
    ) -> Result<bool, FrameError> {
        if !self.held_cr {
            return Ok(true);
        }
        self.held_cr = false;
        let line_bytes = std::mem::take(&mut self.pending);
        let line = String::from_utf8(line_bytes).map_err(|_| FrameError::InvalidUtf8)?;
        self.apply_line(&line, &mut on_message)
    }

    fn consume_bom(&mut self, input: &mut &[u8]) {
        const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
        let mut prefix = [0u8; 3];
        let from_pending = self.pending.len().min(BOM.len());
        prefix[..from_pending].copy_from_slice(&self.pending[..from_pending]);
        let need = BOM.len() - from_pending;
        let from_input = need.min(input.len());
        prefix[from_pending..from_pending + from_input].copy_from_slice(&input[..from_input]);
        let have = from_pending + from_input;
        if have == 0 {
            return;
        }
        if prefix[..have] == BOM[..have] {
            if have < BOM.len() {
                self.pending.clear();
                self.pending.extend_from_slice(&prefix[..have]);
                *input = &input[from_input..];
                return;
            }
            self.pending.clear();
            *input = &input[from_input..];
            self.at_start = false;
            return;
        }
        self.at_start = false;
    }

    fn feed(
        &mut self,
        mut input: &[u8],
        on_message: &mut dyn FnMut(SseMessage) -> bool,
    ) -> Result<bool, FrameError> {
        loop {
            match self.take_line(&mut input)? {
                Some(line_bytes) => {
                    let line =
                        String::from_utf8(line_bytes).map_err(|_| FrameError::InvalidUtf8)?;
                    if !self.apply_line(&line, on_message)? {
                        return Ok(false);
                    }
                }
                None => return Ok(true),
            }
        }
    }

    /// Take one line, not including its end-of-line marker.
    ///
    /// `None` means more bytes are required. The line content stored in
    /// `pending` never exceeds the cap. Bytes appended to `pending` are
    /// UTF-8-checked immediately so an invalid byte closes before a newline.
    fn take_line(&mut self, input: &mut &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        if self.held_cr {
            if input.is_empty() {
                return Ok(None);
            }
            self.held_cr = false;
            if input[0] == b'\n' {
                *input = &input[1..];
            }
            return Ok(Some(std::mem::take(&mut self.pending)));
        }

        if let Some(rel) = find_eol(input) {
            let line_len = self.pending.len() + rel;
            if line_len > self.max_event_bytes {
                let room = self.max_event_bytes.saturating_sub(self.pending.len());
                self.pending.extend_from_slice(&input[..room]);
                self.check_pending_utf8()?;
                return Err(self.oversize("line"));
            }
            let mut line = std::mem::take(&mut self.pending);
            line.extend_from_slice(&input[..rel]);
            let delim = input[rel];
            if delim == b'\n' {
                *input = &input[rel + 1..];
                return Ok(Some(line));
            }
            // `\r` may still be followed by `\n`.
            if rel + 1 < input.len() {
                let extra = usize::from(input[rel + 1] == b'\n');
                *input = &input[rel + 1 + extra..];
                return Ok(Some(line));
            }
            // Hold the line until the next byte decides `\r` vs `\r\n`, but
            // still reject definite invalid UTF-8 now — the peer may go idle.
            utf8_ok_or_incomplete(&line)?;
            self.pending = line;
            self.held_cr = true;
            *input = &[];
            return Ok(None);
        }

        let room = self.max_event_bytes.saturating_sub(self.pending.len());
        if input.len() > room {
            self.pending.extend_from_slice(&input[..room]);
            self.check_pending_utf8()?;
            return Err(self.oversize("line"));
        }
        self.pending.extend_from_slice(input);
        *input = &[];
        self.check_pending_utf8()?;
        Ok(None)
    }

    /// Reject definite invalid UTF-8 in `pending`; allow a truncated character.
    fn check_pending_utf8(&self) -> Result<(), FrameError> {
        utf8_ok_or_incomplete(&self.pending)
    }

    fn apply_line(
        &mut self,
        line: &str,
        on_message: &mut dyn FnMut(SseMessage) -> bool,
    ) -> Result<bool, FrameError> {
        if line.is_empty() {
            if let Some(message) = self.dispatch() {
                return Ok(on_message(message));
            }
            return Ok(true);
        }
        if line.starts_with(':') {
            return Ok(true);
        }
        let (name, value) = split_field(line);
        match name {
            "data" => {
                let sep = usize::from(self.saw_data);
                let new_len = self.data.len() + sep + value.len();
                if new_len > self.max_event_bytes {
                    return Err(self.oversize("data"));
                }
                if sep == 1 {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.saw_data = true;
            }
            "event" => {
                if value.len() > self.max_event_bytes {
                    return Err(self.oversize("event"));
                }
                self.event = value.to_string();
            }
            "id" => {
                // A NUL in the id is ignored (HTML event stream spec). The
                // previous id stays in place.
                if value.contains('\0') {
                    return Ok(true);
                }
                if value.len() > self.max_event_bytes {
                    return Err(self.oversize("id"));
                }
                self.id = value.to_string();
            }
            _ => {}
        }
        Ok(true)
    }

    fn dispatch(&mut self) -> Option<SseMessage> {
        if !self.saw_data {
            self.event.clear();
            return None;
        }
        self.saw_data = false;
        let data = std::mem::take(&mut self.data);
        let event_name = std::mem::take(&mut self.event);
        let event = if event_name.is_empty() { "message".to_string() } else { event_name };
        // Do not clone `self.id` onto the message: a max-length id would be
        // duplicated once per frame while nothing downstream reads it.
        Some(SseMessage { event, data })
    }

    fn oversize(&self, field: &'static str) -> FrameError {
        FrameError::Oversize { cap: self.max_event_bytes, field }
    }
}

fn find_eol(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|b| *b == b'\n' || *b == b'\r')
}

/// `Ok` when `bytes` is valid UTF-8, or only incomplete at the very end.
/// A definite invalid sequence is [`FrameError::InvalidUtf8`].
fn utf8_ok_or_incomplete(bytes: &[u8]) -> Result<(), FrameError> {
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok(()),
        Err(err) if err.error_len().is_none() => Ok(()),
        Err(_) => Err(FrameError::InvalidUtf8),
    }
}

/// HTML field syntax: one optional space after the colon is not part of the value.
fn split_field(line: &str) -> (&str, &str) {
    match line.split_once(':') {
        Some((name, rest)) => {
            let value = rest.strip_prefix(' ').unwrap_or(rest);
            (name, value)
        }
        None => (line, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_collect(framer: &mut SseFramer, chunk: &[u8]) -> Result<Vec<SseMessage>, FrameError> {
        let mut out = Vec::new();
        framer.push(chunk, |msg| {
            out.push(msg);
            true
        })?;
        Ok(out)
    }

    #[test]
    fn test_data_lines_join_with_a_newline() {
        let mut framer = SseFramer::new(1024);
        let msgs = push_collect(&mut framer, b"event: head\ndata: hello\ndata: world\n\n").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].event, "head");
        assert_eq!(msgs[0].data, "hello\nworld");
    }

    #[test]
    fn test_leading_bom_is_stripped_without_panic() {
        let mut framer = SseFramer::new(1024);
        let mut body = "\u{feff}".as_bytes().to_vec();
        body.extend(b"event: head\ndata: hi\n\n");
        let msgs = push_collect(&mut framer, &body).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].event, "head");
        assert_eq!(msgs[0].data, "hi");
    }

    #[test]
    fn test_leading_bom_split_across_chunks_is_stripped() {
        let mut framer = SseFramer::new(1024);
        assert!(push_collect(&mut framer, &[0xEF]).unwrap().is_empty());
        assert!(push_collect(&mut framer, &[0xBB]).unwrap().is_empty());
        let mut rest = vec![0xBF];
        rest.extend(b"event: head\ndata: hi\n\n");
        let msgs = push_collect(&mut framer, &rest).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, "hi");
        assert_eq!(msgs[0].event, "head");
    }

    #[test]
    fn test_multibyte_char_at_start_is_not_sliced() {
        // U+00E9 is the two bytes C3 A9. Indexing at byte 1 would panic.
        let mut framer = SseFramer::new(1024);
        let msgs = push_collect(&mut framer, &[0xC3, 0xA9, b'\n', b'\n']).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_crlf_and_split_cr_lf() {
        let mut framer = SseFramer::new(1024);
        let msgs = push_collect(&mut framer, b"event: head\r\ndata: hi\r\n\r\n").unwrap();
        assert_eq!(msgs[0].data, "hi");
        assert_eq!(msgs[0].event, "head");

        let mut framer = SseFramer::new(1024);
        assert!(push_collect(&mut framer, b"data: hi\r").unwrap().is_empty());
        let msgs = push_collect(&mut framer, b"\n\n").unwrap();
        assert_eq!(msgs[0].data, "hi");
    }

    #[test]
    fn test_comments_are_ignored_and_empty_data_dispatches() {
        let mut framer = SseFramer::new(1024);
        let msgs = push_collect(&mut framer, b": keep-alive\ndata\n\n").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, "");
        assert_eq!(msgs[0].event, "message");
    }

    #[test]
    fn test_id_is_replaced_and_nul_is_ignored() {
        let mut framer = SseFramer::new(64);
        let msgs =
            push_collect(&mut framer, b"id: abc\ndata: hi\n\nid: de\0f\ndata: yo\n\n").unwrap();
        assert_eq!(msgs.len(), 2);
        // Id stays on the framer only; messages do not carry a cloned copy.
        assert_eq!(framer.id, "abc");
        assert!(framer.id.len() <= 64);
    }

    #[test]
    fn test_long_id_plus_many_tiny_frames_stays_bounded() {
        let cap = 64 * 1024;
        let mut framer = SseFramer::new(cap);
        let mut body = Vec::with_capacity(cap + 16 + 6 * 8_000);
        // Line length is capped too, so the id value is cap - "id: ".len().
        body.extend_from_slice(b"id: ");
        body.extend(std::iter::repeat_n(b'x', cap - 4));
        body.extend_from_slice(b"\n");
        // ~6-byte frames: "data\n\n". One hyper-sized batch of them must not
        // allocate O(frames × id).
        let frames = 8_000;
        for _ in 0..frames {
            body.extend_from_slice(b"data\n\n");
        }

        let mut seen = 0usize;
        let mut peak_owned = 0usize;
        framer
            .push(&body, |msg| {
                seen += 1;
                // Only event + data are owned per message (no id clone).
                peak_owned = peak_owned.max(msg.event.len() + msg.data.len());
                true
            })
            .unwrap();

        assert_eq!(seen, frames);
        assert_eq!(framer.id.len(), cap - 4);
        // Default event name "message" (7) + empty data. Far below one id copy.
        assert!(peak_owned <= 16, "per-message owned bytes {peak_owned}");
        // Framer buffers remain O(cap), not O(frames × id).
        assert!(framer.pending.len() <= cap);
        assert!(framer.data.len() <= cap);
        assert!(framer.event.len() <= cap);
        assert!(framer.id.len() <= cap);
    }

    #[test]
    fn test_trailing_cr_at_eof_flushes_completed_line() {
        let mut framer = SseFramer::new(1024);
        // Blank line terminator is a lone `\r` at the chunk end; without
        // finish() the dispatched message would be lost at EOF.
        assert!(push_collect(&mut framer, b"data: hi\r\n\r").unwrap().is_empty());
        assert!(framer.held_cr);

        let mut msgs = Vec::new();
        framer
            .finish(|msg| {
                msgs.push(msg);
                true
            })
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, "hi");
        assert!(!framer.held_cr);
    }

    #[test]
    fn test_invalid_utf8_in_incomplete_line_is_rejected_immediately() {
        let mut framer = SseFramer::new(1024);
        // 0xFF is never valid UTF-8. No newline — lossy decoding would hide
        // this until EOL (or forever if the peer goes idle).
        let err = push_collect(&mut framer, b"data: hi\xff").unwrap_err();
        assert_eq!(err, FrameError::InvalidUtf8);
    }

    #[test]
    fn test_incomplete_utf8_prefix_waits_then_completes() {
        let mut framer = SseFramer::new(1024);
        // U+00E9 is C3 A9; a lone C3 must wait, not fail.
        assert!(push_collect(&mut framer, b"data: \xc3").unwrap().is_empty());
        let msgs = push_collect(&mut framer, b"\xa9\n\n").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data, "\u{e9}");
    }

    #[test]
    fn test_invalid_utf8_before_held_cr_is_rejected() {
        let mut framer = SseFramer::new(1024);
        let err = push_collect(&mut framer, b"data: hi\xff\r").unwrap_err();
        assert_eq!(err, FrameError::InvalidUtf8);
        assert!(!framer.held_cr);
    }

    #[test]
    fn test_incomplete_line_retains_at_most_the_cap() {
        let cap = 128;
        let mut framer = SseFramer::new(cap);
        let huge = vec![b'x'; cap * 50];
        let err = push_collect(&mut framer, &huge).unwrap_err();
        assert_eq!(err, FrameError::Oversize { cap, field: "line" });
        assert!(framer.pending.len() <= cap);
        assert!(framer.data.len() <= cap);
        assert!(framer.event.len() <= cap);
        assert!(framer.id.len() <= cap);
        // The rejected tail was not appended.
        assert_eq!(framer.pending.len(), cap);
    }

    #[test]
    fn test_multi_data_field_stops_at_the_cap() {
        let cap = 100;
        let mut framer = SseFramer::new(cap);
        let line = b"data: 0123456789\n";
        let mut pushes = 0;
        loop {
            pushes += 1;
            assert!(pushes < 100, "framer kept accepting data lines");
            match push_collect(&mut framer, line) {
                Ok(_) => assert!(framer.data.len() <= cap),
                Err(FrameError::Oversize { field: "data", cap: got }) => {
                    assert_eq!(got, cap);
                    assert!(framer.data.len() <= cap);
                    assert!(framer.data.len() + 10 > cap);
                    break;
                }
                Err(err) => panic!("unexpected {err}"),
            }
        }
    }

    #[test]
    fn test_event_and_id_fields_do_not_grow_past_the_cap() {
        let cap = 32;
        for prefix in [b"event: ".as_slice(), b"id: ".as_slice()] {
            let mut framer = SseFramer::new(cap);
            let mut line = prefix.to_vec();
            line.extend(std::iter::repeat_n(b'z', cap * 10));
            let err = push_collect(&mut framer, &line).unwrap_err();
            assert_eq!(err, FrameError::Oversize { cap, field: "line" });
            assert!(framer.pending.len() <= cap);
            assert!(framer.event.len() <= cap);
            assert!(framer.id.len() <= cap);
            assert_eq!(framer.event.len(), 0);
            assert_eq!(framer.id.len(), 0);
        }
    }

    #[test]
    fn test_oversize_line_does_not_dispatch_a_later_event_in_the_same_chunk() {
        let cap = 32;
        let mut framer = SseFramer::new(cap);
        let mut body = vec![b'x'; cap + 10];
        body.extend(b"\n\nevent: head\ndata: hi\n\n");
        let err = push_collect(&mut framer, &body).unwrap_err();
        assert!(matches!(err, FrameError::Oversize { field: "line", .. }));
        assert!(framer.pending.len() <= cap);
    }
}
