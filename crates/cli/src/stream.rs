//! Minimal, line-oriented live event output for the CLI.

use std::io::{self, Write};

use procmon_sdk::Event;

/// Formats one event as tab-separated fields:
/// `date-time.ms`, operation, pid, parent pid, executable, working directory,
/// command line.
/// Tabs make paths and command lines containing spaces unambiguous; control
/// characters inside captured strings are flattened so every event stays on one
/// physical stdout line.
pub(crate) fn format_event(ev: &Event) -> String {
    let timestamp = timestamp_millis(&ev.date_precise());
    let operation = sanitize_field(ev.operation_name());
    let executable = sanitize_field(ev.process_subject_image_path().as_deref().unwrap_or(""));
    let workdir = sanitize_field(ev.process_working_directory().as_deref().unwrap_or(""));
    let command_line = sanitize_field(ev.process_subject_command_line().as_deref().unwrap_or(""));

    format!(
        "{timestamp}\t{operation}\t{}\t{}\t{executable}\t{workdir}\t{command_line}",
        ev.process_subject_pid(),
        ev.process_subject_parent_pid().unwrap_or(0)
    )
}

/// Writes and immediately flushes one already-formatted event line. Explicit
/// flushing keeps redirected/piped stdout live as well as an interactive console.
pub(crate) fn write_line(out: &mut impl Write, line: &str) -> io::Result<()> {
    writeln!(out, "{line}")?;
    out.flush()
}

fn timestamp_millis(precise: &str) -> String {
    let mut out = precise.replace('/', "-");
    if let Some(dot) = out.rfind('.') {
        let keep = dot.saturating_add(4);
        if out.len() > keep {
            out.truncate(keep);
        }
    }
    out
}

fn sanitize_field(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '\t' | '\r' | '\n' => ' ',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_iso_like_and_millisecond_precision() {
        assert_eq!(
            timestamp_millis("2026/08/11 17:23:45.1234567"),
            "2026-08-11 17:23:45.123"
        );
        assert_eq!(timestamp_millis("12345"), "12345");
    }

    #[test]
    fn fields_cannot_break_the_line_protocol() {
        assert_eq!(sanitize_field("a\tb\r\nc"), "a b  c");
    }

    #[test]
    fn writes_and_terminates_one_line() {
        let mut out = Vec::new();
        write_line(&mut out, "one\ttwo").unwrap();
        assert_eq!(out, b"one\ttwo\n");
    }
}
