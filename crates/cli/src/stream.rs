//! Line-oriented live event output for the CLI.

use std::io::{self, Write};

use procmon_sdk::Event;
use serde_json::{Map, Value};

/// The stdout wire format. No `--fields` means a complete JSON object per line;
/// selecting fields switches to CSV and keeps the timestamp as column zero.
#[derive(Clone, Debug, Default)]
pub(crate) enum StreamFormat {
    #[default]
    JsonLines,
    Csv(Vec<Field>),
}

impl StreamFormat {
    pub(crate) fn from_names(names: &[String]) -> Result<Self, String> {
        if names.is_empty() {
            return Ok(Self::JsonLines);
        }

        let mut fields = vec![Field::Timestamp];
        for name in names {
            let field = Field::parse(name).ok_or_else(|| {
                format!(
                    "unknown stdout field {name:?}; valid fields: {}",
                    available_fields().join(", ")
                )
            })?;
            if !fields.contains(&field) {
                fields.push(field);
            }
        }
        Ok(Self::Csv(fields))
    }

    pub(crate) fn header(&self) -> Option<String> {
        match self {
            Self::JsonLines => None,
            Self::Csv(fields) => Some(csv_record(
                fields
                    .iter()
                    .map(|field| field.name().to_string())
                    .collect(),
            )),
        }
    }

    pub(crate) fn format_event(&self, ev: &Event) -> io::Result<String> {
        match self {
            Self::JsonLines => {
                let mut object = Map::new();
                for field in Field::DEFAULT_JSON {
                    object.insert(field.name().to_string(), field.value(ev));
                }

                let mut extensions = Map::new();
                for field in procmon_sdk::struct_fields() {
                    if let Some(value) = ev.struct_field(field.name) {
                        extensions
                            .insert(field.name.to_string(), Value::String(value.into_owned()));
                    }
                }
                if !extensions.is_empty() {
                    object.insert("extension_fields".to_string(), Value::Object(extensions));
                }

                serde_json::to_string(&object).map_err(io::Error::other)
            }
            Self::Csv(fields) => {
                let values: Vec<Value> = fields.iter().map(|field| field.value(ev)).collect();
                Ok(csv_record(values.into_iter().map(json_scalar).collect()))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    Timestamp,
    TimestampRaw100ns,
    Category,
    Operation,
    Pid,
    ParentPid,
    Tid,
    ProcessName,
    ImagePath,
    WorkingDirectory,
    CommandLine,
    Path,
    Result,
    CompletionTime,
    Duration,
    Duration100ns,
    Sequence,
    SessionId,
    Architecture,
    Virtualized,
    Integrity,
    AuthId,
    User,
    Company,
    Description,
    Version,
    Detail,
    Extension(String),
}

impl Field {
    const DEFAULT_JSON: &'static [Field] = &[
        Field::Timestamp,
        Field::TimestampRaw100ns,
        Field::Category,
        Field::Operation,
        Field::Pid,
        Field::ParentPid,
        Field::Tid,
        Field::ProcessName,
        Field::ImagePath,
        Field::WorkingDirectory,
        Field::CommandLine,
        Field::Path,
        Field::Result,
        Field::CompletionTime,
        Field::Duration,
        Field::Duration100ns,
        Field::Sequence,
        Field::SessionId,
        Field::Architecture,
        Field::Virtualized,
        Field::Integrity,
        Field::AuthId,
        Field::User,
        Field::Company,
        Field::Description,
        Field::Version,
        Field::Detail,
    ];

    fn parse(input: &str) -> Option<Self> {
        let normalized = normalize_name(input);
        let field = match normalized.as_str() {
            "timestamp" | "datetime" | "dateandtime" | "date" => Self::Timestamp,
            "timestampraw100ns" | "timeraw" | "rawtime" => Self::TimestampRaw100ns,
            "category" | "class" => Self::Category,
            "operation" | "event" | "eventname" => Self::Operation,
            "pid" | "processid" => Self::Pid,
            "parentpid" | "ppid" => Self::ParentPid,
            "tid" | "threadid" => Self::Tid,
            "processname" => Self::ProcessName,
            "imagepath" | "binarypath" | "binpath" | "executable" => Self::ImagePath,
            "workingdirectory" | "workdir" | "cwd" => Self::WorkingDirectory,
            "commandline" | "cmdline" => Self::CommandLine,
            "path" | "eventpath" => Self::Path,
            "result" => Self::Result,
            "completiontime" | "endtime" => Self::CompletionTime,
            "duration" => Self::Duration,
            "duration100ns" | "durationticks" => Self::Duration100ns,
            "sequence" | "seq" => Self::Sequence,
            "session" | "sessionid" => Self::SessionId,
            "architecture" | "arch" => Self::Architecture,
            "virtualized" => Self::Virtualized,
            "integrity" => Self::Integrity,
            "authid" => Self::AuthId,
            "user" => Self::User,
            "company" => Self::Company,
            "description" => Self::Description,
            "version" => Self::Version,
            "detail" => Self::Detail,
            _ => {
                let extension = procmon_sdk::struct_fields()
                    .into_iter()
                    .find(|field| normalize_name(field.name) == normalized)?;
                Self::Extension(extension.name.to_string())
            }
        };
        Some(field)
    }

    fn name(&self) -> &str {
        match self {
            Self::Timestamp => "timestamp",
            Self::TimestampRaw100ns => "timestamp_raw_100ns",
            Self::Category => "category",
            Self::Operation => "operation",
            Self::Pid => "pid",
            Self::ParentPid => "parent_pid",
            Self::Tid => "tid",
            Self::ProcessName => "process_name",
            Self::ImagePath => "image_path",
            Self::WorkingDirectory => "working_directory",
            Self::CommandLine => "command_line",
            Self::Path => "path",
            Self::Result => "result",
            Self::CompletionTime => "completion_time",
            Self::Duration => "duration",
            Self::Duration100ns => "duration_100ns",
            Self::Sequence => "sequence",
            Self::SessionId => "session_id",
            Self::Architecture => "architecture",
            Self::Virtualized => "virtualized",
            Self::Integrity => "integrity",
            Self::AuthId => "auth_id",
            Self::User => "user",
            Self::Company => "company",
            Self::Description => "description",
            Self::Version => "version",
            Self::Detail => "detail",
            Self::Extension(name) => name,
        }
    }

    fn value(&self, ev: &Event) -> Value {
        match self {
            Self::Timestamp => Value::String(timestamp_precise(ev)),
            Self::TimestampRaw100ns => ev.time_raw().into(),
            Self::Category => Value::String(ev.class_name().to_string()),
            Self::Operation => Value::String(ev.operation_name().to_string()),
            Self::Pid => ev.process_subject_pid().into(),
            Self::ParentPid => option_value(ev.process_subject_parent_pid()),
            Self::Tid => ev.thread_id().into(),
            Self::ProcessName => {
                let image = ev.process_subject_image_path();
                option_value(
                    image
                        .as_deref()
                        .map(procmon_sdk::basename)
                        .or_else(|| ev.process_name()),
                )
            }
            Self::ImagePath => option_value(ev.process_subject_image_path()),
            Self::WorkingDirectory => option_value(ev.process_working_directory()),
            Self::CommandLine => option_value(ev.process_subject_command_line()),
            Self::Path => option_value(ev.path()),
            Self::Result => Value::String(ev.result().into_owned()),
            Self::CompletionTime => option_value(ev.completion_time()),
            Self::Duration => option_value(ev.duration()),
            Self::Duration100ns => option_value(ev.duration_ticks()),
            Self::Sequence => ev.sequence().into(),
            Self::SessionId => option_value(ev.session_id()),
            Self::Architecture => {
                option_value(
                    ev.is_wow64()
                        .map(|wow64| if wow64 { "32-bit" } else { "64-bit" }),
                )
            }
            Self::Virtualized => option_value(ev.is_virtualized()),
            Self::Integrity => option_value(ev.integrity()),
            Self::AuthId => option_value(ev.auth_id()),
            Self::User => option_value(ev.user()),
            Self::Company => option_value(ev.company()),
            Self::Description => option_value(ev.description()),
            Self::Version => option_value(ev.version()),
            Self::Detail => Value::String(ev.detail()),
            Self::Extension(name) => option_value(ev.struct_field(name).map(|v| v.into_owned())),
        }
    }
}

fn timestamp_precise(ev: &Event) -> String {
    ev.date_precise().replace('/', "-")
}

fn option_value<T: serde::Serialize>(value: Option<T>) -> Value {
    value
        .map(|value| serde_json::to_value(value).unwrap_or(Value::Null))
        .unwrap_or(Value::Null)
}

fn json_scalar(value: Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value,
        other => other.to_string(),
    }
}

fn normalize_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn available_fields() -> Vec<String> {
    let mut names: Vec<String> = Field::DEFAULT_JSON
        .iter()
        .map(|field| field.name().to_string())
        .collect();
    names.extend(
        procmon_sdk::struct_fields()
            .into_iter()
            .map(|field| field.name.to_string()),
    );
    names
}

/// Encodes exactly one physical RFC-4180-style record. Captured CR/LF are
/// flattened so an event can never split the stdout line protocol.
fn csv_record(values: Vec<String>) -> String {
    values
        .into_iter()
        .map(|value| {
            let value = value.replace(['\r', '\n'], " ");
            if value.contains([',', '"']) {
                format!("\"{}\"", value.replace('"', "\"\""))
            } else {
                value
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Writes and immediately flushes one already-formatted event line. Explicit
/// flushing keeps redirected/piped stdout live as well as an interactive console.
pub(crate) fn write_line(out: &mut impl Write, line: &str) -> io::Result<()> {
    writeln!(out, "{line}")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_fields_selects_json_lines() {
        assert!(matches!(
            StreamFormat::from_names(&[]).unwrap(),
            StreamFormat::JsonLines
        ));
    }

    #[test]
    fn csv_always_starts_with_timestamp_and_deduplicates() {
        let format = StreamFormat::from_names(&[
            "pid".to_string(),
            "cmdline".to_string(),
            "timestamp".to_string(),
            "pid".to_string(),
        ])
        .unwrap();
        assert_eq!(
            format.header().as_deref(),
            Some("timestamp,pid,command_line")
        );
    }

    #[test]
    fn aliases_are_case_and_separator_insensitive() {
        let format = StreamFormat::from_names(&[
            "Parent-PID".to_string(),
            "Working Directory".to_string(),
            "binary_path".to_string(),
        ])
        .unwrap();
        assert_eq!(
            format.header().as_deref(),
            Some("timestamp,parent_pid,working_directory,image_path")
        );
    }

    #[test]
    fn csv_quotes_and_stays_on_one_physical_line() {
        assert_eq!(
            csv_record(vec!["a,b".into(), "x\"y".into(), "one\r\ntwo".into()]),
            "\"a,b\",\"x\"\"y\",one  two"
        );
    }

    #[test]
    fn missing_csv_value_is_an_empty_column() {
        assert_eq!(json_scalar(Value::Null), "");
    }

    #[test]
    fn rejects_unknown_fields_before_capture() {
        let error = StreamFormat::from_names(&["not-a-field".to_string()]).unwrap_err();
        assert!(error.contains("unknown stdout field"));
        assert!(error.contains("command_line"));
    }

    #[test]
    fn writes_and_terminates_one_line() {
        let mut out = Vec::new();
        write_line(&mut out, "{\"pid\":42}").unwrap();
        assert_eq!(out, b"{\"pid\":42}\n");
    }
}
