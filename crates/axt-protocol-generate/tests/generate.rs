//! The command, ported from `test/generate_test.dart` of `axt_protocol` for Dart.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use axt_protocol_generate::{generate_from_descriptions, run, rustfmt};
use serde_json::{Value as Json, json};

fn description(name: &str, field: &str) -> Json {
    json!({
        "name": "root",
        "doc": "A type.",
        "texts": {},
        "kind": {"axt.ObjectField": {
            "name": name,
            "version": 1,
            "fields": [{
                "name": field,
                "doc": "The text.",
                "texts": {},
                "required": true,
                "kind": {"axt.StringField": {}},
            }],
        }},
    })
}

/// A directory of its own for each test, removed at the end.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("axt_generate_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_with(args: &[&str], formats: bool) -> (u8, String, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let format = move |_: &Path| formats;
    let code = run(&args, &mut out, &mut err, Some(&format));
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn writes_and_formats_the_structs_of_descriptions() {
    let dir = Dir::new();
    let input = dir.file(
        "memo.json",
        &description("org.example.Memo", "text").to_string(),
    );
    let output = dir.path("memo.rs");
    let args: Vec<OsString> = [input.as_str(), "-o", output.as_str()]
        .iter()
        .map(OsString::from)
        .collect();
    let mut out = Vec::new();
    let code = run(&args, &mut out, &mut Vec::new(), None);
    assert_eq!(code, 0);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains(&format!("wrote {output}"))
    );
    let source = std::fs::read_to_string(&output).unwrap();
    assert!(source.contains("pub struct Memo {"));
    assert!(source.contains("impl TryFrom<Value> for Memo {"));
    assert!(source.contains("impl From<Memo> for Value {"));
    assert!(source.contains("pub const DESCRIPTION: &'static str"));
    assert!(source.contains(&format!("// - {input}")));
    // Formatted once, the source stays as it is.
    assert!(rustfmt(Path::new(&output), None));
    assert_eq!(std::fs::read_to_string(&output).unwrap(), source);
}

#[test]
fn a_formatter_that_cannot_run_fails() {
    let dir = Dir::new();
    assert!(!rustfmt(
        Path::new(&dir.path("x.rs")),
        Some(Path::new(&dir.path("none")))
    ));
}

#[test]
fn usage_missing_files_and_invalid_descriptions_fail() {
    let dir = Dir::new();
    assert_eq!(run_with(&["-h"], true).0, 0);
    assert!(run_with(&["--help"], true).1.contains("Usage:"));
    assert_eq!(run_with(&["x.json"], true).0, 2);
    assert_eq!(run_with(&["-o"], true).0, 2);
    let output = dir.path("out.rs");
    assert_eq!(run_with(&["-o", &output], true).0, 2);
    assert_eq!(
        run_with(&[&dir.path("none.json"), "-o", &output], true).0,
        1
    );
    assert_eq!(
        run_with(&[&dir.file("bad.json", "{"), "-o", &output], true).0,
        1
    );
    let mut empty_doc = description("org.example.A", "text");
    empty_doc["doc"] = json!("");
    let invalid = run_with(
        &[
            &dir.file("invalid.json", &empty_doc.to_string()),
            "--output",
            &output,
        ],
        true,
    );
    assert_eq!(invalid.0, 1);
    assert!(invalid.2.contains("DESCRIPTION_INVALID"), "{}", invalid.2);
    let twice = run_with(
        &[
            &dir.file("a.json", &description("org.example.A", "text").to_string()),
            &dir.file("b.json", &description("org.example.A", "other").to_string()),
            "-o",
            &output,
        ],
        true,
    );
    assert_eq!(twice.0, 1);
    assert!(twice.2.contains("axt-protocol-generate"));
    assert!(!Path::new(&output).exists());
    let unformatted = run_with(
        &[
            &dir.file("c.json", &description("org.example.C", "text").to_string()),
            "-o",
            &output,
        ],
        false,
    );
    assert_eq!(unformatted.0, 1);
    assert!(unformatted.2.contains("rustfmt failed"));
}

#[test]
fn two_types_of_one_rust_name_fail_and_the_same_type_twice_is_written_once() {
    let a = description("org.example.A", "text").to_string();
    let b = description("com.example.A", "text").to_string();
    let e = generate_from_descriptions(&[("a".into(), a.clone()), ("b".into(), b)]).unwrap_err();
    assert!(e.to_string().contains("both named A"), "{e}");
    let source =
        generate_from_descriptions(&[("a".into(), a.clone()), ("b".into(), a.clone())]).unwrap();
    assert_eq!(source.matches("pub struct A {").count(), 1);
    assert_eq!(
        generate_from_descriptions(&[("a".into(), a.clone()), ("b".into(), a)]).unwrap(),
        source
    );
}
