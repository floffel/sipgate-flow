//! The API review as a gate: every public enum, and every public struct that
//! exposes a field, is `#[non_exhaustive]`, so adding a variant or a field stays
//! a non-breaking release.
//!
//! Rust cannot reflect over attributes, so this reads `src/` the way a reviewer
//! does - one item at a time - and derives the decision from the attribute that
//! is actually in the file, not from a list somebody typed once. Types that are
//! deliberately exhaustive go into [`ALLOWED_EXHAUSTIVE`] with their argument;
//! that list is checked in both directions, so an entry for a type that no
//! longer exists (or that has since been marked `#[non_exhaustive]`) fails here.

use std::fs;
use std::path::{Path, PathBuf};

/// What kind of type an [`Item`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Struct,
    Enum,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Enum => "enum",
        }
    }
}

/// A public type found in `src/`.
#[derive(Debug)]
struct Item {
    kind: Kind,
    name: String,
    file: String,
    line: usize,
    non_exhaustive: bool,
    public_fields: Vec<String>,
}

impl Item {
    fn location(&self) -> String {
        format!(
            "{} {} ({}:{})",
            self.kind.as_str(),
            self.name,
            self.file,
            self.line
        )
    }

    fn allowed_exhaustive(&self) -> bool {
        ALLOWED_EXHAUSTIVE
            .iter()
            .any(|(kind, name, _)| *kind == self.kind.as_str() && *name == self.name)
    }
}

/// Public types that are deliberately exhaustive, with the reason.
///
/// Only types that **cannot** grow belong here: a closed set the specification
/// fixes, or a type whose extra fields would already be breaking for another
/// documented reason. "A field is unlikely" is not an entry.
const ALLOWED_EXHAUSTIVE: &[(&str, &str, &str)] = &[];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        .map(|entry| entry.expect("readable directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn items_in(file: &str, source: &str) -> Vec<Item> {
    let lines: Vec<&str> = source.lines().collect();
    let mut items = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let declaration = if let Some(rest) = line.strip_prefix("pub struct ") {
            Some((Kind::Struct, rest))
        } else {
            line.strip_prefix("pub enum ")
                .map(|rest| (Kind::Enum, rest))
        };
        let Some((kind, rest)) = declaration else {
            continue;
        };
        let name = name_of(rest);
        let non_exhaustive = attributes_before(&lines, index)
            .iter()
            .any(|attribute| attribute.contains("non_exhaustive"));
        let public_fields = if kind == Kind::Struct {
            public_fields(&lines, index, file, &name)
        } else {
            Vec::new()
        };
        items.push(Item {
            kind,
            name,
            file: file.to_string(),
            line: index + 1,
            non_exhaustive,
            public_fields,
        });
    }
    items
}

/// The type name from `Name<..> {`, `Name {` or `Name(..)`.
fn name_of(declaration: &str) -> String {
    declaration
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The attribute block and doc block that sit directly above a declaration.
fn attributes_before(lines: &[&str], index: usize) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        let trimmed = lines[cursor].trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with("#[") {
            attributes.push(trimmed.to_string());
        } else if !trimmed.starts_with("//") {
            break;
        }
    }
    attributes
}

/// The `pub` fields declared in the body of the struct starting at `index`.
fn public_fields(lines: &[&str], index: usize, file: &str, item: &str) -> Vec<String> {
    let declaration = lines[index];
    if !declaration.contains('{') {
        // A tuple struct: its one field is private in this crate.
        return Vec::new();
    }

    let mut fields = Vec::new();
    let mut depth = 0_i32;
    for (offset, line) in lines[index..].iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        depth += i32::try_from(line.matches('{').count()).unwrap_or(i32::MAX)
            - i32::try_from(line.matches('}').count()).unwrap_or(i32::MAX);
        if offset > 0 {
            if let Some(field) = trimmed.strip_prefix("pub ") {
                let name = field.split(':').next().unwrap_or_default().trim();
                if !name.is_empty() && !name.contains('(') {
                    fields.push(name.to_string());
                }
            }
        }
        if depth <= 0 {
            return fields;
        }
    }
    panic!("{file}: no closing brace for `{item}` - the parser needs fixing, not the crate");
}

fn items() -> Vec<Item> {
    let mut files = Vec::new();
    rust_files(&manifest_dir().join("src"), &mut files);
    let mut items = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let name = path
            .strip_prefix(manifest_dir())
            .unwrap_or(&path)
            .display()
            .to_string();
        items.extend(items_in(&name, &source));
    }
    items.sort_by(|left, right| left.name.cmp(&right.name));
    items
}

#[test]
fn every_public_enum_is_non_exhaustive() {
    let offenders = items()
        .into_iter()
        .filter(|item| item.kind == Kind::Enum)
        .filter(|item| !item.non_exhaustive && !item.allowed_exhaustive())
        .map(|item| item.location())
        .collect::<Vec<_>>();
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "an enum without #[non_exhaustive] lets a new variant break a caller"
    );
}

#[test]
fn every_struct_with_a_public_field_is_non_exhaustive() {
    let watched = items()
        .into_iter()
        .filter(|item| item.kind == Kind::Struct && !item.public_fields.is_empty())
        .collect::<Vec<_>>();
    assert!(
        !watched.is_empty(),
        "no struct with a public field was found - the scan is broken, not the crate"
    );

    let offenders = watched
        .iter()
        .filter(|item| !item.non_exhaustive && !item.allowed_exhaustive())
        .map(|item| {
            format!(
                "{} -> pub {}",
                item.location(),
                item.public_fields.join(", ")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "a literal-constructible struct with public fields cannot gain a field without a breaking release"
    );
}

#[test]
fn the_allow_list_cannot_rot() {
    let all = items();
    for (kind, name, reason) in ALLOWED_EXHAUSTIVE {
        assert!(
            !reason.trim().is_empty(),
            "`{name}` is exempt without an argument"
        );
        let item = all
            .iter()
            .find(|item| item.kind.as_str() == *kind && item.name == *name)
            .unwrap_or_else(|| panic!("`{kind} {name}` no longer exists in src/"));
        assert!(
            !item.non_exhaustive,
            "`{name}` is both exempt and #[non_exhaustive] - delete the exemption"
        );
    }
}

#[test]
fn the_parser_reads_attributes_and_fields() {
    let source = "\
#[derive(Debug)]
#[non_exhaustive]
pub struct Gated {
    /// doc
    pub field: u8,
    private: u8,
}

pub struct Open<T> {
    pub field: u8,
}

pub struct Tuple(String);

/// Prose that mentions #[non_exhaustive] without setting it.
pub struct Prose {
    pub field: u8,
}

pub enum Closed {
    A,
}
";
    let parsed = items_in("synthetic.rs", source);
    let names = parsed
        .iter()
        .map(|item| item.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["Gated", "Open", "Tuple", "Prose", "Closed"]);

    assert!(parsed[0].non_exhaustive);
    assert_eq!(parsed[0].public_fields, vec!["field"]);
    assert!(!parsed[1].non_exhaustive);
    assert_eq!(parsed[1].public_fields, vec!["field"]);
    assert_eq!(parsed[2].kind, Kind::Struct);
    assert_eq!(parsed[2].public_fields, Vec::<String>::new());
    assert_eq!(parsed[3].kind, Kind::Struct);
    assert!(
        !parsed[3].non_exhaustive,
        "a doc line that quotes the attribute is not the attribute"
    );
    assert_eq!(parsed[4].kind, Kind::Enum);
}

#[test]
fn the_review_covered_the_whole_surface() {
    let all = items();
    assert!(
        all.len() >= 50,
        "only {} public types were found; the scan must see the whole crate",
        all.len()
    );
    let mut names = all
        .iter()
        .map(|item| format!("{} {}", item.kind.as_str(), item.name))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    assert_eq!(
        names.len(),
        all.len(),
        "two public types share a name and one of them escaped the review"
    );

    for expected in ["Error", "EventPayload", "Session", "Request", "WavFormat"] {
        assert!(
            all.iter().any(|item| item.name == expected),
            "`{expected}` was not reviewed - the scan missed it"
        );
    }
}

#[test]
fn the_compile_time_guards_are_still_on() {
    let lib = fs::read_to_string(manifest_dir().join("src/lib.rs")).expect("src/lib.rs exists");
    for guard in ["#![forbid(unsafe_code)]", "#![deny(missing_docs)]"] {
        assert!(lib.contains(guard), "`{guard}` disappeared from src/lib.rs");
    }
}
