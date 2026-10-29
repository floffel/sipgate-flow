//! Changelog guards: the promise in the README ("every observable change gets an
//! entry, the bump and the entry land on the tagged commit") is only worth
//! something if the file exists, names its conventions, covers the version in
//! `Cargo.toml` and says whether that version actually shipped.

const CHANGELOG: &str = include_str!("../CHANGELOG.md");
const README: &str = include_str!("../README.md");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// `## [x.y.z] — …` headings, in file order.
fn version_headings() -> Vec<&'static str> {
    CHANGELOG
        .lines()
        .filter_map(|line| line.strip_prefix("## ["))
        .filter(|heading| !heading.starts_with("Unreleased]"))
        .collect()
}

/// `x.y.z` out of a heading body such as `0.1.0] — 2026-10-29`.
fn version_of(heading: &str) -> (u64, u64, u64) {
    let version = heading
        .split_once(']')
        .unwrap_or_else(|| panic!("heading without a closing bracket: {heading}"))
        .0;
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "{version:?} is not a semver triple");
    let axis = |index: usize| {
        parts[index]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{version:?} has a non-numeric component"))
    };
    (axis(0), axis(1), axis(2))
}

/// What follows the version in a heading: a release date or an explicit "not yet".
fn release_state(heading: &str) -> &str {
    heading
        .split_once(']')
        .map(|(_, rest)| rest.trim_start_matches(['—', '-', ' ']))
        .unwrap_or_default()
}

fn looks_like_a_date(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

#[test]
fn the_changelog_names_its_conventions() {
    assert!(
        CHANGELOG.contains("https://keepachangelog.com/en/1.1.0/"),
        "CHANGELOG.md no longer names the format it follows"
    );
    assert!(
        CHANGELOG.contains("https://semver.org/spec/v2.0.0.html"),
        "CHANGELOG.md no longer names the versioning scheme it follows"
    );
    assert!(
        CHANGELOG.starts_with("# Changelog\n"),
        "CHANGELOG.md must open with a level-one `# Changelog` heading"
    );
}

#[test]
fn the_version_in_the_manifest_has_an_entry() {
    let current = env!("CARGO_PKG_VERSION");
    let headings = version_headings();
    assert!(
        !headings.is_empty(),
        "CHANGELOG.md has no `## [x.y.z]` sections at all"
    );
    assert!(
        headings
            .iter()
            .any(|heading| heading.starts_with(&format!("{current}]"))),
        "Cargo.toml says {current} but CHANGELOG.md has no `## [{current}]` entry (entries: {headings:?})"
    );
}

#[test]
fn versions_descend_newest_first() {
    let versions: Vec<_> = version_headings().iter().map(|h| version_of(h)).collect();
    for pair in versions.windows(2) {
        assert!(
            pair[0] > pair[1],
            "CHANGELOG.md is not newest-first: {:?} comes before {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn every_entry_says_whether_that_version_shipped() {
    for heading in version_headings() {
        let state = release_state(heading);
        assert!(
            looks_like_a_date(state) || state == "not yet published",
            "entry {heading:?} carries neither a release date (YYYY-MM-DD) nor \"not yet published\" - \
             an unpublished version must never look released"
        );
    }
}

#[test]
fn only_the_newest_entry_may_be_unpublished() {
    // A stale "not yet published" marker on an older entry would make a shipped
    // version look provisional; only the top of the file can be unpublished.
    let headings = version_headings();
    for (index, heading) in headings.iter().enumerate() {
        if release_state(heading) == "not yet published" {
            assert_eq!(
                index, 0,
                "{heading:?} is marked unpublished but is not the newest entry"
            );
        }
    }
}

#[test]
fn only_keep_a_changelog_section_names_are_used() {
    const ALLOWED: [&str; 8] = [
        "Added",
        "Changed",
        "Deprecated",
        "Removed",
        "Fixed",
        "Security",
        "Notes",
        "Unreleased",
    ];
    for line in CHANGELOG.lines() {
        let Some(entry) = line.strip_prefix("### ") else {
            continue;
        };
        assert!(
            ALLOWED.contains(&entry.trim()),
            "`### {entry}` is not a Keep a Changelog section name"
        );
    }
}

#[test]
fn the_readme_points_at_the_changelog_and_states_the_msrv() {
    assert!(
        README.contains("CHANGELOG.md"),
        "README.md does not link the changelog"
    );
    let declared = CARGO_TOML
        .lines()
        .find_map(|line| line.strip_prefix("rust-version = \""))
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default();
    assert_eq!(
        declared, "1.89",
        "Cargo.toml no longer declares the MSRV the README documents"
    );
    assert!(
        README.contains(&format!("MSRV: Rust {declared}")),
        "README.md must document `MSRV: Rust {declared}`, the version in Cargo.toml"
    );
}

#[test]
fn the_unreleased_section_sits_on_top() {
    let index = CHANGELOG
        .lines()
        .filter_map(|line| line.strip_prefix("## ["))
        .position(|heading| heading.starts_with("Unreleased]"));
    if let Some(index) = index {
        assert_eq!(
            index, 0,
            "the `[Unreleased]` section must be the first entry in the file"
        );
    }
}
