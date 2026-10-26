//! Documentation guards for the standing order: unbuilt surface is a tracked issue,
//! never a decision entry. Both documents are read as the checked-in text, so a gap
//! written down without an issue link fails the build instead of aging into a README.

const README: &str = include_str!("../README.md");
const CONTRACTS: &str = include_str!("../docs/contracts.md");
const ISSUE_URL: &str = "https://github.com/floffel/sipgate-flow/issues/";

/// The body of `heading`, up to the next level-two heading.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(heading)
        .unwrap_or_else(|| panic!("{heading:?} is gone from the document"));
    let body = &doc[start + heading.len()..];
    body.find("\n## ").map_or(body, |cut| &body[..cut])
}

/// Markdown bullets with their soft-wrapped continuation lines folded in.
fn bullets(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut open = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("* ") {
            out.push(rest.trim().to_owned());
            open = true;
        } else if line.trim().is_empty() {
            open = false;
        } else if open {
            if let Some(last) = out.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        }
    }
    out
}

/// §8 split into the tracked list and the "absent upstream" tail.
fn contract_gaps() -> (String, String) {
    let eight = section(CONTRACTS, "## 8. ").to_owned();
    match eight.split_once("\n### Absent upstream") {
        Some((tracked, absent)) => (tracked.to_owned(), absent.to_owned()),
        None => (eight, String::new()),
    }
}

fn assert_every_gap_is_tracked(what: &str, text: &str) {
    let found = bullets(text);
    assert!(
        found.len() >= 4,
        "{what}: expected at least 4 gap entries, found {}",
        found.len()
    );
    for gap in &found {
        assert!(
            gap.contains(ISSUE_URL),
            "{what}: surface written down without a tracked issue: {gap}"
        );
    }
}

#[test]
fn every_gap_in_the_readme_links_a_tracked_issue() {
    assert_every_gap_is_tracked("README.md", section(README, "## Where the rest lives"));
}

#[test]
fn every_gap_in_the_contracts_links_a_tracked_issue() {
    let (tracked, _absent) = contract_gaps();
    assert_every_gap_is_tracked("docs/contracts.md", &tracked);
}

#[test]
fn the_two_documents_list_the_same_gaps() {
    let readme = bullets(section(README, "## Where the rest lives"));
    let (tracked, _absent) = contract_gaps();
    let contracts = bullets(&tracked);
    assert_eq!(
        readme.len(),
        contracts.len(),
        "README lists {} gaps, docs/contracts.md {} - the two documents disagree",
        readme.len(),
        contracts.len()
    );
}

#[test]
fn no_document_calls_a_documented_surface_out_of_scope() {
    for (name, doc) in [("README.md", README), ("docs/contracts.md", CONTRACTS)] {
        for (index, line) in doc.lines().enumerate() {
            let lower = line.to_lowercase();
            let banned = [
                "out of scope",
                "deliberately not modelled",
                "deliberately not modeled",
                "deliberate exclusion",
                "deliberate exclusions",
            ];
            for phrase in banned {
                assert!(
                    !lower.contains(phrase),
                    "{name}:{}: a documented surface is declared {phrase:?}: {line}",
                    index + 1
                );
            }
        }
    }
}

#[test]
fn the_absent_upstream_list_stays_cited_and_short() {
    let (_tracked, absent) = contract_gaps();
    let items = bullets(&absent);
    assert_eq!(
        items.len(),
        2,
        "the absent-upstream list grew to {} entries - each one needs a citation in 7.x",
        items.len()
    );
    for item in &items {
        assert!(
            item.contains("7."),
            "absent-upstream entry without a citation in the 7.x sections: {item}"
        );
    }
}
