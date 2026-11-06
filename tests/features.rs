//! The headline feature promise is that the default build forces no networking
//! stack on a webhook-only consumer. Resolve the real graph in a child Cargo so
//! optional dependencies in the lockfile cannot hide behind `cfg`-gated code.

use std::process::Command;

fn active_normal_dependencies(extra_args: &[&str]) -> String {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["tree", "--prefix", "none", "-e", "normal"])
        .args(extra_args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree starts");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree emits UTF-8")
}

fn assert_no_network_stack(tree: &str) {
    for package in ["reqwest", "hyper", "rustls", "tokio", "ring"] {
        assert!(
            !tree
                .lines()
                .any(|line| line.split_whitespace().next() == Some(package)),
            "{package} is active in the default/minimal graph:\n{tree}"
        );
    }
}

#[test]
fn default_features_force_no_http_or_async_runtime() {
    let tree = active_normal_dependencies(&[]);
    assert_no_network_stack(&tree);
    assert_eq!(
        tree,
        active_normal_dependencies(&["--no-default-features"]),
        "the default graph must equal the minimal graph"
    );
}

#[test]
fn http_is_opt_in_and_pulls_the_transport_stack() {
    let tree = active_normal_dependencies(&["--features", "http"]);
    for package in ["reqwest", "hyper", "rustls"] {
        assert!(
            tree.lines()
                .any(|line| line.split_whitespace().next() == Some(package)),
            "{package} is missing from the opt-in HTTP graph:\n{tree}"
        );
    }
}
