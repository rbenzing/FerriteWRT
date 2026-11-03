//! Re-run the build when any embedded UI asset changes, since `include_dir!` does not
//! track the directory contents by itself.

fn main() {
    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed=build.rs");
}
