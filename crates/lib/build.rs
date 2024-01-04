use serde::{Deserialize, Serialize};

const REFERENCES_DIR: &str = "tests/sops_references";

// WORKAROUND: cargo:rerun-if-changed=REFERENCES_DIR would always be triggered
// Naive approach that works well enough.
const CACHE_PATH: &str = "tests/sops_references/cache.yaml";

#[derive(Serialize, Deserialize)]
struct Cache {
    previous_files_in_directory: usize,
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed={}", CACHE_PATH);
    normalize_sops_references()
}

fn normalize_sops_references() -> anyhow::Result<()> {
    let cache = serde_yaml::from_str::<Cache>(&std::fs::read_to_string(CACHE_PATH)?)?;

    let entries_count = walkdir::WalkDir::new(REFERENCES_DIR).into_iter().count();

    if cache.previous_files_in_directory < entries_count {
        for file_path in walkdir::WalkDir::new(REFERENCES_DIR).into_iter().filter_map(|entry| {
            let entry = entry.unwrap().into_path();
            entry.is_file().then_some(entry)
        }) {
            let content = std::fs::read_to_string(&file_path)?;
            let normalized_content = match file_path.extension().unwrap().to_str().unwrap() {
                "yaml" => serde_yaml::to_string(&serde_yaml::from_str::<serde_yaml::Value>(&content)?)?,
                "json" => serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&content)?)?,
                _ => unimplemented!(),
            };
            std::fs::write(file_path, normalized_content)?;
        }

        let new_cache = serde_yaml::to_string(&Cache {
            previous_files_in_directory: entries_count,
        })?;

        std::fs::write(CACHE_PATH, new_cache)?
    }

    Ok(())
}
