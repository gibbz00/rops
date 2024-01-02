const REFERENCES_DIR: &str = "tests/sops_references";

fn main() {
    println!("cargo:rerun-if-changed={}", REFERENCES_DIR);
    normalize_sops_references()
}

fn normalize_sops_references() {
    for file_path in walkdir::WalkDir::new(REFERENCES_DIR).into_iter().filter_map(|entry| {
        let entry = entry.unwrap().into_path();
        entry.is_file().then_some(entry)
    }) {
        let content = std::fs::read_to_string(&file_path).unwrap();
        let normalized_content = match file_path.extension().unwrap().to_str().unwrap() {
            "yaml" => serde_yaml::to_string(&serde_yaml::from_str::<serde_yaml::Value>(&content).unwrap()).unwrap(),
            "json" => serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&content).unwrap()).unwrap(),
            _ => unimplemented!(),
        };
        std::fs::write(file_path, normalized_content).unwrap();
    }
}
