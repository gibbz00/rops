fn main() {
    let mut args = std::env::args();
    args.next().expect("program arg");
    let content = args.next().expect("no content arg");
    let to = args.next().expect("no destination arg");
    std::fs::write(to, content).unwrap();
}
