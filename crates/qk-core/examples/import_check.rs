use std::collections::HashSet;
use std::fs::File;

fn main() {
    let path = std::env::args().nth(1).expect("usage: import_check <file.csv>");
    let report = qk_core::host_csv::import(File::open(path).unwrap(), &HashSet::new()).unwrap();
    println!("imported={} duplicates={} errors={}", report.hosts.len(), report.duplicates.len(), report.errors.len());
    for e in &report.errors {
        println!("line {}: {}", e.line, e.message);
    }
}
