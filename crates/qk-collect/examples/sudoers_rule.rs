fn main() {
    let user = std::env::args().nth(1).expect("usage: sudoers_rule <user> <os>");
    let os: qk_core::host::OsType = std::env::args().nth(2).expect("os").parse().expect("os type");
    print!("{}", qk_collect::sudoers_rule(&user, os));
}
