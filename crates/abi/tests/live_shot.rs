#[test]
#[ignore = "live host only, needs valid tg token/chat"]
fn live_sendphoto_vs_senddocument() {
    let token = std::env::var("LEMON_TG_TOKEN").expect("LEMON_TG_TOKEN");
    let chat = std::env::var("LEMON_TG_CHAT").expect("LEMON_TG_CHAT");

    let png = abi::screenshot_png().expect("screenshot");
    println!("LIVE png = {} bytes", png.len());

    let photo_body = abi::build_multipart(
        "lemonboundary",
        &[
            ("chat_id", &chat),
            ("caption", "🍋 test photo"),
            ("parse_mode", "HTML"),
        ],
        "photo",
        "screenshot.png",
        "image/png",
        &png,
    );
    let url = format!("https://api.telegram.org/bot{token}/sendPhoto");
    let t0 = std::time::Instant::now();
    match abi::post_multipart(&url, "lemonboundary", &photo_body) {
        Ok((s, body)) => println!(
            "LIVE sendPhoto ok: status={s} in {}ms body={}",
            t0.elapsed().as_millis(),
            String::from_utf8_lossy(&body)
                .chars()
                .take(120)
                .collect::<String>()
        ),
        Err(e) => println!(
            "LIVE sendPhoto err after {}ms: {e}",
            t0.elapsed().as_millis()
        ),
    }
}
