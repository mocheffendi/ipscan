fn main() {
    // Embed the icon as a real Windows resource so File Explorer, the taskbar
    // and Alt+Tab all show it (the runtime egui icon alone only covers the
    // window, not the .exe file itself).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("icon.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("could not embed the Windows icon resource");
    }
}
