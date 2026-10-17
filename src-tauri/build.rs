fn main() {
       let manifest = if std::env::var("PROFILE").as_deref() == Ok("debug")
        && std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some()
    {
        include_str!("app.manifest").replace("requireAdministrator", "asInvoker")
    } else {
        include_str!("app.manifest").to_string()
    };
    let windows = tauri_build::WindowsAttributes::new()
        .window_icon_path("icons/wawity.ico")
        .app_manifest(manifest);
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("build Windows resources");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=icons/wawity.ico");
    println!("cargo:rerun-if-env-changed=WAWITY_PORTS_TEST_MODE");
}
