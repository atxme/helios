fn main() {
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows/orion-manifest.xml"));
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("construction des ressources Tauri Orion");
}
