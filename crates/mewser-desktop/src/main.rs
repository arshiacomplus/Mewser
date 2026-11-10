fn main() {
    #[cfg(target_os = "linux")]
    {
        mewser_desktop::app::ui::run_gtk_app();
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Mewser Desktop currently provides native WebKitGTK integration on Linux.");
        eprintln!(
            "Windows (WebView2) and Android adapters are defined in mewser_desktop::adapter."
        );
    }
}
