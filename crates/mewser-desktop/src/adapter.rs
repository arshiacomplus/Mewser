pub trait BrowserEngineAdapter {
    fn load_uri(&self, uri: &str);
    fn go_back(&self);
    fn go_forward(&self);
    fn reload(&self);
    fn stop_loading(&self);
    fn uri(&self) -> Option<String>;
    fn title(&self) -> Option<String>;
    fn can_go_back(&self) -> bool;
    fn can_go_forward(&self) -> bool;
    fn is_loading(&self) -> bool;
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::BrowserEngineAdapter;
    use webkit2gtk::{WebView, WebViewExt};

    #[derive(Clone)]
    pub struct WebKitGtkAdapter {
        webview: WebView,
    }

    impl WebKitGtkAdapter {
        pub fn new(webview: WebView) -> Self {
            Self { webview }
        }

        pub fn webview(&self) -> &WebView {
            &self.webview
        }
    }

    impl BrowserEngineAdapter for WebKitGtkAdapter {
        fn load_uri(&self, uri: &str) {
            self.webview.load_uri(uri);
        }

        fn go_back(&self) {
            self.webview.go_back();
        }

        fn go_forward(&self) {
            self.webview.go_forward();
        }

        fn reload(&self) {
            self.webview.reload();
        }

        fn stop_loading(&self) {
            self.webview.stop_loading();
        }

        fn uri(&self) -> Option<String> {
            self.webview.uri().map(|g| g.to_string())
        }

        fn title(&self) -> Option<String> {
            self.webview.title().map(|g| g.to_string())
        }

        fn can_go_back(&self) -> bool {
            self.webview.can_go_back()
        }

        fn can_go_forward(&self) -> bool {
            self.webview.can_go_forward()
        }

        fn is_loading(&self) -> bool {
            self.webview.is_loading()
        }
    }
}

#[cfg(target_os = "windows")]
pub mod windows {
    use super::BrowserEngineAdapter;

    /// Windows WebView2 adapter boundary.
    /// Requires Windows WebView2 SDK on Windows hosts.
    pub struct WebView2Adapter;

    impl BrowserEngineAdapter for WebView2Adapter {
        fn load_uri(&self, _uri: &str) {}
        fn go_back(&self) {}
        fn go_forward(&self) {}
        fn reload(&self) {}
        fn stop_loading(&self) {}
        fn uri(&self) -> Option<String> {
            None
        }
        fn title(&self) -> Option<String> {
            None
        }
        fn can_go_back(&self) -> bool {
            false
        }
        fn can_go_forward(&self) -> bool {
            false
        }
        fn is_loading(&self) -> bool {
            false
        }
    }
}

#[cfg(target_os = "android")]
pub mod android {
    use super::BrowserEngineAdapter;

    /// Android WebView adapter boundary.
    /// Requires Android SDK & NDK for JNI/Compose integration.
    pub struct AndroidWebViewAdapter;

    impl BrowserEngineAdapter for AndroidWebViewAdapter {
        fn load_uri(&self, _uri: &str) {}
        fn go_back(&self) {}
        fn go_forward(&self) {}
        fn reload(&self) {}
        fn stop_loading(&self) {}
        fn uri(&self) -> Option<String> {
            None
        }
        fn title(&self) -> Option<String> {
            None
        }
        fn can_go_back(&self) -> bool {
            false
        }
        fn can_go_forward(&self) -> bool {
            false
        }
        fn is_loading(&self) -> bool {
            false
        }
    }
}
