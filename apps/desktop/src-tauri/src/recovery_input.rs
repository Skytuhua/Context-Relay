use context_relay_protocol::RecoveryPhraseWords;
#[cfg(any(windows, target_os = "macos", test))]
use zeroize::Zeroizing;

#[cfg(any(windows, target_os = "macos", test))]
const MAX_INPUT: usize = 1024;

#[cfg(any(windows, target_os = "macos", test))]
fn parse_input(input: &[u16]) -> Result<RecoveryPhraseWords, &'static str> {
    if input.len() > MAX_INPUT || input.iter().any(|unit| *unit > 0x7f) {
        return Err("Enter exactly 24 recovery words.");
    }
    let mut text = Zeroizing::new(String::with_capacity(input.len()));
    for unit in input {
        text.push(*unit as u8 as char);
    }
    RecoveryPhraseWords::new(
        text.split_ascii_whitespace()
            .map(str::to_ascii_lowercase)
            .collect(),
    )
    .map_err(|_| "Enter exactly 24 recovery words.")
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub async fn prompt(app: &tauri::AppHandle) -> Result<Option<RecoveryPhraseWords>, &'static str> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        #[cfg(windows)]
        use tauri::Manager;
        let (send, receive) = tokio::sync::oneshot::channel();
        #[cfg(windows)]
        let app_copy = app.clone();
        app.run_on_main_thread(move || {
            #[cfg(windows)]
            let result = app_copy
                .get_webview_window("main")
                .ok_or("The desktop window is unavailable.")
                .and_then(|window| {
                    window
                        .hwnd()
                        .map_err(|_| "The desktop window is unavailable.")
                })
                .and_then(|parent| windows::show(parent.0));
            #[cfg(target_os = "macos")]
            let result = macos::show();
            let _ = send.send(result);
        })
        .map_err(|_| "The recovery dialog could not be opened.")?;
        receive
            .await
            .map_err(|_| "The recovery dialog closed unexpectedly.")?
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = app;
        Err("Native recovery entry is not available on this platform yet.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_input_is_bounded_normalized_and_redacted() {
        let words = parse_input(
            "ABANDON "
                .repeat(24)
                .encode_utf16()
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .unwrap();
        assert_eq!(words.as_words(), vec!["abandon"; 24]);
        assert!(!format!("{words:?}").contains("abandon"));
        assert!(parse_input(&[0xd800]).is_err());
        assert!(parse_input(&vec![b'a' as u16; MAX_INPUT + 1]).is_err());
        assert!(parse_input(&"abandon ".repeat(23).encode_utf16().collect::<Vec<_>>()).is_err());
    }
}
