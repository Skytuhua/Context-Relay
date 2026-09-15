use context_relay_protocol::RecoveryPhraseWords;
use objc2::{MainThreadMarker, MainThreadOnly, rc::autoreleasepool};
use objc2_app_kit::{NSAccessibility, NSAlert, NSAlertFirstButtonReturn, NSSecureTextField};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use zeroize::Zeroizing;

use super::{MAX_INPUT, parse_input};

fn read_phrase(value: &NSString) -> Result<RecoveryPhraseWords, &'static str> {
    if value.length() > MAX_INPUT {
        return Err("Enter exactly 24 recovery words.");
    }
    let mut input = Zeroizing::new(Vec::with_capacity(value.length()));
    for index in 0..value.length() {
        input.push(value.characterAtIndex(index));
    }
    parse_input(&input)
}

pub fn show() -> Result<Option<RecoveryPhraseWords>, &'static str> {
    let mtm = MainThreadMarker::new().ok_or("The recovery dialog requires the main thread.")?;
    autoreleasepool(|_| {
        let alert = NSAlert::new(mtm);
        alert.setMessageText(&NSString::from_str("Context Relay recovery"));
        alert.setInformativeText(&NSString::from_str(
            "Enter all 24 recovery words, separated by spaces. Your phrase stays in the native recovery host.",
        ));
        alert.addButtonWithTitle(&NSString::from_str("Recover"));
        alert
            .addButtonWithTitle(&NSString::from_str("Cancel"))
            .setKeyEquivalent(&NSString::from_str("\u{1b}"));
        let field = NSSecureTextField::initWithFrame(
            NSSecureTextField::alloc(mtm),
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(360.0, 24.0)),
        );
        field.setAccessibilityLabel(Some(&NSString::from_str("Recovery phrase")));
        field.setPlaceholderString(Some(&NSString::from_str("24 recovery words")));
        field.setAutomaticTextCompletionEnabled(false);
        alert.setAccessoryView(Some(&field));
        alert.window().setInitialFirstResponder(Some(&field));
        loop {
            let response = alert.runModal();
            if response != NSAlertFirstButtonReturn {
                field.abortEditing();
                field.setStringValue(&NSString::new());
                return Ok(None);
            }
            // Bound the native-to-Rust copy before allocating it. Each attempt
            // drains its autoreleased strings; no phrase enters a renderer.
            let parsed = autoreleasepool(|_| {
                field.validateEditing();
                let value = field.stringValue();
                field.abortEditing();
                field.setStringValue(&NSString::new());
                read_phrase(&value)
            });
            match parsed {
                Ok(words) => return Ok(Some(words)),
                Err(_) => alert.setInformativeText(&NSString::from_str(
                    "Enter exactly 24 recovery words using English letters, separated by spaces.",
                )),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_string_reader_bounds_and_validates_before_returning_words() {
        autoreleasepool(|_| {
            let words = read_phrase(&NSString::from_str(&"ABANDON ".repeat(24))).unwrap();
            assert_eq!(words.as_words(), vec!["abandon"; 24]);
            assert!(read_phrase(&NSString::from_str(&"a".repeat(MAX_INPUT + 1))).is_err());
            assert!(read_phrase(&NSString::from_str(&"abandon ".repeat(23))).is_err());
            assert!(read_phrase(&NSString::from_str(&"\u{1f512} ".repeat(24))).is_err());
        });
    }
}
