use std::ptr::null_mut;

use context_relay_protocol::RecoveryPhraseWords;
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, WPARAM},
    UI::{
        Controls::{EM_EMPTYUNDOBUFFER, EM_LIMITTEXT},
        Input::KeyboardAndMouse::SetFocus,
        WindowsAndMessaging::*,
    },
};
use zeroize::Zeroizing;

use super::{MAX_INPUT, parse_input};

const INPUT: i32 = 100;
const ERROR: i32 = 101;

#[derive(Default)]
struct DialogState {
    words: Option<RecoveryPhraseWords>,
    #[cfg(test)]
    automatic_answer: Option<Option<&'static str>>,
}

// DWORD-aligned standard dialog template; controls use dialog units and the
// system's dialog keyboard navigation, password masking and accessible labels.
fn template() -> Vec<u32> {
    fn dword(out: &mut Vec<u16>, value: u32) {
        out.extend([value as u16, (value >> 16) as u16]);
    }
    fn string(out: &mut Vec<u16>, value: &str) {
        out.extend(value.encode_utf16().chain(Some(0)));
    }
    let mut out = Vec::new();
    dword(
        &mut out,
        WS_POPUP
            | WS_CAPTION
            | WS_SYSMENU
            | DS_MODALFRAME as u32
            | DS_SETFONT as u32
            | DS_CENTER as u32,
    );
    dword(&mut out, 0);
    out.extend([5, 0, 0, 320, 110, 0, 0]);
    string(&mut out, "Context Relay recovery");
    out.push(9);
    string(&mut out, "Segoe UI");
    for (class, id, rect, style, title) in [
        (
            0x82,
            102,
            [10, 8, 300, 20],
            0,
            "&Recovery phrase: enter all 24 words, separated by spaces.",
        ),
        (
            0x81,
            INPUT as u16,
            [10, 32, 300, 16],
            WS_BORDER | WS_TABSTOP | ES_PASSWORD as u32 | ES_AUTOHSCROLL as u32,
            "",
        ),
        (
            0x82,
            ERROR as u16,
            [10, 54, 300, 20],
            0,
            "Your phrase stays in the native recovery host.",
        ),
        (
            0x80,
            IDOK as u16,
            [160, 82, 72, 18],
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            "&Recover",
        ),
        (
            0x80,
            IDCANCEL as u16,
            [238, 82, 72, 18],
            WS_TABSTOP,
            "Cancel",
        ),
    ] {
        if out.len() % 2 != 0 {
            out.push(0);
        }
        dword(&mut out, WS_CHILD | WS_VISIBLE | style);
        dword(&mut out, 0);
        out.extend(rect);
        out.extend([id, 0xffff, class]);
        string(&mut out, title);
        out.push(0);
    }
    if out.len() % 2 != 0 {
        out.push(0);
    }
    out.chunks_exact(2)
        .map(|pair| u32::from(pair[0]) | (u32::from(pair[1]) << 16))
        .collect()
}

unsafe fn clear_input(dialog: HWND) {
    // SAFETY: called only while this dialog and its edit control are alive.
    unsafe {
        SetDlgItemTextW(dialog, INPUT, windows_sys::core::w!(""));
        SendDlgItemMessageW(dialog, INPUT, EM_EMPTYUNDOBUFFER, 0, 0);
    }
}

unsafe extern "system" fn dialog_proc(
    dialog: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    // SAFETY: DialogBox keeps the stack-owned result alive until its modal loop
    // has destroyed the dialog. Only this UI thread accesses that result.
    unsafe {
        match message {
            WM_INITDIALOG => {
                SetWindowLongPtrW(dialog, GWLP_USERDATA, lparam);
                SendDlgItemMessageW(dialog, INPUT, EM_LIMITTEXT, MAX_INPUT, 0);
                SetFocus(GetDlgItem(dialog, INPUT));
                #[cfg(test)]
                if let Some(answer) = (*(lparam as *const DialogState)).automatic_answer {
                    let command = if let Some(answer) = answer {
                        let text: Vec<u16> = answer.encode_utf16().chain(Some(0)).collect();
                        SetDlgItemTextW(dialog, INPUT, text.as_ptr());
                        IDOK
                    } else {
                        IDCANCEL
                    };
                    SendMessageW(dialog, WM_COMMAND, command as usize, 0);
                }
                return 0;
            }
            WM_COMMAND if (wparam & 0xffff) as i32 == IDOK => {
                let state = GetWindowLongPtrW(dialog, GWLP_USERDATA) as *mut DialogState;
                if state.is_null() {
                    return 0;
                }
                let mut buffer = Zeroizing::new(vec![0u16; MAX_INPUT + 1]);
                let count = GetDlgItemTextW(dialog, INPUT, buffer.as_mut_ptr(), buffer.len() as i32)
                    as usize;
                match parse_input(&buffer[..count]) {
                    Ok(words) => {
                        (*state).words = Some(words);
                        clear_input(dialog);
                        EndDialog(dialog, IDOK as isize);
                    }
                    Err(_) => {
                        SetDlgItemTextW(
                            dialog,
                            ERROR,
                            windows_sys::core::w!("Enter exactly 24 recovery words."),
                        );
                        SetFocus(GetDlgItem(dialog, INPUT));
                    }
                }
                return 1;
            }
            WM_CLOSE => {
                clear_input(dialog);
                EndDialog(dialog, IDCANCEL as isize);
                return 1;
            }
            WM_COMMAND if (wparam & 0xffff) as i32 == IDCANCEL => {
                clear_input(dialog);
                EndDialog(dialog, IDCANCEL as isize);
                return 1;
            }
            WM_DESTROY => {
                clear_input(dialog);
                SetWindowLongPtrW(dialog, GWLP_USERDATA, 0);
            }
            _ => {}
        }
    }
    0
}

pub fn show(parent: HWND) -> Result<Option<RecoveryPhraseWords>, &'static str> {
    show_with_state(parent, DialogState::default())
}

fn show_with_state(
    parent: HWND,
    mut state: DialogState,
) -> Result<Option<RecoveryPhraseWords>, &'static str> {
    let template = template();
    // SAFETY: the aligned template is complete and lives through the blocking
    // call; parent comes from Tauri on the UI thread; words remains stack-owned.
    let result = unsafe {
        DialogBoxIndirectParamW(
            null_mut(),
            template.as_ptr().cast(),
            parent,
            Some(dialog_proc),
            (&mut state as *mut DialogState) as isize,
        )
    };
    match result {
        result if result == IDOK as isize => state
            .words
            .map(Some)
            .ok_or("The recovery dialog returned no phrase."),
        result if result == IDCANCEL as isize => Ok(None),
        _ => Err("The recovery dialog could not be opened."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_native_dialog_accepts_and_cancels_before_display() {
        // Exercise the actual Win32 template, edit control and callback. EndDialog
        // during initialization closes the modal dialog before it is displayed.
        let accepted = show_with_state(null_mut(), DialogState {
            words: None,
            automatic_answer: Some(Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")),
        }).unwrap().unwrap();
        assert_eq!(accepted.as_words().len(), 24);
        assert_eq!(accepted.as_words()[23], "art");
        assert!(
            show_with_state(
                null_mut(),
                DialogState {
                    words: None,
                    automatic_answer: Some(None),
                }
            )
            .unwrap()
            .is_none()
        );
    }
}
