//! Parse the closed string/dictionary/list syntax in setuptools' generated finder.
//! Python expressions are never evaluated.

use context_relay_protocol::ClientError;
use serde_json::Value;

pub(super) fn parse(text: &str) -> Result<Value, ClientError> {
    if text.len() > 256 * 1024 {
        return Err(super::invalid());
    }
    let mut parser = Parser {
        chars: text.chars().peekable(),
        entries: 0,
    };
    parser.expect('{')?;
    let mut values = serde_json::Map::new();
    if !parser.take('}') {
        loop {
            let key = parser.string()?;
            parser.expect(':')?;
            let value = if parser.take('[') {
                let mut paths = Vec::new();
                if !parser.take(']') {
                    loop {
                        paths.push(Value::String(parser.string()?));
                        if parser.take(']') {
                            break;
                        }
                        parser.expect(',')?;
                        if parser.take(']') {
                            break;
                        }
                    }
                }
                Value::Array(paths)
            } else {
                Value::String(parser.string()?)
            };
            if values.insert(key, value).is_some() {
                return Err(super::invalid());
            }
            if parser.take('}') {
                break;
            }
            parser.expect(',')?;
            if parser.take('}') {
                break;
            }
        }
    }
    parser.whitespace();
    if parser.chars.next().is_some() {
        return Err(super::invalid());
    }
    Ok(Value::Object(values))
}

struct Parser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    entries: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self.chars.peek().is_some_and(|ch| ch.is_ascii_whitespace()) {
            self.chars.next();
        }
    }
    fn take(&mut self, expected: char) -> bool {
        self.whitespace();
        if self.chars.peek() == Some(&expected) {
            self.chars.next();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, expected: char) -> Result<(), ClientError> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(super::invalid())
        }
    }
    fn string(&mut self) -> Result<String, ClientError> {
        self.entries += 1;
        if self.entries > 2048 {
            return Err(super::invalid());
        }
        self.whitespace();
        let quote = self.chars.next().ok_or_else(super::invalid)?;
        if !matches!(quote, '\'' | '"') {
            return Err(super::invalid());
        }
        let mut value = String::new();
        loop {
            let ch = self.chars.next().ok_or_else(super::invalid)?;
            if ch == quote {
                return Ok(value);
            }
            let ch = if ch == '\\' {
                match self.chars.next().ok_or_else(super::invalid)? {
                    '\\' => '\\',
                    '\'' => '\'',
                    '"' => '"',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'x' => self.hex(2)?,
                    'u' => self.hex(4)?,
                    'U' => self.hex(8)?,
                    _ => return Err(super::invalid()),
                }
            } else {
                ch
            };
            if ch.is_control() {
                return Err(super::invalid());
            }
            value.push(ch);
            if value.len() > 4096 {
                return Err(super::invalid());
            }
        }
    }
    fn hex(&mut self, digits: usize) -> Result<char, ClientError> {
        let mut value = 0u32;
        for _ in 0..digits {
            value = value
                .checked_mul(16)
                .and_then(|value| {
                    self.chars
                        .next()?
                        .to_digit(16)
                        .and_then(|digit| value.checked_add(digit))
                })
                .ok_or_else(super::invalid)?;
        }
        char::from_u32(value).ok_or_else(super::invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_python_quoted_paths_lists_and_unicode() {
        assert_eq!(parse(r#"{'module': 'C:\\Users\\User\\專案', 'namespace': ['path/with\'quote', "path/with\"quote"]}"#).unwrap(),
            serde_json::json!({"module":"C:\\Users\\User\\專案", "namespace":["path/with'quote", "path/with\"quote"]}));
        assert_eq!(
            parse(r#"{'escaped': '\x41\u0042\U0001f680'}"#).unwrap(),
            serde_json::json!({"escaped":"AB🚀"})
        );
    }
    #[test]
    fn rejects_expressions_duplicate_keys_and_unbounded_shapes() {
        for text in [
            "__import__('os').system('anything')",
            "{'a': str('path')}",
            "{'a': 'x', 'a': 'y'}",
            "{'a': 1}",
            "{'a': True}",
            "{'a': {'b': 'nested'}}",
            "{'a': '\\q'}",
            "{'a': '\\uD800'}",
            "{'a': 'x'} trailing",
        ] {
            assert!(parse(text).is_err(), "accepted {text}");
        }
        assert!(parse(&" ".repeat(256 * 1024 + 1)).is_err());
    }
}
