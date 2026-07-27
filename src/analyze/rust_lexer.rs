//! Tokenizing Rust source, far enough to see its structure.
//!
//! This is not a Rust front end and does not try to be one. It answers exactly the
//! questions the structural analyzer asks: where do identifiers sit, where do the
//! delimiters nest, and which of those are real rather than characters inside a string or
//! a comment.
//!
//! # Why the awkward cases are here rather than skipped
//!
//! Every one of them can silently move a brace. A `/*` inside a line comment, a `}` inside
//! a raw string, an apostrophe in `'\''` — get any of them wrong and the brace counter
//! drifts, and from that point on every item lands in the wrong parent. A skim parser is
//! allowed to be imprecise about *meaning*; it is not allowed to be wrong about *nesting*,
//! because nesting is the only thing it actually knows.
//!
//! So this handles, deliberately and with a test each:
//!
//! - nested block comments, which Rust has and C does not;
//! - raw strings at any hash depth, and their byte-string forms;
//! - the lifetime-versus-character-literal ambiguity after `'`;
//! - raw identifiers, so `r#type` is the identifier `type` and not the keyword;
//! - unterminated strings and comments at end of input, which must stop rather than loop.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or keyword. A raw identifier carries its name without the `r#`.
    Ident {
        /// The name.
        name: String,
        /// Whether it was written `r#name`, which makes it never a keyword.
        raw: bool,
    },
    /// A literal of any kind, reduced to the fact that one was here.
    Literal,
    /// A lifetime, including the leading apostrophe.
    Lifetime(String),
    /// An opening delimiter.
    Open(Delimiter),
    /// A closing delimiter.
    Close(Delimiter),
    /// Any other punctuation, one character at a time.
    Punct(char),
}

impl Token {
    /// The identifier's name, when this is one that was not written raw.
    ///
    /// A raw identifier is deliberately excluded from keyword matching: `r#fn` names
    /// something called `fn` and does not begin a function.
    #[must_use]
    pub fn keyword(&self) -> Option<&str> {
        match self {
            Self::Ident { name, raw: false } => Some(name.as_str()),
            _ => None,
        }
    }

    /// The identifier's name, raw or not.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Ident { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    /// Reports whether this is the given punctuation character.
    #[must_use]
    pub fn is_punct(&self, character: char) -> bool {
        matches!(self, Self::Punct(found) if *found == character)
    }
}

/// A bracketing pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delimiter {
    /// `{}`
    Brace,
    /// `()`
    Paren,
    /// `[]`
    Bracket,
}

impl fmt::Display for Delimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Brace => "{}",
            Self::Paren => "()",
            Self::Bracket => "[]",
        })
    }
}

/// A token and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spanned {
    /// The token.
    pub token: Token,
    /// 1-based line of its first character.
    pub line: u32,
    /// 1-based column of its first character, in Unicode scalar values.
    pub column: u32,
    /// 0-based byte offset of its first character.
    pub offset: u64,
}

/// Tokenizes Rust source.
///
/// Never fails. Malformed input — an unterminated string, a stray backslash, a lone `'` —
/// produces whatever tokens can be read and then stops. A structural analyzer runs over
/// source somebody is still editing, so refusing to produce anything for a file with one
/// unclosed quote would make the common case the failing case.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Spanned> {
    Lexer::new(source).run()
}

struct Lexer<'a> {
    source: &'a [u8],
    text: &'a str,
    at: usize,
    line: u32,
    column: u32,
    pending_offset: u64,
    tokens: Vec<Spanned>,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            source: text.as_bytes(),
            text,
            at: 0,
            line: 1,
            column: 1,
            pending_offset: 0,
            tokens: Vec::new(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.at).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.source.get(self.at + ahead).copied()
    }

    /// Advances one byte, keeping the line and column current.
    ///
    /// A column counts Unicode scalar values, so a continuation byte does not advance it.
    /// Counting bytes instead would put every range after the first non-ASCII character in
    /// the wrong place.
    fn bump(&mut self) {
        let Some(byte) = self.peek() else { return };
        self.at += 1;
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
        } else if byte & 0xC0 != 0x80 {
            self.column += 1;
        }
    }

    fn bump_while(&mut self, mut predicate: impl FnMut(u8) -> bool) {
        while self.peek().is_some_and(&mut predicate) {
            self.bump();
        }
    }

    fn push(&mut self, token: Token, line: u32, column: u32) {
        // The offset is captured with the line and column by every caller, through
        // `mark`, so a token's three coordinates always describe the same character.
        self.tokens.push(Spanned {
            token,
            line,
            column,
            offset: self.pending_offset,
        });
    }

    /// The position a token starts at, captured before anything is consumed.
    fn mark(&mut self) -> (u32, u32) {
        self.pending_offset = self.at as u64;
        (self.line, self.column)
    }

    fn run(mut self) -> Vec<Spanned> {
        while let Some(byte) = self.peek() {
            let (line, column) = self.mark();
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => self.bump(),
                b'/' if self.peek_at(1) == Some(b'/') => self.line_comment(),
                b'/' if self.peek_at(1) == Some(b'*') => self.block_comment(),
                b'{' => self.delimiter(Token::Open(Delimiter::Brace), line, column),
                b'}' => self.delimiter(Token::Close(Delimiter::Brace), line, column),
                b'(' => self.delimiter(Token::Open(Delimiter::Paren), line, column),
                b')' => self.delimiter(Token::Close(Delimiter::Paren), line, column),
                b'[' => self.delimiter(Token::Open(Delimiter::Bracket), line, column),
                b']' => self.delimiter(Token::Close(Delimiter::Bracket), line, column),
                b'"' => {
                    self.string();
                    self.push(Token::Literal, line, column);
                }
                b'\'' => self.apostrophe(line, column),
                b'r' if matches!(self.peek_at(1), Some(b'"' | b'#')) => {
                    self.raw_prefixed(line, column)
                }
                b'b' if matches!(self.peek_at(1), Some(b'"' | b'\'' | b'r')) => {
                    self.byte_prefixed(line, column);
                }
                b'0'..=b'9' => {
                    self.number();
                    self.push(Token::Literal, line, column);
                }
                _ if is_ident_start(byte) => {
                    let name = self.ident_text();
                    self.push(Token::Ident { name, raw: false }, line, column);
                }
                _ => {
                    self.bump();
                    // Multi-byte characters outside a literal are punctuation this analyzer
                    // has no use for, and emitting one token per scalar keeps the position
                    // arithmetic honest.
                    self.push(Token::Punct(byte as char), line, column);
                }
            }
        }
        self.tokens
    }

    fn delimiter(&mut self, token: Token, line: u32, column: u32) {
        self.bump();
        self.push(token, line, column);
    }

    fn line_comment(&mut self) {
        self.bump_while(|byte| byte != b'\n');
    }

    /// Skips a block comment, counting nesting.
    ///
    /// Rust's block comments nest, so `/* /* */ */` is one comment. Treating the first
    /// `*/` as the end would leave the rest of the file inside a comment that is not there.
    fn block_comment(&mut self) {
        self.bump();
        self.bump();
        let mut depth = 1_usize;
        while depth > 0 {
            match (self.peek(), self.peek_at(1)) {
                (None, _) => return,
                (Some(b'/'), Some(b'*')) => {
                    self.bump();
                    self.bump();
                    depth += 1;
                }
                (Some(b'*'), Some(b'/')) => {
                    self.bump();
                    self.bump();
                    depth -= 1;
                }
                _ => self.bump(),
            }
        }
    }

    /// Skips a normal double-quoted string, honoring backslash escapes.
    fn string(&mut self) {
        self.bump();
        loop {
            match self.peek() {
                None => return,
                Some(b'\\') => {
                    self.bump();
                    self.bump();
                }
                Some(b'"') => {
                    self.bump();
                    return;
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// Reads `r"..."` or `r#"..."#` at any hash depth, having seen the `r`.
    ///
    /// Returns whether it was in fact a raw string. `r` followed by something else is an
    /// ordinary identifier, and `r#name` is a raw identifier.
    fn raw_prefixed(&mut self, line: u32, column: u32) {
        // Look past the `r` and its hashes without consuming, so a raw identifier can fall
        // through to the identifier path unchanged.
        let mut ahead = 1_usize;
        while self.peek_at(ahead) == Some(b'#') {
            ahead += 1;
        }
        if self.peek_at(ahead) != Some(b'"') {
            // `r#type` — a raw identifier, which is never a keyword.
            if ahead == 2 && self.peek_at(2).is_some_and(is_ident_start) {
                self.bump();
                self.bump();
                let name = self.ident_text();
                self.push(Token::Ident { name, raw: true }, line, column);
                return;
            }
            let name = self.ident_text();
            self.push(Token::Ident { name, raw: false }, line, column);
            return;
        }
        let hashes = ahead - 1;
        self.bump();
        for _ in 0..hashes {
            self.bump();
        }
        self.raw_string_body(hashes);
        self.push(Token::Literal, line, column);
    }

    /// Skips a raw string body, having consumed `r` and its hashes but not the quote.
    ///
    /// A raw string has no escapes at all, so the terminator is the only thing to look
    /// for: a quote followed by exactly the opening number of hashes.
    fn raw_string_body(&mut self, hashes: usize) {
        self.bump();
        loop {
            match self.peek() {
                None => return,
                Some(b'"') => {
                    let closes = (0..hashes).all(|ahead| self.peek_at(ahead + 1) == Some(b'#'));
                    self.bump();
                    if closes {
                        for _ in 0..hashes {
                            self.bump();
                        }
                        return;
                    }
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// Reads `b"..."`, `b'x'`, or `br#"..."#`, having seen the `b`.
    fn byte_prefixed(&mut self, line: u32, column: u32) {
        match self.peek_at(1) {
            Some(b'"') => {
                self.bump();
                self.string();
                self.push(Token::Literal, line, column);
            }
            Some(b'\'') => {
                self.bump();
                self.character();
                self.push(Token::Literal, line, column);
            }
            Some(b'r') => {
                let mut ahead = 2_usize;
                while self.peek_at(ahead) == Some(b'#') {
                    ahead += 1;
                }
                if self.peek_at(ahead) != Some(b'"') {
                    let name = self.ident_text();
                    self.push(Token::Ident { name, raw: false }, line, column);
                    return;
                }
                let hashes = ahead - 2;
                self.bump();
                self.bump();
                for _ in 0..hashes {
                    self.bump();
                }
                self.raw_string_body(hashes);
                self.push(Token::Literal, line, column);
            }
            _ => {
                let name = self.ident_text();
                self.push(Token::Ident { name, raw: false }, line, column);
            }
        }
    }

    /// Decides what an apostrophe starts.
    ///
    /// `'a` is a lifetime and `'a'` is a character, and the two are distinguished only by
    /// what follows the name. Reading a lifetime as a character literal would swallow
    /// everything up to the next apostrophe, which in generic-heavy code is most of a
    /// signature.
    fn apostrophe(&mut self, line: u32, column: u32) {
        let is_lifetime = self.peek_at(1).is_some_and(is_ident_start)
            && !self.rest_from(1).is_some_and(|rest| {
                let end = rest
                    .find(|character: char| !is_ident_char_scalar(character))
                    .unwrap_or(rest.len());
                rest[end..].starts_with('\'')
            });
        if is_lifetime {
            self.bump();
            let name = self.ident_text();
            self.push(Token::Lifetime(format!("'{name}")), line, column);
            return;
        }
        self.character();
        self.push(Token::Literal, line, column);
    }

    /// The remaining text starting `ahead` bytes from here, when that lands on a boundary.
    fn rest_from(&self, ahead: usize) -> Option<&'a str> {
        self.text.get(self.at + ahead..)
    }

    /// Skips a character literal, honoring escapes.
    fn character(&mut self) {
        self.bump();
        loop {
            match self.peek() {
                None => return,
                Some(b'\\') => {
                    self.bump();
                    self.bump();
                }
                Some(b'\'') => {
                    self.bump();
                    return;
                }
                // A newline inside what looked like a character literal means it was not
                // one. Stopping keeps a stray apostrophe in a comment-free line from
                // eating the rest of the file.
                Some(b'\n') => return,
                Some(_) => self.bump(),
            }
        }
    }

    fn number(&mut self) {
        self.bump_while(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.');
    }

    fn ident_text(&mut self) -> String {
        let start = self.at;
        self.bump_while(is_ident_char);
        self.text.get(start..self.at).unwrap_or_default().to_owned()
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic() || byte >= 0x80
}

fn is_ident_char(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric() || byte >= 0x80
}

fn is_ident_char_scalar(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(source: &str) -> Vec<String> {
        tokenize(source)
            .into_iter()
            .filter_map(|spanned| spanned.token.name().map(str::to_owned))
            .collect()
    }

    /// The nesting depth the tokens describe, which is what the analyzer relies on.
    fn depth_after(source: &str) -> i32 {
        let mut depth = 0_i32;
        for spanned in tokenize(source) {
            match spanned.token {
                Token::Open(_) => depth += 1,
                Token::Close(_) => depth -= 1,
                _ => {}
            }
        }
        depth
    }

    #[test]
    fn identifiers_and_delimiters_are_read() {
        let tokens = tokenize("fn main() {}");
        assert_eq!(names("fn main() {}"), ["fn", "main"]);
        assert_eq!(tokens[2].token, Token::Open(Delimiter::Paren));
        assert_eq!(tokens[5].token, Token::Close(Delimiter::Brace));
    }

    #[test]
    fn a_line_comment_hides_everything_after_it_including_a_block_opener() {
        assert_eq!(depth_after("fn a() {} // }} /* \n fn b() {}"), 0);
        assert_eq!(
            names("fn a() {} // hidden\nfn b() {}"),
            ["fn", "a", "fn", "b"]
        );
    }

    #[test]
    fn block_comments_nest_the_way_rust_says_they_do() {
        // C does not nest them. Treating the first `*/` as the end would leave the rest of
        // the file inside a comment that is not there.
        assert_eq!(names("/* /* } */ */ fn a() {}"), ["fn", "a"]);
        assert_eq!(depth_after("/* /* { */ */ fn a() {}"), 0);
    }

    #[test]
    fn an_unterminated_comment_stops_rather_than_looping() {
        assert_eq!(names("fn a() {} /* never closed"), ["fn", "a"]);
        assert_eq!(names("fn a() {} /* /* never closed"), ["fn", "a"]);
    }

    #[test]
    fn a_brace_inside_a_string_does_not_count() {
        assert_eq!(depth_after(r#"fn a() { let s = "}}}}"; }"#), 0);
        assert_eq!(depth_after(r#"fn a() { let s = "\""; }"#), 0);
    }

    #[test]
    fn a_raw_string_has_no_escapes_and_closes_only_on_its_own_hash_count() {
        assert_eq!(depth_after(r####"fn a() { let s = r"\"; }"####), 0);
        assert_eq!(depth_after(r####"fn a() { let s = r#"a"b}"#; }"####), 0);
        assert_eq!(depth_after(r####"fn a() { let s = r##"a"#b}"##; }"####), 0);
        assert_eq!(
            names(r####"fn a() { let s = r#"fn hidden() {"#; }"####),
            ["fn", "a", "let", "s"]
        );
    }

    #[test]
    fn byte_strings_and_byte_characters_are_literals_too() {
        assert_eq!(depth_after(r#"fn a() { let s = b"}"; }"#), 0);
        assert_eq!(depth_after(r"fn a() { let c = b'}'; }"), 0);
        assert_eq!(depth_after(r####"fn a() { let s = br#"}"#; }"####), 0);
    }

    #[test]
    fn a_lifetime_is_not_a_character_literal() {
        // Reading `'a` as an unterminated character would swallow the rest of the
        // signature, which in generic-heavy code is most of the file.
        let tokens = tokenize("fn a<'a>(x: &'a str) {}");
        assert_eq!(
            tokens
                .iter()
                .filter_map(|spanned| match &spanned.token {
                    Token::Lifetime(name) => Some(name.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["'a", "'a"]
        );
        assert_eq!(depth_after("fn a<'a>(x: &'a str) { }"), 0);
        assert_eq!(names("fn f<'a, 'b>() {}"), ["fn", "f"]);
    }

    #[test]
    fn a_character_literal_is_not_a_lifetime() {
        assert_eq!(depth_after("fn a() { let c = 'x'; }"), 0);
        assert_eq!(depth_after(r"fn a() { let c = '\''; }"), 0);
        assert_eq!(depth_after(r"fn a() { let c = '}'; }"), 0);
        assert_eq!(depth_after(r"fn a() { let c = '\u{1F600}'; }"), 0);
        assert_eq!(names("fn a() { let c = 'x'; }"), ["fn", "a", "let", "c"]);
    }

    #[test]
    fn a_static_lifetime_reads_as_a_lifetime() {
        assert_eq!(
            tokenize("&'static str")
                .iter()
                .filter_map(|spanned| match &spanned.token {
                    Token::Lifetime(name) => Some(name.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["'static"]
        );
    }

    #[test]
    fn a_raw_identifier_carries_its_name_and_is_never_a_keyword() {
        let tokens = tokenize("let r#fn = 1;");
        let raw = tokens
            .iter()
            .find_map(|spanned| match &spanned.token {
                Token::Ident { name, raw: true } => Some(name.as_str()),
                _ => None,
            })
            .expect("a raw identifier");
        assert_eq!(raw, "fn");
        assert!(
            tokens
                .iter()
                .all(|spanned| spanned.token.keyword() != Some("fn")),
            "`r#fn` names something called `fn`; it does not begin a function"
        );
    }

    #[test]
    fn an_r_that_is_not_a_raw_prefix_is_an_ordinary_identifier() {
        assert_eq!(names("let range = r + 1;"), ["let", "range", "r"]);
        assert_eq!(names("let b = bytes;"), ["let", "b", "bytes"]);
    }

    #[test]
    fn positions_count_scalars_rather_than_bytes() {
        // A column counted in bytes puts every range after the first non-ASCII character
        // in the wrong place.
        let tokens = tokenize("let s = \"héllo\"; let after = 1;");
        let after = tokens
            .iter()
            .find(|spanned| spanned.token.name() == Some("after"))
            .expect("the identifier");
        assert_eq!(after.line, 1);
        assert_eq!(after.column, 22);
    }

    #[test]
    fn lines_advance_and_columns_restart() {
        let tokens = tokenize("fn a() {}\nfn b() {}\n");
        let second = tokens
            .iter()
            .find(|spanned| spanned.token.name() == Some("b"))
            .expect("the identifier");
        assert_eq!((second.line, second.column), (2, 4));
    }

    #[test]
    fn a_number_does_not_split_into_pieces() {
        assert_eq!(names("let x = 1_000u64;"), ["let", "x"]);
        assert_eq!(names("let x = 0xFFu8;"), ["let", "x"]);
        assert_eq!(names("let x = 1.5e10;"), ["let", "x"]);
    }

    #[test]
    fn an_unterminated_string_stops_at_the_end_of_input() {
        assert_eq!(
            names("fn a() { let s = \"never closed"),
            ["fn", "a", "let", "s"]
        );
        assert_eq!(
            names(r####"fn a() { let s = r#"never closed"####),
            ["fn", "a", "let", "s"]
        );
    }

    #[test]
    fn an_empty_source_produces_no_tokens() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   \n\t\n").is_empty());
        assert!(tokenize("// only a comment").is_empty());
    }
}
