//! Tokenizes Go far enough for structural analysis.
//!
//! # Why this is its own lexer
//!
//! Go's grammar is the smallest in this module and shares the brace shape with Java's, but it has one
//! form nothing else here does: a **raw string in backticks**, which honours no escape and spans lines.
//! `` `a"b\` `` is a string containing a quote and a backslash, and reading it any other way leaves both
//! as code. Kotlin's backticks quote an *identifier* and Java has none at all, so a shared lexer would
//! branch on the one construct that matters most.
//!
//! # Semicolon insertion, which a structural analyzer does need
//!
//! It was left out at first, on the reasoning that braces delimit every body and a declaration is found by
//! its keyword. That is wrong, and Go's own grammar says why: a **grouped declaration and a struct field
//! are terminated by the inserted semicolon**, not by a brace. Without it,
//!
//! ```go
//! const ( A = 1
//!         B = 2 )
//! ```
//!
//! has no boundary between `A = 1` and `B`, and the analyzer read the second name as part of the first
//! value. The same held for `Name string` after an embedded field and for an interface's second method.
//!
//! So the rule is implemented as the specification states it: at the end of a line, a semicolon is
//! inserted when the last token was an identifier, a literal, one of `break`, `continue`, `fallthrough`,
//! or `return`, or one of `++`, `--`, `)`, `]`, `}`.
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **a raw string.** It ends only at the next backtick, so one holding `{`, `"`, or `//` must not
//!   unbalance the file or start a comment;
//! - **a rune literal.** `'}'` is a character, and read as punctuation it closes a body that is still
//!   open;
//! - **unterminated everything** stops rather than looping.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or a keyword.
    Ident(String),
    /// A number or a rune literal, reduced to the fact that one was here.
    Literal,
    /// An interpreted or raw string literal, carrying its content.
    ///
    /// Kept because an import's path is a string, and a struct tag —
    /// `` Name string `json:"name"` `` — is where a serialization framework's meaning lives.
    Text(String),
    /// An opening delimiter.
    Open(Delimiter),
    /// A closing delimiter.
    Close(Delimiter),
    /// Any other punctuation, one character at a time.
    Punct(char),
}

impl Token {
    /// The identifier's name, when this is one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Ident(name) => Some(name.as_str()),
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
}

/// Tokenizes Go source.
///
/// Never fails. Malformed input produces whatever tokens can be read and then stops.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Spanned> {
    Lexer::new(source).run()
}

/// Keywords after which a line ending inserts a semicolon.
const BEFORE_INSERTED_SEMICOLON: [&str; 4] = ["break", "continue", "fallthrough", "return"];

struct Lexer {
    characters: Vec<char>,
    at: usize,
    line: u32,
    column: u32,
    /// The last token emitted, which is what decides whether a line ending terminates a statement.
    previous: Option<Token>,
}

impl Lexer {
    fn new(source: &str) -> Self {
        Self {
            characters: source.chars().collect(),
            at: 0,
            line: 1,
            column: 1,
            previous: None,
        }
    }

    fn peek(&self) -> Option<char> {
        self.characters.get(self.at).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.characters.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let character = self.characters.get(self.at).copied()?;
        self.at += 1;
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn matches(&self, expected: &str) -> bool {
        expected
            .chars()
            .enumerate()
            .all(|(ahead, wanted)| self.peek_at(ahead) == Some(wanted))
    }

    fn take(&mut self, count: usize) {
        for _ in 0..count {
            self.bump();
        }
    }

    /// Reports whether a line ending here terminates a statement.
    fn line_ends_statement(&self) -> bool {
        match &self.previous {
            Some(Token::Ident(name)) => {
                // Every identifier, and the four keywords the specification lists. Any other keyword is
                // an identifier to this lexer, and none of them can end a statement.
                !is_keyword(name) || BEFORE_INSERTED_SEMICOLON.contains(&name.as_str())
            }
            Some(Token::Literal | Token::Text(_)) => true,
            Some(Token::Close(_)) => true,
            Some(Token::Punct('+' | '-')) => true,
            _ => false,
        }
    }

    fn run(mut self) -> Vec<Spanned> {
        let mut tokens = Vec::new();
        loop {
            // A line ending is significant, so it is handled here rather than skipped as trivia.
            while let Some(character) = self.peek() {
                if character == '\n' {
                    let (line, column) = (self.line, self.column);
                    self.bump();
                    if self.line_ends_statement() {
                        self.previous = Some(Token::Punct(';'));
                        tokens.push(Spanned {
                            token: Token::Punct(';'),
                            line,
                            column,
                        });
                    }
                } else if character.is_whitespace() {
                    self.bump();
                } else if self.matches("//") || self.matches("/*") {
                    self.skip_trivia();
                } else {
                    break;
                }
            }
            let (line, column) = (self.line, self.column);
            let Some(character) = self.peek() else {
                return tokens;
            };
            let token = match character {
                '{' => {
                    self.bump();
                    Token::Open(Delimiter::Brace)
                }
                '}' => {
                    self.bump();
                    Token::Close(Delimiter::Brace)
                }
                '(' => {
                    self.bump();
                    Token::Open(Delimiter::Paren)
                }
                ')' => {
                    self.bump();
                    Token::Close(Delimiter::Paren)
                }
                '[' => {
                    self.bump();
                    Token::Open(Delimiter::Bracket)
                }
                ']' => {
                    self.bump();
                    Token::Close(Delimiter::Bracket)
                }
                '"' => Token::Text(self.interpreted_string()),
                '`' => Token::Text(self.raw_string()),
                '\'' => {
                    self.rune();
                    Token::Literal
                }
                _ if character.is_ascii_digit() => {
                    self.number();
                    Token::Literal
                }
                _ if is_identifier_start(character) => Token::Ident(self.identifier()),
                _ => {
                    self.bump();
                    Token::Punct(character)
                }
            };
            self.previous = Some(token.clone());
            tokens.push(Spanned {
                token,
                line,
                column,
            });
        }
    }

    /// Skips comments and horizontal whitespace, never a line ending.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(character) if character.is_whitespace() && character != '\n' => {
                    self.bump();
                }
                Some('/') if self.matches("//") => {
                    while self.peek().is_some_and(|found| found != '\n') {
                        self.bump();
                    }
                }
                Some('/') if self.matches("/*") => {
                    self.take(2);
                    while self.peek().is_some() {
                        if self.matches("*/") {
                            self.take(2);
                            break;
                        }
                        self.bump();
                    }
                }
                _ => return,
            }
        }
    }

    /// A `"…"` string, which honours escapes and cannot span a line.
    fn interpreted_string(&mut self) -> String {
        self.bump();
        let mut content = String::new();
        while let Some(character) = self.peek() {
            match character {
                '"' => {
                    self.bump();
                    break;
                }
                '\n' => break,
                '\\' => {
                    self.bump();
                    if let Some(escaped) = self.bump() {
                        content.push(escaped);
                    }
                }
                _ => {
                    content.push(character);
                    self.bump();
                }
            }
        }
        content
    }

    /// A `` `…` `` string, which honours no escape and may span lines.
    ///
    /// A backslash inside one is content, so consuming the character after it — the way an interpreted
    /// string must — would swallow a closing backtick written as `` \` ``.
    fn raw_string(&mut self) -> String {
        self.bump();
        let mut content = String::new();
        while let Some(character) = self.peek() {
            self.bump();
            if character == '`' {
                return content;
            }
            content.push(character);
        }
        content
    }

    /// A rune literal, escapes included.
    ///
    /// Consumed rather than left as punctuation because `'}'` and `'{'` are ordinary runes, and reading
    /// either as a brace moves every following declaration.
    fn rune(&mut self) {
        self.bump();
        while let Some(character) = self.peek() {
            match character {
                '\'' => {
                    self.bump();
                    return;
                }
                '\n' => return,
                '\\' => {
                    self.bump();
                    self.bump();
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    fn number(&mut self) {
        while let Some(character) = self.peek() {
            if character.is_alphanumeric() || character == '_' || character == '.' {
                self.bump();
            } else {
                return;
            }
        }
    }

    fn identifier(&mut self) -> String {
        let mut name = String::new();
        while let Some(character) = self.peek() {
            if is_identifier_continue(character) {
                name.push(character);
                self.bump();
            } else {
                return name;
            }
        }
        name
    }
}

/// Go's keywords, so a line ending after one of them inserts no semicolon.
///
/// Only the ones that can end a line matter, but listing all of them keeps the question local: an
/// identifier that is not here ends a statement, and a keyword that is not in
/// [`BEFORE_INSERTED_SEMICOLON`] does not.
fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "break"
            | "case"
            | "chan"
            | "const"
            | "continue"
            | "default"
            | "defer"
            | "else"
            | "fallthrough"
            | "for"
            | "func"
            | "go"
            | "goto"
            | "if"
            | "import"
            | "interface"
            | "map"
            | "package"
            | "range"
            | "return"
            | "select"
            | "struct"
            | "switch"
            | "type"
            | "var"
    )
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character.is_alphabetic()
}

fn is_identifier_continue(character: char) -> bool {
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

    fn texts(source: &str) -> Vec<String> {
        tokenize(source)
            .into_iter()
            .filter_map(|spanned| match spanned.token {
                Token::Text(content) => Some(content),
                _ => None,
            })
            .collect()
    }

    fn braces_balance(source: &str) -> bool {
        let mut depth = 0_i64;
        for spanned in tokenize(source) {
            match spanned.token {
                Token::Open(Delimiter::Brace) => depth += 1,
                Token::Close(Delimiter::Brace) => depth -= 1,
                _ => {}
            }
        }
        depth == 0
    }

    #[test]
    fn a_raw_string_holds_braces_quotes_and_comment_markers() {
        assert_eq!(
            texts("var q = `SELECT \"{a}\" // not a comment`"),
            ["SELECT \"{a}\" // not a comment"]
        );
        assert!(braces_balance(
            "func f() { q := `{` ; _ = q }\nfunc after() { }"
        ));
        assert_eq!(
            names("func f() { q := `{` ; _ = q }\nfunc after() { }"),
            ["func", "f", "q", "_", "q", "func", "after"]
        );
    }

    #[test]
    fn a_raw_string_may_span_lines_and_keeps_its_backslashes() {
        assert_eq!(texts("var q = `one\ntwo\\n`"), ["one\ntwo\\n"]);
        // A backslash is content, so it must not consume the closing backtick.
        assert_eq!(
            names("var q = `a\\` ; var after = 1"),
            ["var", "q", "var", "after"]
        );
    }

    #[test]
    fn a_rune_holding_a_brace_is_one_token() {
        assert!(braces_balance(
            "func f() { c := '}' ; _ = c }\nfunc after() { }"
        ));
        assert_eq!(
            names("func f() { c := '}' ; _ = c }"),
            ["func", "f", "c", "_", "c"]
        );
    }

    #[test]
    fn an_interpreted_string_honours_escapes_and_stops_at_a_newline() {
        assert_eq!(texts(r#"var s = "a\"b""#), ["a\"b"]);
        assert_eq!(
            names("var s = \"open\nvar after = 1"),
            ["var", "s", "var", "after"]
        );
    }

    #[test]
    fn a_struct_tag_is_kept() {
        // Where a serialization framework's meaning lives, which is why the content is carried.
        assert_eq!(
            texts("type A struct {\n\tName string `json:\"name\"`\n}"),
            ["json:\"name\""]
        );
    }

    #[test]
    fn a_block_comment_closes_at_the_first_terminator() {
        assert_eq!(names("/* /* */ func after() { }"), ["func", "after"]);
    }

    #[test]
    fn unterminated_input_stops_rather_than_looping() {
        assert!(names("/* open").is_empty());
        assert_eq!(names("var q = `open"), ["var", "q"]);
        assert_eq!(names("func f() { c := 'open"), ["func", "f", "c"]);
    }

    #[test]
    fn a_position_is_the_first_character_of_the_token() {
        let found: Vec<(String, u32, u32)> = tokenize("type A struct {\n\tName string\n}")
            .into_iter()
            .filter_map(|spanned| {
                spanned
                    .token
                    .name()
                    .map(|name| (name.to_owned(), spanned.line, spanned.column))
            })
            .collect();
        assert_eq!(
            found,
            [
                ("type".to_owned(), 1, 1),
                ("A".to_owned(), 1, 6),
                ("struct".to_owned(), 1, 8),
                ("Name".to_owned(), 2, 2),
                ("string".to_owned(), 2, 7),
            ]
        );
    }
}
