//! Tokenizes Java far enough for structural analysis.
//!
//! # Why this is not the Kotlin lexer with a flag
//!
//! The argument [`super::kotlin_lexer`] makes about Rust applies here, and Java is the closest case
//! yet — same platform, same annotation syntax, same brace-and-bracket shape. It is still a different
//! grammar in the places a lexer cannot get wrong:
//!
//! - **block comments do not nest.** `/* /* */ */` closes at the first `*/` in Java and at the second
//!   in Kotlin, so the trailing `*/` is code. Reading it Kotlin's way would swallow the rest of the
//!   file and find no declarations after it;
//! - **there are no string templates.** `"${a}"` is four ordinary characters in Java. Scanning for a
//!   template's nested braces would be scanning for something the language cannot produce;
//! - **there are no backtick identifiers**, so an identifier is never exempt from being a keyword and
//!   [`Token`] carries no flag for it;
//! - **a text block is opened by three quotes and a line terminator**, not by three quotes alone.
//!   `""` followed by `"x"` is an empty string next to a string, and treating the three quotes as a
//!   text-block opener would read the rest of the file as its content.
//!
//! A lexer branching on a language flag in each of those places would make a Kotlin fix a Java change.
//! What is shared is the contract they produce, and that is [`super::FileAnalysis`].
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **unterminated everything.** An unclosed string, character literal, comment, or text block at end
//!   of input stops rather than looping. Refusing to produce anything for a file with one unclosed
//!   quote would make the common case the failing case;
//! - **escapes.** `"\""` is a string containing one quote, and `'\''` is a character literal. Missing
//!   that ends the token early and leaves the rest of the line reading as code;
//! - **`$` is an identifier character.** Generated and inner-class names use it, and a lexer that
//!   treated it as punctuation would split `Outer$Inner` into three tokens.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or a keyword. Java has no way to write an identifier that is exempt from being
    /// read as a keyword, so unlike Kotlin's there is no flag here and the parser decides by name.
    Ident(String),
    /// A number or a character literal, reduced to the fact that one was here.
    Literal,
    /// A string literal or text block, carrying its content.
    ///
    /// Kept for the same reason Kotlin keeps it: a framework's meaning is often inside the string. A
    /// route is `@GetMapping("/api/x")`, and an annotation whose argument reads `<literal>` tells a
    /// framework analyzer that a string was there and not which one.
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

/// Tokenizes Java source.
///
/// Never fails. Malformed input produces whatever tokens can be read and then stops.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Spanned> {
    Lexer::new(source).run()
}

struct Lexer {
    characters: Vec<char>,
    at: usize,
    line: u32,
    column: u32,
}

impl Lexer {
    fn new(source: &str) -> Self {
        Self {
            characters: source.chars().collect(),
            at: 0,
            line: 1,
            column: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.characters.get(self.at).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.characters.get(self.at + ahead).copied()
    }

    /// Consumes one character, keeping the line and column current.
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

    fn run(mut self) -> Vec<Spanned> {
        let mut tokens = Vec::new();
        loop {
            self.skip_trivia();
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
                // A text block opens with three quotes *and* a line terminator. Anything else starting
                // with a quote is an ordinary string, including `""` — which is the empty one.
                '"' if self.opens_text_block() => match self.text_block() {
                    Some(content) => Token::Text(content),
                    None => return tokens,
                },
                '"' => Token::Text(self.string()),
                '\'' => {
                    self.character_literal();
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
            tokens.push(Spanned {
                token,
                line,
                column,
            });
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(character) if character.is_whitespace() => {
                    self.bump();
                }
                Some('/') if self.matches("//") => {
                    while let Some(character) = self.peek() {
                        if character == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some('/') if self.matches("/*") => self.block_comment(),
                _ => return,
            }
        }
    }

    /// Consumes a block comment, which in Java does not nest.
    ///
    /// `/* /* */` is a closed comment and the `/*` inside it is content. A nesting reader would still
    /// be looking for a second `*/` and would consume every declaration after it.
    fn block_comment(&mut self) {
        self.take(2);
        while self.peek().is_some() {
            if self.matches("*/") {
                self.take(2);
                return;
            }
            self.bump();
        }
        // Unterminated at end of input. Consumed to the end, which is what the source says.
    }

    /// Reports whether three quotes here open a text block rather than an empty string.
    ///
    /// A text block's opening delimiter is three quotes followed by optional whitespace and then a line
    /// terminator. `""" x` is not one, and `""` followed by `"x"` is two ordinary strings.
    fn opens_text_block(&self) -> bool {
        if !self.matches("\"\"\"") {
            return false;
        }
        let mut ahead = 3;
        while let Some(character) = self.peek_at(ahead) {
            match character {
                '\n' => return true,
                // Carriage return, and horizontal whitespace, are permitted between the delimiter and
                // the line terminator.
                '\r' | ' ' | '\t' => ahead += 1,
                _ => return false,
            }
        }
        false
    }

    /// Consumes a text block and returns its content, or `None` when it is unterminated.
    ///
    /// The content is returned as written, without the incidental-indentation stripping the language
    /// applies. A framework analyzer reading a route out of a text block is reading one line of it, and
    /// re-implementing the stripping rules would be a second place for them to be wrong.
    fn text_block(&mut self) -> Option<String> {
        self.take(3);
        let mut content = String::new();
        loop {
            if self.matches("\"\"\"") {
                self.take(3);
                return Some(content);
            }
            match self.peek()? {
                // An escape inside a text block still escapes, so `\"""` does not close it.
                '\\' => {
                    self.bump();
                    if let Some(escaped) = self.bump() {
                        content.push(escaped);
                    }
                }
                _ => content.push(self.bump()?),
            }
        }
    }

    /// Consumes a string literal and returns its content.
    ///
    /// Stops at a newline as well as at the closing quote: a single-line string cannot span one, and
    /// running past it would consume the rest of the file looking for a quote that is not coming.
    fn string(&mut self) -> String {
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

    /// Consumes a character literal, escapes included.
    fn character_literal(&mut self) {
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

    /// Consumes a numeric literal.
    ///
    /// Every radix, digit separator, and type suffix Java writes is consumed by the same rule: a run of
    /// alphanumerics, dots, and underscores. The analyzer needs only that a literal was here, so
    /// distinguishing `0x1_0L` from `1.0e3f` would be work with no reader.
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

/// Java's identifier start: a letter, `_`, or `$`.
fn is_identifier_start(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphabetic()
}

/// Java's identifier continuation, which adds digits.
fn is_identifier_continue(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
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

    #[test]
    fn a_block_comment_closes_at_the_first_terminator() {
        // Java's do not nest. Reading this Kotlin's way leaves the lexer inside a comment looking for a
        // second `*/`, and every declaration after it disappears.
        assert_eq!(names("/* /* */ int after;"), ["int", "after"]);
    }

    #[test]
    fn a_dollar_sign_is_part_of_an_identifier() {
        assert_eq!(names("Outer$Inner x;"), ["Outer$Inner", "x"]);
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        assert_eq!(texts(r#" "a\"b" "#), ["a\"b"]);
        assert_eq!(names(r#" "a\"b" after "#), ["after"]);
    }

    #[test]
    fn a_string_stops_at_a_newline_rather_than_running_to_the_next_quote() {
        // An unterminated string on one line must not consume the next line's code looking for a quote.
        assert_eq!(
            names("String a = \"open\nint after;"),
            ["String", "a", "int", "after"]
        );
    }

    #[test]
    fn three_quotes_open_a_text_block_only_before_a_line_terminator() {
        assert_eq!(texts("\"\"\"\nhello\n\"\"\""), ["\nhello\n"]);
        // An empty string beside another string, not a text block holding `x`.
        assert_eq!(texts("\"\" \"x\""), ["", "x"]);
        // Three quotes with content on the same line is not a text block opener either.
        assert_eq!(texts("\"\"\"x\""), ["", "x"]);
    }

    #[test]
    fn a_template_is_ordinary_text() {
        // Java has no string templates, so there are no nested braces to balance here.
        assert_eq!(texts("\"${a}\""), ["${a}"]);
        assert_eq!(names("\"${a}\" after"), ["after"]);
    }

    #[test]
    fn a_character_literal_holding_a_quote_is_one_token() {
        assert_eq!(
            names("char c = '\\'' ; int after;"),
            ["char", "c", "int", "after"]
        );
    }

    #[test]
    fn an_unterminated_comment_string_or_text_block_stops_rather_than_looping() {
        // Each of these is a file somebody is midway through typing.
        assert!(names("/* open").is_empty());
        assert_eq!(names("int a; /* open"), ["int", "a"]);
        assert_eq!(names("String s = \"\"\"\nopen"), ["String", "s"]);
        assert_eq!(names("char c = 'open"), ["char", "c"]);
    }

    #[test]
    fn a_number_consumes_its_radix_separators_and_suffix() {
        assert_eq!(
            names("long a = 0x1_0L; float b = 1.0e3f;"),
            ["long", "a", "float", "b"]
        );
    }

    #[test]
    fn a_position_is_the_first_character_of_the_token() {
        let tokens = tokenize("class A {\n  void b() {}\n}");
        let found: Vec<(String, u32, u32)> = tokens
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
                ("class".to_owned(), 1, 1),
                ("A".to_owned(), 1, 7),
                ("void".to_owned(), 2, 3),
                ("b".to_owned(), 2, 8),
            ]
        );
    }

    #[test]
    fn annotations_and_generics_are_punctuation_the_parser_reads() {
        let tokens = tokenize("@GetMapping(\"/x\") List<Map<String, Integer>> f();");
        assert!(
            tokens
                .first()
                .is_some_and(|first| first.token.is_punct('@'))
        );
        assert_eq!(
            names("@GetMapping(\"/x\") void f();"),
            ["GetMapping", "void", "f"]
        );
    }
}
