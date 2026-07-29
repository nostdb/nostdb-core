//! Tokenizes C and C++ far enough for structural analysis.
//!
//! One lexer for both, on the same reasoning [`super::typescript_lexer`] gives about JavaScript: a C file
//! is a C++ file that declares no class. `class`, `namespace`, and `template` simply do not appear in one,
//! and reading for them costs nothing when they are absent.
//!
//! # The preprocessor is a token, not punctuation
//!
//! `#include <vector>` is the import statement of this language, and its argument is a header name that
//! only *looks* like a comparison. Lexed as punctuation it becomes `#`, `include`, `<`, `vector`, `>`, and
//! reassembling a path from that means deciding — in the analyzer, per call site — whether a `<` opened a
//! header name or a template argument list.
//!
//! So a directive line is one [`Token::Directive`] carrying its name and the rest of the line as written.
//! That keeps the decision in one place and leaves the code *between* directives tokenized normally.
//!
//! A conditional's branches are both read. `#ifdef` cannot be evaluated without the build's flags, and a
//! declaration inside a branch is a declaration the source contains — so both arms contribute, and a graph
//! may hold two declarations that no single build compiles. Reading one arm would mean picking it, and
//! reading neither would lose whole files of platform-specific code.
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **a raw string.** C++'s `R"sql(SELECT "x")sql"` ends at its own delimiter, so one holding a quote or a
//!   brace must not unbalance the file;
//! - **a character literal.** `'}'` read as punctuation closes a body that is still open;
//! - **a line continuation.** A `\` at the end of a line joins it to the next, which is how every
//!   multi-line macro is written;
//! - **unterminated everything** stops rather than looping.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or a keyword.
    Ident(String),
    /// A number or a character literal, reduced to the fact that one was here.
    Literal,
    /// A string literal, ordinary or raw, carrying its content.
    Text(String),
    /// A preprocessor directive: its name, and the rest of its logical line as written.
    Directive {
        /// The directive's name, without the `#`.
        name: String,
        /// Everything after the name, as written: the source's spacing is kept, each line
        /// continuation becomes one space, and the result is trimmed.
        rest: String,
    },
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

/// Tokenizes C or C++ source.
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
    /// Whether nothing but whitespace has been seen on this line, which is where a directive may start.
    at_line_start: bool,
}

impl Lexer {
    fn new(source: &str) -> Self {
        Self {
            characters: source.chars().collect(),
            at: 0,
            line: 1,
            column: 1,
            at_line_start: true,
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

    fn run(mut self) -> Vec<Spanned> {
        let mut tokens = Vec::new();
        loop {
            self.skip_trivia();
            let (line, column) = (self.line, self.column);
            let Some(character) = self.peek() else {
                return tokens;
            };
            let token = match character {
                '#' if self.at_line_start => self.directive(),
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
                // A raw string, and its prefixes: `R"…"`, `LR"…"`, `u8R"…"`.
                _ if self.opens_raw_string() => Token::Text(self.raw_string()),
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
            self.at_line_start = false;
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
                Some('\n') => {
                    self.bump();
                    self.at_line_start = true;
                }
                Some(character) if character.is_whitespace() => {
                    self.bump();
                }
                Some('/') if self.matches("//") => {
                    // A `\` at the end of a line continues even a line comment.
                    loop {
                        match self.peek() {
                            None | Some('\n') => break,
                            Some('\\') if self.peek_at(1) == Some('\n') => {
                                self.bump();
                                self.bump();
                            }
                            _ => {
                                self.bump();
                            }
                        }
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
                Some('\\') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                _ => return,
            }
        }
    }

    /// One preprocessor directive, as its name and the rest of its logical line.
    ///
    /// The line continues through every `\` at a line ending, which is how a multi-line macro is written.
    fn directive(&mut self) -> Token {
        self.bump();
        // `#  include` is legal, and so is `# 1 "file.c"` from a preprocessed source.
        while self
            .peek()
            .is_some_and(|found| found == ' ' || found == '\t')
        {
            self.bump();
        }
        let mut name = String::new();
        while self.peek().is_some_and(is_identifier_continue) {
            if let Some(character) = self.bump() {
                name.push(character);
            }
        }
        let mut rest = String::new();
        loop {
            match self.peek() {
                None | Some('\n') => break,
                Some('\\') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                    rest.push(' ');
                }
                // A comment ends the directive's text rather than becoming part of it.
                Some('/') if self.matches("//") || self.matches("/*") => break,
                _ => {
                    if let Some(character) = self.bump() {
                        rest.push(character);
                    }
                }
            }
        }
        Token::Directive {
            name,
            rest: rest.trim().to_owned(),
        }
    }

    /// Reports whether a raw string literal starts here, prefix included.
    fn opens_raw_string(&self) -> bool {
        for ahead in 0..3 {
            if self.peek_at(ahead) == Some('R') && self.peek_at(ahead + 1) == Some('"') {
                // Everything before the `R` must be a prefix letter, not the tail of an identifier.
                return (0..ahead)
                    .all(|before| matches!(self.peek_at(before), Some('L' | 'u' | 'U' | '8')))
                    && (ahead == 0
                        || self
                            .at
                            .checked_sub(1)
                            .and_then(|index| self.characters.get(index))
                            .is_none_or(|found| !is_identifier_continue(*found)));
            }
        }
        false
    }

    /// A C++ raw string, `R"delim(…)delim"`, which ends only at its own delimiter.
    fn raw_string(&mut self) -> String {
        while self.peek().is_some_and(|found| found != '"') {
            self.bump();
        }
        self.bump();
        let mut delimiter = String::new();
        while self.peek().is_some_and(|found| found != '(') {
            if let Some(character) = self.bump() {
                delimiter.push(character);
            }
        }
        self.bump();
        let closing = format!("){delimiter}\"");
        let mut content = String::new();
        loop {
            if self.peek().is_none() {
                return content;
            }
            if self.matches(&closing) {
                self.take(closing.chars().count());
                return content;
            }
            if let Some(character) = self.bump() {
                content.push(character);
            }
        }
    }

    /// An ordinary string, which honours escapes and does not span a line.
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

    fn directives(source: &str) -> Vec<(String, String)> {
        tokenize(source)
            .into_iter()
            .filter_map(|spanned| match spanned.token {
                Token::Directive { name, rest } => Some((name, rest)),
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
    fn a_directive_is_one_token_carrying_its_line() {
        // `<vector>` only looks like a comparison. Lexed as punctuation, reassembling a path means deciding
        // per call site whether a `<` opened a header name or a template argument list.
        assert_eq!(
            directives("#include <vector>\n#include \"local.h\"\n#define MAX 10\n"),
            [
                ("include".to_owned(), "<vector>".to_owned()),
                ("include".to_owned(), "\"local.h\"".to_owned()),
                ("define".to_owned(), "MAX 10".to_owned()),
            ]
        );
    }

    #[test]
    fn a_directive_may_be_written_with_space_after_the_hash() {
        assert_eq!(
            directives("#  include <a.h>\n"),
            [("include".to_owned(), "<a.h>".to_owned())]
        );
    }

    #[test]
    fn a_multiline_macro_is_one_directive() {
        assert_eq!(
            directives("#define TWO_LINES(a) \\\n    do { a; } \\\n    while (0)\nint after;"),
            [(
                "define".to_owned(),
                "TWO_LINES(a)      do { a; }      while (0)".to_owned()
            )]
        );
        assert_eq!(names("#define M \\\n  x\nint after;"), ["int", "after"]);
    }

    #[test]
    fn a_hash_that_is_not_at_a_line_start_is_punctuation() {
        // Stringification and concatenation inside a macro body, which is not a directive of its own.
        let tokens = tokenize("int a = b # c;");
        assert!(
            tokens.iter().any(|held| held.token == Token::Punct('#')),
            "{tokens:?}"
        );
    }

    #[test]
    fn a_raw_string_ends_at_its_own_delimiter() {
        assert_eq!(
            texts("auto q = R\"sql(SELECT \"x\" FROM t)sql\";"),
            ["SELECT \"x\" FROM t"]
        );
        assert!(braces_balance(
            "void f() { auto q = R\"(})\"; }\nvoid after() { }"
        ));
        assert_eq!(
            names("void f() { auto q = R\"(})\"; }\nvoid after() { }"),
            ["void", "f", "auto", "q", "void", "after"]
        );
    }

    #[test]
    fn a_raw_string_prefix_is_recognised_and_an_identifier_ending_in_r_is_not() {
        assert_eq!(texts("auto a = LR\"(x)\";"), ["x"]);
        // `myR` is a name, and the `"` after it opens an ordinary string.
        assert_eq!(names("auto b = myR;"), ["auto", "b", "myR"]);
    }

    #[test]
    fn a_character_literal_holding_a_brace_is_one_token() {
        assert!(braces_balance(
            "void f() { char c = '}'; }\nvoid after() { }"
        ));
        assert_eq!(
            names("void f() { char c = '}'; }"),
            ["void", "f", "char", "c"]
        );
    }

    #[test]
    fn a_block_comment_closes_at_the_first_terminator() {
        assert_eq!(names("/* /* */ int after;"), ["int", "after"]);
    }

    #[test]
    fn a_line_comment_continues_through_a_backslash() {
        // A rule people forget, and the reason a declaration can vanish: the second line is still comment.
        assert_eq!(
            names("// one \\\nint hidden;\nint after;"),
            ["int", "after"]
        );
    }

    #[test]
    fn unterminated_input_stops_rather_than_looping() {
        assert!(names("/* open").is_empty());
        assert_eq!(names("auto q = R\"x(open"), ["auto", "q"]);
        assert_eq!(names("char c = 'open"), ["char", "c"]);
    }

    #[test]
    fn a_position_is_the_first_character_of_the_token() {
        let found: Vec<(String, u32, u32)> = tokenize("class A {\n  void b();\n};")
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
}
