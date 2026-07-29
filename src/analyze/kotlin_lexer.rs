//! Tokenizes Kotlin far enough for structural analysis.
//!
//! # Why this is not the Rust lexer with a flag
//!
//! The two share a shape — identifiers, literals, brackets, punctuation — and almost nothing else.
//! Kotlin nests block comments, has raw strings delimited by three quotes, allows an identifier to be
//! written in backticks, and puts arbitrary expressions inside string templates. Rust has lifetimes,
//! raw identifiers written `r#name`, and the `'` ambiguity between a lifetime and a character.
//!
//! A single lexer taking a language flag would branch in every one of those places, and a change made
//! for one language would be a change to the other's tokenizer. Two languages are two grammars; what
//! must not be duplicated is the analysis contract they produce, and [`super::FileAnalysis`] is shared.
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **nested block comments.** `/* /* */ */` closes once in Kotlin, not twice. Reading it Rust's way
//!   would treat the rest of the file as code and find declarations inside a comment;
//! - **string templates.** `"${a[0]}"` and `"${if (x) "y" else "z"}"` contain brackets, braces, and
//!   strings *inside* a string. Losing brace balance there moves every following declaration into the
//!   wrong scope, which is worse than missing one;
//! - **raw strings.** `"""..."""` ends only at three quotes, and a lone `"` inside it is content. A
//!   raw string holding `{` is otherwise an unbalanced brace;
//! - **backtick identifiers.** `` fun `class`() `` declares a function named `class`. Treated as a
//!   keyword it would begin a class declaration;
//! - **unterminated everything.** An unclosed string, comment, or backtick at end of input must stop
//!   rather than loop. Refusing to produce anything for a file with one unclosed quote would make the
//!   common case the failing case.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or keyword. A backtick-quoted one carries its name without the backticks.
    Ident {
        /// The name.
        name: String,
        /// Whether it was written in backticks, which makes it never a keyword.
        quoted: bool,
    },
    /// A literal of any kind, reduced to the fact that one was here.
    Literal,
    /// An opening delimiter.
    Open(Delimiter),
    /// A closing delimiter.
    Close(Delimiter),
    /// Any other punctuation, one character at a time.
    Punct(char),
}

impl Token {
    /// The identifier's name, when this is one that was not written in backticks.
    ///
    /// A quoted identifier is deliberately excluded from keyword matching: `` `fun` `` names something
    /// called `fun` and does not begin a function.
    #[must_use]
    pub fn keyword(&self) -> Option<&str> {
        match self {
            Self::Ident {
                name,
                quoted: false,
            } => Some(name.as_str()),
            _ => None,
        }
    }

    /// The identifier's name, quoted or not.
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
}

/// Tokenizes Kotlin source.
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
                '"' => {
                    self.string();
                    Token::Literal
                }
                '\'' => {
                    self.character_literal();
                    Token::Literal
                }
                '`' => match self.quoted_identifier() {
                    Some(name) => Token::Ident { name, quoted: true },
                    // Unterminated at end of input. Stopping beats emitting an identifier whose
                    // name is the rest of the file.
                    None => return tokens,
                },
                _ if character.is_ascii_digit() => {
                    self.number();
                    Token::Literal
                }
                _ if is_identifier_start(character) => Token::Ident {
                    name: self.identifier(),
                    quoted: false,
                },
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

    /// Whitespace and comments, including nested block comments.
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

    /// A block comment, which nests in Kotlin.
    ///
    /// Depth-counted rather than scanned for the first `*/`. `/* /* */ */` is one comment, and reading
    /// it as two would leave the trailing `*/` as code and everything after the inner close treated as
    /// declarations inside a comment.
    fn block_comment(&mut self) {
        self.take(2);
        let mut depth = 1_u32;
        while depth > 0 {
            if self.peek().is_none() {
                // Unterminated at end of input. The file ends inside a comment, which is a file
                // somebody is still typing rather than an error worth refusing.
                return;
            }
            if self.matches("/*") {
                self.take(2);
                depth += 1;
            } else if self.matches("*/") {
                self.take(2);
                depth -= 1;
            } else {
                self.bump();
            }
        }
    }

    /// A string, raw or not, including any template expressions inside it.
    fn string(&mut self) {
        if self.matches("\"\"\"") {
            self.raw_string();
            return;
        }
        self.bump();
        while let Some(character) = self.peek() {
            match character {
                '\\' => {
                    self.take(2);
                }
                '"' => {
                    self.bump();
                    return;
                }
                '\n' => {
                    // A newline ends an unterminated single-quoted string. Kotlin does not allow one
                    // to span lines, so continuing would swallow the rest of the file.
                    return;
                }
                '$' if self.peek_at(1) == Some('{') => self.template(),
                _ => {
                    self.bump();
                }
            }
        }
    }

    /// A raw string, which ends at three quotes and holds a lone quote as content.
    fn raw_string(&mut self) {
        self.take(3);
        loop {
            if self.peek().is_none() {
                return;
            }
            if self.matches("\"\"\"") {
                self.take(3);
                // Kotlin allows more than three closing quotes; the last three close it and any
                // extras belong to the content. Consuming the run keeps a following `"` from opening
                // a new string.
                while self.peek() == Some('"') {
                    self.bump();
                }
                return;
            }
            if self.peek() == Some('$') && self.peek_at(1) == Some('{') {
                self.template();
                continue;
            }
            self.bump();
        }
    }

    /// A `${...}` template expression, which may contain braces and strings of its own.
    ///
    /// Brace-counted, and it recurses through `string` for a nested string, so
    /// `"${if (x) "}" else ""}"` closes where Kotlin closes it rather than at the `}` inside the inner
    /// string. Losing this moves every following declaration into the wrong scope.
    fn template(&mut self) {
        self.take(2);
        let mut depth = 1_u32;
        while depth > 0 {
            let Some(character) = self.peek() else {
                return;
            };
            match character {
                '{' => {
                    self.bump();
                    depth += 1;
                }
                '}' => {
                    self.bump();
                    depth -= 1;
                }
                '"' => self.string(),
                '\'' => self.character_literal(),
                '/' if self.matches("/*") => self.block_comment(),
                '/' if self.matches("//") => {
                    while let Some(inner) = self.peek() {
                        if inner == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    fn character_literal(&mut self) {
        self.bump();
        while let Some(character) = self.peek() {
            match character {
                '\\' => {
                    self.take(2);
                }
                '\'' => {
                    self.bump();
                    return;
                }
                '\n' => return,
                _ => {
                    self.bump();
                }
            }
        }
    }

    /// An identifier in backticks, or `None` when the closing backtick never arrives.
    fn quoted_identifier(&mut self) -> Option<String> {
        self.bump();
        let mut name = String::new();
        while let Some(character) = self.peek() {
            match character {
                '`' => {
                    self.bump();
                    return Some(name);
                }
                '\n' => return None,
                _ => {
                    name.push(character);
                    self.bump();
                }
            }
        }
        None
    }

    fn identifier(&mut self) -> String {
        let mut name = String::new();
        while let Some(character) = self.peek() {
            if !is_identifier_continue(character) {
                break;
            }
            name.push(character);
            self.bump();
        }
        name
    }

    /// A numeric literal, including underscores, hex, a decimal point, an exponent, and a suffix.
    ///
    /// Read as one token rather than several because `1.0` split at the dot would leave a `.` that the
    /// item reader treats as a qualified-name separator.
    fn number(&mut self) {
        while let Some(character) = self.peek() {
            let next = self.peek_at(1);
            let continues = character.is_ascii_alphanumeric()
                || character == '_'
                || (character == '.' && next.is_some_and(|found| found.is_ascii_digit()))
                || ((character == '+' || character == '-')
                    && self
                        .characters
                        .get(self.at.wrapping_sub(1))
                        .is_some_and(|previous| *previous == 'e' || *previous == 'E'));
            if !continues {
                return;
            }
            self.bump();
        }
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

    fn kinds(source: &str) -> Vec<Token> {
        tokenize(source)
            .into_iter()
            .map(|held| held.token)
            .collect()
    }

    fn names(source: &str) -> Vec<String> {
        tokenize(source)
            .into_iter()
            .filter_map(|held| held.token.name().map(str::to_owned))
            .collect()
    }

    /// Every brace the tokens report, as a running depth. Zero at the end means balanced.
    fn depth(source: &str) -> i32 {
        let mut at = 0;
        for held in tokenize(source) {
            match held.token {
                Token::Open(Delimiter::Brace) => at += 1,
                Token::Close(Delimiter::Brace) => at -= 1,
                _ => {}
            }
        }
        at
    }

    #[test]
    fn a_declaration_reads_as_keywords_and_names() {
        assert_eq!(
            names("class Server(val port: Int)"),
            ["class", "Server", "val", "port", "Int"]
        );
    }

    #[test]
    fn a_block_comment_nests() {
        // Rust's rule closes at the first `*/`, which would leave ` */ class Leaked` as code.
        assert_eq!(names("/* /* inner */ */ class Kept"), ["class", "Kept"]);
        assert_eq!(depth("/* /* { */ */ class Kept {}"), 0);
    }

    #[test]
    fn a_line_comment_ends_at_the_newline_and_not_before() {
        assert_eq!(names("// class Ignored\nclass Kept"), ["class", "Kept"]);
    }

    #[test]
    fn a_template_expression_keeps_the_brace_balance() {
        // The `}` closing the template is the template's, not the class body's.
        assert_eq!(depth(r#"class A { fun f() { val s = "${1 + 2}" } }"#), 0);
        assert_eq!(depth(r#"class A { val s = "${a[0]}" }"#), 0);
    }

    #[test]
    fn a_string_inside_a_template_hides_its_own_braces() {
        // This is the case a brace counter that did not recurse into the inner string gets wrong: the
        // `}` inside `"}"` would close the template early and leave the real one closing the class.
        let source = "class A { val s = \"${ if (x) \"}\" else \"\" }\" }";
        assert_eq!(depth(source), 0, "{:?}", kinds(source));
        // A template's contents are part of the literal and are not tokenized. That is the choice
        // rather than an omission: nothing can be *declared* inside a string, so emitting `if` and
        // `else` there would put keywords where no declaration can be and buy nothing.
        //
        // What it costs is stated because it is real: a reference written inside a template — say
        // `"${server.port}"` — is invisible to this lexer, so an edge that could have been drawn from
        // it will not be. Recovering that means tokenizing template expressions as code, and it is
        // not needed for declarations.
        assert_eq!(names(source), ["class", "A", "val", "s"]);
    }

    #[test]
    fn a_raw_string_holds_a_lone_quote_and_a_brace() {
        assert_eq!(depth("class A { val s = \"\"\"a \" { b\"\"\" }"), 0);
        assert_eq!(names("val s = \"\"\"class Nope\"\"\""), ["val", "s"]);
    }

    #[test]
    fn a_raw_string_closed_by_four_quotes_does_not_open_another() {
        // The last three close it and the extra is content. Consuming only three would leave a `"`
        // that opens a string running to the end of the file.
        let source = "val s = \"\"\"a\"\"\"\"\nclass Kept";
        assert_eq!(names(source), ["val", "s", "class", "Kept"], "{source:?}");
    }

    #[test]
    fn a_backtick_identifier_is_never_a_keyword() {
        let tokens = tokenize("fun `class`() {}");
        assert_eq!(tokens[1].token.name(), Some("class"));
        assert_eq!(
            tokens[1].token.keyword(),
            None,
            "a quoted name does not begin a declaration"
        );
        assert_eq!(tokens[0].token.keyword(), Some("fun"));
    }

    #[test]
    fn a_number_is_one_token_so_its_dot_is_not_a_separator() {
        assert_eq!(kinds("1.0"), [Token::Literal]);
        assert_eq!(kinds("0xFF_u8"), [Token::Literal]);
        assert_eq!(kinds("1e-9"), [Token::Literal]);
        // And a real qualified name still separates.
        assert_eq!(names("a.b"), ["a", "b"]);
    }

    #[test]
    fn a_character_literal_holding_a_quote_or_brace_is_one_token() {
        assert_eq!(kinds(r"'\''"), [Token::Literal]);
        assert_eq!(depth("class A { val c = '}' }"), 0);
    }

    #[test]
    fn positions_are_one_based_and_survive_a_template() {
        let tokens = tokenize("class A {\n    val s = \"${x}\"\n}");
        let last = tokens.last().expect("a closing brace");
        assert_eq!(last.token, Token::Close(Delimiter::Brace));
        assert_eq!((last.line, last.column), (3, 1));
    }

    #[test]
    fn malformed_input_stops_rather_than_loops() {
        // Each of these ends inside something unterminated. What matters is that tokenizing returns.
        for source in [
            "val s = \"unterminated",
            "val s = \"\"\"unterminated",
            "/* unterminated",
            "/* /* unterminated",
            "val s = \"${unterminated",
            "fun `unterminated",
            "val c = 'unterminated",
            "\\",
        ] {
            let _ = tokenize(source);
        }
    }

    #[test]
    fn an_annotation_is_punctuation_and_a_name() {
        assert_eq!(
            kinds("@Test"),
            [
                Token::Punct('@'),
                Token::Ident {
                    name: "Test".to_owned(),
                    quoted: false
                }
            ]
        );
    }
}
