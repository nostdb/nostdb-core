//! Tokenizes TypeScript and JavaScript far enough for structural analysis.
//!
//! One lexer for both, because they are one grammar with a superset: every JavaScript file is a
//! TypeScript file that declares no types. That is not the case for the other pairs in this module —
//! Java and Kotlin share a platform and not a grammar — so this is the one place a shared lexer is the
//! honest answer rather than a flag pretending two languages are one.
//!
//! # The two ambiguities that decide whether anything after them is read correctly
//!
//! - **a `/` is division or the start of a regular expression**, and only the token before it says
//!   which. `a / b` divides; `return /ab+/.test(x)` does not. Reading a regex as division leaves its
//!   body as code, and a regex holding `{`, `"`, or `'` — which is ordinary — then unbalances every
//!   brace after it and moves every following declaration into the wrong scope;
//! - **a template literal nests.** `` `${ {a: `${b}`} }` `` holds a brace, an object, and another
//!   template inside a string. Losing that is the same failure Kotlin's lexer documents, and it is
//!   worse here because template literals are how JavaScript writes most of its strings.
//!
//! # JSX is read as punctuation, and what that costs
//!
//! `<div className="x">text</div>` is lexed as `<`, identifiers, a string, `>`, and so on. No attempt is
//! made to recognise an element, because a structural analyzer is looking for the declarations *around*
//! JSX rather than inside it, and a JSX parser is a second grammar to keep correct.
//!
//! The cost is bounded and worth stating: JSX text containing an apostrophe — `<p>don't</p>` — starts a
//! string literal that runs to the end of the line. It cannot run further, because a single-quoted
//! string stops at a newline, so the damage is one line of one body and never the file's brace balance.
//! A declaration is not lost; at most a call inside one line of markup is.
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **unterminated everything** stops rather than looping;
//! - **`#` starts a private name.** `#count` is one identifier, and splitting it would make a private
//!   field read as punctuation followed by a name;
//! - **`$` and `_` are identifier characters**, which is what most generated code is named with.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier, a keyword, or a private name written with a leading `#`.
    Ident(String),
    /// A number, a regular expression, or anything else whose only fact is that it was here.
    Literal,
    /// A string or template literal, carrying its content.
    ///
    /// Kept because an import's path is a string and a framework's meaning is often inside one. A
    /// template's `${...}` is kept as written: a path built by interpolation is not a path this build can
    /// resolve, and substituting a guess would be worse than reporting what the source says.
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

/// Tokenizes TypeScript or JavaScript source.
///
/// Never fails. Malformed input produces whatever tokens can be read and then stops.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Spanned> {
    Lexer::new(source).run()
}

/// Words after which a `/` begins a regular expression rather than a division.
///
/// Each one can only be followed by an expression, and an expression may start with a regex. After an
/// identifier, a number, a string, or a closing bracket, a `/` is division — that is the other half of
/// the rule and it is decided by [`Lexer::regex_may_start`].
const BEFORE_REGEX: [&str; 14] = [
    "await",
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "of",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
];

struct Lexer {
    characters: Vec<char>,
    at: usize,
    line: u32,
    column: u32,
    /// The last token emitted, which is what decides whether a `/` opens a regex.
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

    /// Reports whether a `/` here opens a regular expression.
    ///
    /// Decided by the previous token, which is the only thing that can decide it. After a value — an
    /// identifier, a literal, a string, or a closing bracket — a `/` divides. Everywhere else an
    /// expression is expected, and an expression may begin with a regex.
    ///
    /// A keyword is an identifier to this lexer, so the ones that are followed by an expression are
    /// listed in [`BEFORE_REGEX`]. Without that, `return /ab+/.test(x)` reads its regex as division.
    ///
    /// `}` counts as allowing one, because most braces close a block rather than an object literal, and
    /// a regex at the start of a statement after a block is the common case.
    fn regex_may_start(&self) -> bool {
        match &self.previous {
            None => true,
            Some(Token::Ident(name)) => BEFORE_REGEX.contains(&name.as_str()),
            Some(Token::Literal | Token::Text(_)) => false,
            Some(Token::Close(Delimiter::Paren | Delimiter::Bracket)) => false,
            Some(Token::Close(Delimiter::Brace) | Token::Open(_)) => true,
            Some(Token::Punct(_)) => true,
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
                '"' | '\'' => Token::Text(self.string(character)),
                '`' => Token::Text(self.template()),
                '/' if self.regex_may_start() => {
                    self.regex();
                    Token::Literal
                }
                _ if character.is_ascii_digit() => {
                    self.number();
                    Token::Literal
                }
                // `#count` is one private name. Split, the `#` would read as punctuation and the field
                // would look like a name in an expression.
                '#' if self.peek_at(1).is_some_and(is_identifier_start) => {
                    self.bump();
                    Token::Ident(format!("#{}", self.identifier()))
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
                // A shebang, which is a comment only on the first line.
                Some('#') if self.at == 0 && self.matches("#!") => {
                    while let Some(character) = self.peek() {
                        if character == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                _ => return,
            }
        }
    }

    /// Consumes a block comment, which does not nest in either language.
    fn block_comment(&mut self) {
        self.take(2);
        while self.peek().is_some() {
            if self.matches("*/") {
                self.take(2);
                return;
            }
            self.bump();
        }
    }

    /// Consumes a quoted string and returns its content.
    ///
    /// Stops at a newline as well as at the closing quote. That bound is what keeps a stray apostrophe
    /// in JSX text from consuming the rest of the file.
    fn string(&mut self, quote: char) -> String {
        self.bump();
        let mut content = String::new();
        while let Some(character) = self.peek() {
            match character {
                found if found == quote => {
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

    /// Consumes a template literal and returns its content as written, `${...}` included.
    ///
    /// The interpolations are tracked rather than skipped, because one may contain a brace, a nested
    /// template, or a string, and losing the balance moves every later declaration into the wrong scope.
    /// A template may span lines, so unlike a quoted string there is no newline bound — only the closing
    /// backtick or the end of input ends it.
    fn template(&mut self) -> String {
        self.bump();
        let mut content = String::new();
        loop {
            let Some(character) = self.peek() else {
                return content;
            };
            match character {
                '`' => {
                    self.bump();
                    return content;
                }
                '\\' => {
                    self.bump();
                    content.push('\\');
                    if let Some(escaped) = self.bump() {
                        content.push(escaped);
                    }
                }
                '$' if self.peek_at(1) == Some('{') => {
                    content.push_str("${");
                    self.take(2);
                    self.interpolation(&mut content);
                }
                _ => {
                    content.push(character);
                    self.bump();
                }
            }
        }
    }

    /// Consumes one `${...}`, counting braces and re-entering for a nested template or string.
    fn interpolation(&mut self, content: &mut String) {
        let mut depth = 1_u32;
        loop {
            let Some(character) = self.peek() else {
                return;
            };
            match character {
                '{' => {
                    depth += 1;
                    content.push('{');
                    self.bump();
                }
                '}' => {
                    depth -= 1;
                    content.push('}');
                    self.bump();
                    if depth == 0 {
                        return;
                    }
                }
                // A nested template, whose own backticks and braces belong to it.
                '`' => {
                    content.push('`');
                    let nested = self.template();
                    content.push_str(&nested);
                    content.push('`');
                }
                '"' | '\'' => {
                    content.push(character);
                    let nested = self.string(character);
                    content.push_str(&nested);
                    content.push(character);
                }
                _ => {
                    content.push(character);
                    self.bump();
                }
            }
        }
    }

    /// Consumes a regular expression literal and its flags.
    ///
    /// A character class is tracked, because `/[/]/` holds a slash that does not end the literal, and an
    /// escape is honoured for the same reason.
    fn regex(&mut self) {
        self.bump();
        let mut in_class = false;
        while let Some(character) = self.peek() {
            match character {
                '\\' => {
                    self.bump();
                    self.bump();
                }
                '[' => {
                    in_class = true;
                    self.bump();
                }
                ']' => {
                    in_class = false;
                    self.bump();
                }
                '/' if !in_class => {
                    self.bump();
                    // The flags.
                    while self.peek().is_some_and(|found| found.is_alphanumeric()) {
                        self.bump();
                    }
                    return;
                }
                // A regex cannot span a line. Stopping here keeps a lone `/` that is neither division nor
                // a regex from consuming the file.
                '\n' => return,
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
    character == '_' || character == '$' || character.is_alphabetic()
}

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
    fn a_slash_after_a_value_is_division_and_after_a_keyword_is_a_regex() {
        // `a / b / c` is two divisions. Read as a regex, `/ b /` would swallow the middle.
        assert_eq!(names("const x = a / b / c;"), ["const", "x", "a", "b", "c"]);
        // `return /ab+/.test(s)` is a regex. Read as division, its body stays as code.
        assert_eq!(
            names("function f(s) { return /ab+/.test(s); }"),
            ["function", "f", "s", "return", "test", "s"]
        );
    }

    #[test]
    fn a_regex_holding_a_brace_or_a_quote_does_not_unbalance_the_file() {
        // The reason the ambiguity matters. A regex like this is ordinary, and read as division its
        // contents become code — one unmatched brace moves every later declaration into the wrong scope.
        assert!(braces_balance(
            "function f() { return /^\\{\"a\"$/.test(x); }\nclass After { }"
        ));
        assert_eq!(
            names("function f() { return /^{\"a\"$/.test(x); }\nclass After { }"),
            ["function", "f", "return", "test", "x", "class", "After"]
        );
    }

    #[test]
    fn a_character_class_may_hold_the_delimiter() {
        assert_eq!(
            names("const re = /[/{]/g; const after = 1;"),
            ["const", "re", "const", "after"]
        );
    }

    #[test]
    fn a_regex_does_not_run_past_a_line() {
        // A lone `/` that is neither must not consume the file.
        assert_eq!(
            names("const a = /unterminated\nclass After { }"),
            ["const", "a", "class", "After"]
        );
    }

    #[test]
    fn a_template_keeps_its_interpolation_and_stays_balanced() {
        assert_eq!(texts("const s = `a${b}c`;"), ["a${b}c"]);
        assert!(braces_balance("const s = `${ {a: 1} }`;\nclass After { }"));
        assert_eq!(
            names("const s = `${ {a: 1} }`;\nclass After { }"),
            ["const", "s", "class", "After"]
        );
    }

    #[test]
    fn a_template_nested_in_an_interpolation_is_still_one_string() {
        assert_eq!(texts("const s = `a${ `b${c}` }d`;"), ["a${ `b${c}` }d"]);
        assert!(braces_balance(
            "const s = `a${ `b${c}` }d`;\nclass After { }"
        ));
    }

    #[test]
    fn a_brace_inside_a_string_inside_an_interpolation_is_content() {
        assert!(braces_balance(
            "const s = `${ f(\"{\") }`;\nclass After { }"
        ));
        // The interpolation stays inside the template's text rather than becoming tokens of its own, so
        // `f` is content here and not an identifier. That is what "kept as written" means, and it is why
        // the analyzer reads an import's path out of a `Text` token.
        assert_eq!(texts("const s = `${ f(\"{\") }`;"), ["${ f(\"{\") }"]);
        assert_eq!(
            names("const s = `${ f(\"{\") }`;\nclass After { }"),
            ["const", "s", "class", "After"]
        );
    }

    #[test]
    fn a_template_may_span_lines() {
        assert_eq!(texts("const s = `one\ntwo`;"), ["one\ntwo"]);
        assert_eq!(
            names("const s = `one\ntwo`;\nclass After { }"),
            ["const", "s", "class", "After"]
        );
    }

    #[test]
    fn a_quoted_string_stops_at_a_newline() {
        // The bound that keeps an apostrophe in JSX text from consuming the rest of the file.
        assert_eq!(
            names("const a = 'open\nclass After { }"),
            ["const", "a", "class", "After"]
        );
    }

    #[test]
    fn jsx_text_with_an_apostrophe_costs_one_line_and_not_the_file() {
        // Stated as a test because it is a known cost rather than a bug that slipped through: the
        // apostrophe opens a string, and the newline closes it.
        let source = "function C() {\n  return <p>don't</p>;\n}\nclass After { }";
        assert!(braces_balance(source));
        assert!(names(source).contains(&"After".to_owned()));
        assert!(names(source).contains(&"C".to_owned()));
    }

    #[test]
    fn a_private_name_is_one_identifier() {
        assert_eq!(
            names("class A { #count = 0; get() { return this.#count; } }"),
            ["class", "A", "#count", "get", "return", "this", "#count"]
        );
    }

    #[test]
    fn a_shebang_is_trivia_only_at_the_start() {
        assert_eq!(names("#!/usr/bin/env node\nclass A { }"), ["class", "A"]);
    }

    #[test]
    fn a_dollar_or_underscore_starts_an_identifier() {
        assert_eq!(names("const $el = _private;"), ["const", "$el", "_private"]);
    }

    #[test]
    fn a_block_comment_closes_at_the_first_terminator() {
        assert_eq!(names("/* /* */ class After { }"), ["class", "After"]);
    }

    #[test]
    fn unterminated_input_stops_rather_than_looping() {
        assert!(names("/* open").is_empty());
        assert_eq!(names("const s = `open"), ["const", "s"]);
        assert_eq!(names("class A { /* open"), ["class", "A"]);
    }

    #[test]
    fn a_position_is_the_first_character_of_the_token() {
        let found: Vec<(String, u32, u32)> = tokenize("class A {\n  m() {}\n}")
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
                ("m".to_owned(), 2, 3),
            ]
        );
    }
}
