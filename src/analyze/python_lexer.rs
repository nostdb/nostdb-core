//! Tokenizes Python far enough for structural analysis.
//!
//! # Why this one carries tokens the others do not
//!
//! Every other language in this module delimits a block with a brace, so its analyzer finds the end of a
//! declaration by counting them. Python delimits with **indentation**, which is not a character the lexer
//! can count — it is a comparison against the enclosing line. So this lexer resolves it once, here, and
//! emits [`Token::Indent`] and [`Token::Dedent`] where a brace would have been. The analyzer then reads
//! the same shape it reads for every other language.
//!
//! Doing it in the analyzer instead would mean every declaration carrying a column and comparing against
//! its parent, and the two rules below would be re-derived at each site that asked.
//!
//! # The two rules that decide where a block ends
//!
//! - **a newline inside brackets is not a newline.** `f(\n  a,\n  b,\n)` is one logical line, and the
//!   indentation of its continuation lines means nothing. A lexer that measured them would emit an
//!   `Indent` in the middle of a call and put every following declaration inside it;
//!
//! - **a blank line and a comment-only line have no indentation.** They may appear at any depth, and
//!   measuring them would close every block that a file happens to leave a blank line inside — which is
//!   most of them.
//!
//! # What it must get right, because a structural analyzer runs over source somebody is editing
//!
//! - **a triple-quoted string.** A docstring is the first thing in most bodies, and it holds `#`, quotes,
//!   and blank lines. Read as three separate strings, its content becomes code;
//! - **an f-string's replacement fields.** `f"{a['k']}"` holds a quote inside a brace inside a string.
//!   Losing the nesting ends the string early;
//! - **unterminated everything** stops rather than looping;
//! - **a dedent at end of input** still closes what is open, so the last declaration in a file is not
//!   left waiting for a `Dedent` that never comes.

use std::fmt;

/// One token, reduced to what the structural analyzer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An identifier or a keyword.
    Ident(String),
    /// A number, reduced to the fact that one was here.
    Literal,
    /// A string literal of any of Python's forms, carrying its content.
    Text(String),
    /// An opening bracket.
    Open(Delimiter),
    /// A closing bracket.
    Close(Delimiter),
    /// Any other punctuation, one character at a time.
    Punct(char),
    /// The end of a logical line.
    Newline,
    /// The start of a more deeply indented block, which is Python's opening brace.
    Indent,
    /// The end of one, which is its closing brace.
    Dedent,
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

/// How far a tab advances the indentation column.
///
/// Eight, which is what the language reference states for the purpose of comparing indentation. A file
/// mixing tabs and spaces is ambiguous to a reader and to CPython both; this at least resolves it the way
/// the reference documents rather than inventing a third answer.
const TAB_WIDTH: u32 = 8;

/// Tokenizes Python source.
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
    /// Open bracket depth. Inside brackets, a newline is not a logical newline.
    brackets: u32,
    /// The indentation of each enclosing block, innermost last.
    indents: Vec<u32>,
    /// Whether the next thing to read is the start of a logical line.
    at_line_start: bool,
}

impl Lexer {
    fn new(source: &str) -> Self {
        Self {
            characters: source.chars().collect(),
            at: 0,
            line: 1,
            column: 1,
            brackets: 0,
            indents: vec![0],
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

    fn run(mut self) -> Vec<Spanned> {
        let mut tokens = Vec::new();
        loop {
            if self.at_line_start && self.brackets == 0 {
                self.at_line_start = false;
                if let Some(width) = self.measure_indentation() {
                    self.emit_indentation(width, &mut tokens);
                }
            }
            self.skip_inline_trivia();
            let (line, column) = (self.line, self.column);
            let Some(character) = self.peek() else {
                // Close every open block, so the last declaration in a file is not left waiting.
                //
                // The final newline is emitted only when the source did not end with one. A file that
                // did already produced it, and a second would read as an empty statement — which showed
                // up as a spurious `;` before every closing `Dedent`.
                if tokens
                    .last()
                    .is_some_and(|held| held.token != Token::Newline)
                {
                    tokens.push(Spanned {
                        token: Token::Newline,
                        line,
                        column,
                    });
                }
                while self.indents.len() > 1 {
                    self.indents.pop();
                    tokens.push(Spanned {
                        token: Token::Dedent,
                        line,
                        column,
                    });
                }
                return tokens;
            };
            let token = match character {
                '\n' => {
                    self.bump();
                    // Only a *logical* newline starts a line whose indentation is measured. Setting it
                    // inside brackets left the flag on until the bracket closed, and then the first real
                    // newline after the closing `)` was consumed as a blank line by the measurement
                    // instead of ending the statement — so `x = f(\n…\n)` and the declaration after it
                    // ran together.
                    self.at_line_start = self.brackets == 0;
                    if self.brackets > 0 {
                        // Implicit line joining: a newline inside brackets is not one.
                        continue;
                    }
                    Token::Newline
                }
                '\\' if self.peek_at(1) == Some('\n') => {
                    // Explicit line joining.
                    self.bump();
                    self.bump();
                    continue;
                }
                '{' => {
                    self.brackets += 1;
                    self.bump();
                    Token::Open(Delimiter::Brace)
                }
                '}' => {
                    self.brackets = self.brackets.saturating_sub(1);
                    self.bump();
                    Token::Close(Delimiter::Brace)
                }
                '(' => {
                    self.brackets += 1;
                    self.bump();
                    Token::Open(Delimiter::Paren)
                }
                ')' => {
                    self.brackets = self.brackets.saturating_sub(1);
                    self.bump();
                    Token::Close(Delimiter::Paren)
                }
                '[' => {
                    self.brackets += 1;
                    self.bump();
                    Token::Open(Delimiter::Bracket)
                }
                ']' => {
                    self.brackets = self.brackets.saturating_sub(1);
                    self.bump();
                    Token::Close(Delimiter::Bracket)
                }
                '"' | '\'' => Token::Text(self.string()),
                _ if character.is_ascii_digit() => {
                    self.number();
                    Token::Literal
                }
                // A prefixed string: `f"…"`, `r'…'`, `rb"…"`, and every case of them.
                _ if is_identifier_start(character) => {
                    let start = self.at;
                    let name = self.identifier();
                    if is_string_prefix(&name) && matches!(self.peek(), Some('"' | '\'')) {
                        Token::Text(self.string())
                    } else {
                        debug_assert!(self.at > start);
                        Token::Ident(name)
                    }
                }
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

    /// The indentation of the line about to be read, or `None` when the line has none to measure.
    ///
    /// A blank line and a comment-only line return `None`. They may appear at any depth, and measuring
    /// them would close every block a file leaves a blank line inside — which is most of them.
    fn measure_indentation(&mut self) -> Option<u32> {
        let mut width = 0_u32;
        loop {
            match self.peek() {
                Some(' ') => {
                    width += 1;
                    self.bump();
                }
                Some('\t') => {
                    width = (width / TAB_WIDTH + 1) * TAB_WIDTH;
                    self.bump();
                }
                // A form feed resets the count, which is what the reference says.
                Some('\u{c}') => {
                    width = 0;
                    self.bump();
                }
                Some('\n') => {
                    self.bump();
                    // Still at a line start, and this one was blank.
                    width = 0;
                    continue;
                }
                Some('#') => {
                    // A comment-only line, consumed **including its newline**. Leaving the newline behind
                    // made it a logical one, so a comment between two members closed nothing and then
                    // ended a statement that had already ended — an extra empty statement in the middle of
                    // a class body.
                    while self.peek().is_some_and(|found| found != '\n') {
                        self.bump();
                    }
                    self.bump();
                    width = 0;
                    continue;
                }
                None => return None,
                _ => return Some(width),
            }
        }
    }

    /// Emits the `Indent` or `Dedent` tokens that move from the current block to one of `width`.
    fn emit_indentation(&mut self, width: u32, tokens: &mut Vec<Spanned>) {
        let (line, column) = (self.line, self.column);
        let current = *self.indents.last().unwrap_or(&0);
        if width > current {
            self.indents.push(width);
            tokens.push(Spanned {
                token: Token::Indent,
                line,
                column,
            });
            return;
        }
        while width < *self.indents.last().unwrap_or(&0) && self.indents.len() > 1 {
            self.indents.pop();
            tokens.push(Spanned {
                token: Token::Dedent,
                line,
                column,
            });
        }
    }

    /// Skips spaces, comments, and a joined line, but never a newline.
    fn skip_inline_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r') => {
                    self.bump();
                }
                Some('#') => {
                    while self.peek().is_some_and(|found| found != '\n') {
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

    /// Consumes a string literal of any form and returns its content.
    ///
    /// A triple-quoted string ends only at three matching quotes, and may hold newlines, `#`, and single
    /// quotes as content. A docstring is the first thing in most bodies, so reading one as three separate
    /// strings would turn its prose into code.
    fn string(&mut self) -> String {
        let quote = self.peek().unwrap_or('"');
        let triple = self.peek_at(1) == Some(quote) && self.peek_at(2) == Some(quote);
        if triple {
            self.bump();
            self.bump();
            self.bump();
        } else {
            self.bump();
        }
        let mut content = String::new();
        loop {
            let Some(character) = self.peek() else {
                return content;
            };
            match character {
                '\\' => {
                    self.bump();
                    if let Some(escaped) = self.bump() {
                        content.push(escaped);
                    }
                }
                found if found == quote => {
                    if triple {
                        if self.peek_at(1) == Some(quote) && self.peek_at(2) == Some(quote) {
                            self.bump();
                            self.bump();
                            self.bump();
                            return content;
                        }
                        content.push(found);
                        self.bump();
                    } else {
                        self.bump();
                        return content;
                    }
                }
                // A single-quoted string cannot span a line. The bound keeps an unclosed quote from
                // consuming the file.
                '\n' if !triple => return content,
                // A replacement field, which may hold a quote, a bracket, or another string.
                '{' => {
                    content.push('{');
                    self.bump();
                    if self.peek() == Some('{') {
                        // `{{` is a literal brace.
                        content.push('{');
                        self.bump();
                        continue;
                    }
                    self.replacement_field(&mut content, quote, triple);
                }
                _ => {
                    content.push(character);
                    self.bump();
                }
            }
        }
    }

    /// Consumes one `{...}` inside a string, counting braces and re-entering for a nested string.
    ///
    /// Applied to every string rather than only to one carrying an `f` prefix. A brace in a plain string
    /// is content either way, and the alternative is threading the prefix through every call to decide
    /// something that changes nothing: what is consumed is identical, and only an unbalanced brace inside
    /// a non-f string would tell the difference.
    fn replacement_field(&mut self, content: &mut String, quote: char, triple: bool) {
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
                '"' | '\'' => {
                    // The quotes belong to the field as written. Pushing only the content turned
                    // `{a['k']}` into `{a[k]}`, which is a different expression.
                    content.push(character);
                    let nested = self.string();
                    content.push_str(&nested);
                    content.push(character);
                }
                // The enclosing string ended before the field did, on malformed input.
                '\n' if !triple => return,
                found if found == quote && depth > 0 => {
                    content.push(found);
                    self.bump();
                }
                _ => {
                    content.push(character);
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

/// Reports whether a name is one of Python's string prefixes.
///
/// Matched case-insensitively and by its letters, so `f`, `rb`, `BR`, and `u` are all recognised without
/// listing every ordering.
fn is_string_prefix(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 2
        && name
            .chars()
            .all(|character| matches!(character.to_ascii_lowercase(), 'b' | 'f' | 'r' | 'u'))
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

    /// The block structure, as the brace-shaped tokens the analyzer reads.
    fn shape(source: &str) -> String {
        tokenize(source)
            .into_iter()
            .filter_map(|spanned| match spanned.token {
                Token::Indent => Some('{'),
                Token::Dedent => Some('}'),
                Token::Newline => Some(';'),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn indentation_opens_and_closes_a_block() {
        assert_eq!(shape("def a():\n    pass\n"), ";{;}");
        assert_eq!(shape("def a():\n    def b():\n        pass\n"), ";{;{;}}");
        assert_eq!(
            shape("def a():\n    pass\ndef b():\n    pass\n"),
            ";{;};{;}"
        );
    }

    #[test]
    fn every_open_block_closes_at_end_of_input() {
        // Without this the last declaration in a file waits for a `Dedent` that never comes, and a file
        // ending inside a class loses every member of it.
        assert_eq!(shape("class A:\n    def m(self):\n        pass"), ";{;{;}}");
    }

    #[test]
    fn a_newline_inside_brackets_is_not_a_newline() {
        // The continuation lines are indented and mean nothing. An `Indent` here would put every later
        // declaration inside the call.
        assert_eq!(
            shape("x = f(\n    a,\n    b,\n)\ndef after():\n    pass\n"),
            ";;{;}"
        );
        assert_eq!(
            names("x = f(\n    a,\n)\ndef after():\n    pass\n"),
            ["x", "f", "a", "def", "after", "pass"]
        );
    }

    #[test]
    fn a_blank_line_or_a_comment_does_not_close_a_block() {
        // Most bodies hold one, and measuring it would close the block it is inside.
        assert_eq!(
            shape("def a():\n    x = 1\n\n    y = 2\n"),
            ";{;;}",
            "a blank line inside a body"
        );
        assert_eq!(
            shape(
                "class A:\n    def m(self):\n        pass\n\n# a comment at column zero\n    def n(self):\n        pass\n"
            ),
            ";{;{;};{;}}",
        );
    }

    #[test]
    fn an_explicit_line_join_continues_the_line() {
        assert_eq!(
            shape("x = 1 + \\\n    2\ndef after():\n    pass\n"),
            ";;{;}"
        );
    }

    #[test]
    fn a_triple_quoted_string_is_one_token_and_may_hold_anything() {
        assert_eq!(
            texts(
                "def a():\n    \"\"\"Doc.\n\n    # not a comment\n    'not a string'\n    \"\"\"\n"
            ),
            ["Doc.\n\n    # not a comment\n    'not a string'\n    "]
        );
        // And the body it opens still closes.
        assert_eq!(
            shape("def a():\n    \"\"\"Doc\n    \"\"\"\n    pass\ndef b():\n    pass\n"),
            ";{;;};{;}"
        );
    }

    #[test]
    fn a_docstring_holding_a_quote_does_not_end_early() {
        assert_eq!(texts("\"\"\"a \" b\"\"\""), ["a \" b"]);
    }

    #[test]
    fn a_prefixed_string_is_a_string_and_not_an_identifier() {
        assert_eq!(texts("x = f\"a{b}c\""), ["a{b}c"]);
        assert_eq!(texts("x = rb'raw'"), ["raw"]);
        assert_eq!(names("x = f\"a\""), ["x"], "the prefix is not a name");
        // A name that only looks like a prefix, with no string after it, stays a name.
        assert_eq!(names("f = 1"), ["f"]);
        assert_eq!(names("br = 2"), ["br"]);
    }

    #[test]
    fn a_replacement_field_may_hold_a_quote_and_a_brace() {
        assert_eq!(texts("x = f\"{a['k']}\""), ["{a['k']}"]);
        assert_eq!(texts("x = f\"{ {'a': 1} }\""), ["{ {'a': 1} }"]);
        // A literal brace is not a field.
        assert_eq!(texts("x = f\"{{literal}}\""), ["{{literal}}"]);
        // And the declaration after it survives.
        assert_eq!(
            names("x = f\"{a['k']}\"\ndef after():\n    pass\n"),
            ["x", "def", "after", "pass"]
        );
    }

    #[test]
    fn a_single_quoted_string_stops_at_a_newline() {
        assert_eq!(
            names("x = 'open\ndef after():\n    pass\n"),
            ["x", "def", "after", "pass"]
        );
    }

    #[test]
    fn a_tab_advances_to_the_next_multiple_of_eight() {
        // One tab and eight spaces are the same depth, so a body written with either closes the same way.
        assert_eq!(shape("def a():\n\tpass\n"), ";{;}");
        assert_eq!(
            shape("def a():\n\tpass\n"),
            shape("def a():\n        pass\n")
        );
    }

    #[test]
    fn unterminated_input_stops_rather_than_looping() {
        assert_eq!(names("x = \"\"\"open"), ["x"]);
        assert_eq!(names("def a("), ["def", "a"]);
        assert!(names("").is_empty());
        assert!(names("# only a comment").is_empty());
    }

    #[test]
    fn a_position_is_the_first_character_of_the_token() {
        let found: Vec<(String, u32, u32)> = tokenize("class A:\n    def m(self):\n        pass\n")
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
                ("def".to_owned(), 2, 5),
                ("m".to_owned(), 2, 9),
                ("self".to_owned(), 2, 11),
                ("pass".to_owned(), 3, 9),
            ]
        );
    }
}
