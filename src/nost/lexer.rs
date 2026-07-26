//! The `.nost` lexer.
//!
//! Trivia is emitted rather than discarded. A comment-preserving tree cannot be built
//! from a token stream that already threw the comments away, and the canonical
//! formatter has to reproduce every comment with its attachment.
//!
//! Each comment records whether it began its own line, which is what the attachment
//! rule in the language contract turns on: an own-line comment leads the next
//! declaration, and a same-line comment trails the one before it.

use super::ParseError;
use crate::evidence::{SourcePosition, SourceRange};

/// A trivia token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriviaKind {
    /// Spaces, tabs, and line terminators.
    Whitespace,
    /// A `//` comment running to the end of the line.
    LineComment,
    /// A `/* */` comment, which does not nest.
    BlockComment,
}

/// A word the grammar reserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    /// `as`
    As,
    /// `bytes`, outside a tagged literal.
    Bytes,
    /// `datetime`, outside a tagged literal.
    Datetime,
    /// `edge`
    Edge,
    /// `false`
    False,
    /// `id`
    Id,
    /// `module`
    Module,
    /// `node`
    Node,
    /// `source`
    Source,
    /// `true`
    True,
}

impl Keyword {
    fn from_text(text: &str) -> Option<Self> {
        Some(match text {
            "as" => Self::As,
            "bytes" => Self::Bytes,
            "datetime" => Self::Datetime,
            "edge" => Self::Edge,
            "false" => Self::False,
            "id" => Self::Id,
            "module" => Self::Module,
            "node" => Self::Node,
            "source" => Self::Source,
            "true" => Self::True,
            _ => return None,
        })
    }

    /// The reserved spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::As => "as",
            Self::Bytes => "bytes",
            Self::Datetime => "datetime",
            Self::Edge => "edge",
            Self::False => "false",
            Self::Id => "id",
            Self::Module => "module",
            Self::Node => "node",
            Self::Source => "source",
            Self::True => "true",
        }
    }
}

/// What a token is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// Whitespace or a comment.
    Trivia(TriviaKind),
    /// A reserved word.
    Keyword(Keyword),
    /// An identifier.
    Identifier,
    /// An integer literal, kept as text so a range violation stays semantic.
    IntegerLiteral,
    /// A float literal, kept as text for the same reason.
    FloatLiteral,
    /// A string literal, already unescaped.
    StringLiteral,
    /// A `bytes"..."` literal, already decoded.
    BytesLiteral,
    /// A `datetime"..."` literal, kept as text so validation can check RFC 3339.
    DateTimeLiteral,
    /// `@nost`
    NostDirective,
    /// `@link`
    LinkDirective,
    /// `{`
    LeftBrace,
    /// `}`
    RightBrace,
    /// `(`
    LeftParen,
    /// `)`
    RightParen,
    /// `[`
    LeftBracket,
    /// `]`
    RightBracket,
    /// `:`
    Colon,
    /// `::`
    ColonColon,
    /// `,`
    Comma,
    /// `->`
    Arrow,
    /// End of input.
    Eof,
}

/// One token.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    /// What it is.
    pub kind: TokenKind,
    /// Where it is.
    pub range: SourceRange,
    /// The token's meaning: an identifier's name, a literal's value, a comment's text.
    pub text: String,
    /// The decoded bytes, for a `bytes` literal only.
    pub bytes: Vec<u8>,
    /// Whether this token began its own line, which the comment attachment rule uses.
    pub on_own_line: bool,
}

impl Token {
    /// Reports whether this token is trivia.
    #[must_use]
    pub const fn is_trivia(&self) -> bool {
        matches!(self.kind, TokenKind::Trivia(_))
    }

    /// Reports whether this token is a comment.
    #[must_use]
    pub const fn is_comment(&self) -> bool {
        matches!(
            self.kind,
            TokenKind::Trivia(TriviaKind::LineComment | TriviaKind::BlockComment)
        )
    }
}

struct Lexer<'a> {
    source: &'a str,
    characters: Vec<(usize, char)>,
    index: usize,
    line: u32,
    column: u32,
    /// Whether only whitespace has appeared since the last line terminator.
    at_line_start: bool,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            characters: source.char_indices().collect(),
            index: 0,
            line: 1,
            column: 1,
            at_line_start: true,
        }
    }

    fn peek(&self) -> Option<char> {
        self.characters.get(self.index).map(|&(_, c)| c)
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.characters.get(self.index + ahead).map(|&(_, c)| c)
    }

    fn offset(&self) -> u64 {
        self.characters
            .get(self.index)
            .map_or(self.source.len(), |&(offset, _)| offset) as u64
    }

    fn position(&self) -> SourcePosition {
        SourcePosition {
            line: self.line,
            column: self.column,
            offset: self.offset(),
        }
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.index += 1;
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn range(&self, start: SourcePosition) -> SourceRange {
        // This lexer's positions are 1-based and never regress, so the validating
        // constructor cannot reject them. The fallback exists only so the lexer keeps
        // the crate's no-panic guarantee if that ever stops being true.
        SourceRange::new(start, self.position()).unwrap_or(SourceRange::ORIGIN)
    }

    fn error(&self, start: SourcePosition, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            range: self.range(start),
        }
    }
}

/// Splits `source` into tokens, trivia included, ending with [`TokenKind::Eof`].
///
/// # Errors
///
/// Returns a [`ParseError`] with a source range for an unterminated string or block
/// comment, a line terminator inside a string, a malformed number or tagged literal,
/// or a character the grammar does not allow.
pub fn tokenize(source: &str) -> Result<Vec<Token>, ParseError> {
    let mut lexer = Lexer::new(source);
    let mut tokens: Vec<Token> = Vec::new();

    loop {
        let start = lexer.position();
        let own_line = lexer.at_line_start;
        let Some(character) = lexer.peek() else {
            tokens.push(Token {
                kind: TokenKind::Eof,
                range: lexer.range(start),
                text: String::new(),
                bytes: Vec::new(),
                on_own_line: own_line,
            });
            return Ok(tokens);
        };

        let token = match character {
            c if c.is_whitespace() => {
                let mut saw_newline = false;
                while let Some(next) = lexer.peek() {
                    if !next.is_whitespace() {
                        break;
                    }
                    if next == '\n' {
                        saw_newline = true;
                    }
                    lexer.advance();
                }
                if saw_newline {
                    lexer.at_line_start = true;
                }
                Token {
                    kind: TokenKind::Trivia(TriviaKind::Whitespace),
                    range: lexer.range(start),
                    text: String::new(),
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '/' if lexer.peek_at(1) == Some('/') => {
                lexer.advance();
                lexer.advance();
                let mut text = String::new();
                while let Some(next) = lexer.peek() {
                    if next == '\n' {
                        break;
                    }
                    text.push(next);
                    lexer.advance();
                }
                lexer.at_line_start = false;
                Token {
                    kind: TokenKind::Trivia(TriviaKind::LineComment),
                    range: lexer.range(start),
                    // Trimmed on both ends so the canonical form is one space after
                    // `//`. Keeping the leading space would make the formatter add
                    // another on every pass, so output would never stabilize.
                    text: text.trim().to_owned(),
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '/' if lexer.peek_at(1) == Some('*') => {
                lexer.advance();
                lexer.advance();
                let mut text = String::new();
                let mut closed = false;
                while let Some(next) = lexer.peek() {
                    if next == '*' && lexer.peek_at(1) == Some('/') {
                        lexer.advance();
                        lexer.advance();
                        closed = true;
                        break;
                    }
                    text.push(next);
                    lexer.advance();
                }
                if !closed {
                    return Err(lexer.error(start, "an unterminated block comment"));
                }
                lexer.at_line_start = false;
                Token {
                    kind: TokenKind::Trivia(TriviaKind::BlockComment),
                    range: lexer.range(start),
                    text,
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '@' => {
                lexer.advance();
                let mut word = String::new();
                while let Some(next) = lexer.peek() {
                    if !unicode_ident::is_xid_continue(next) {
                        break;
                    }
                    word.push(next);
                    lexer.advance();
                }
                let kind = match word.as_str() {
                    "nost" => TokenKind::NostDirective,
                    "link" => TokenKind::LinkDirective,
                    other => {
                        return Err(lexer.error(
                            start,
                            format!("unknown directive `@{other}`, expected `@nost` or `@link`"),
                        ));
                    }
                };
                lexer.at_line_start = false;
                Token {
                    kind,
                    range: lexer.range(start),
                    text: word,
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '"' => {
                let (text, range) = read_string(&mut lexer, start)?;
                lexer.at_line_start = false;
                Token {
                    kind: TokenKind::StringLiteral,
                    range,
                    text,
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '{' | '}' | '(' | ')' | '[' | ']' | ',' => {
                lexer.advance();
                let kind = match character {
                    '{' => TokenKind::LeftBrace,
                    '}' => TokenKind::RightBrace,
                    '(' => TokenKind::LeftParen,
                    ')' => TokenKind::RightParen,
                    '[' => TokenKind::LeftBracket,
                    ']' => TokenKind::RightBracket,
                    _ => TokenKind::Comma,
                };
                lexer.at_line_start = false;
                Token {
                    kind,
                    range: lexer.range(start),
                    text: character.to_string(),
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            ':' => {
                lexer.advance();
                let kind = if lexer.peek() == Some(':') {
                    lexer.advance();
                    TokenKind::ColonColon
                } else {
                    TokenKind::Colon
                };
                lexer.at_line_start = false;
                Token {
                    kind,
                    range: lexer.range(start),
                    text: String::new(),
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '-' if lexer.peek_at(1) == Some('>') => {
                lexer.advance();
                lexer.advance();
                lexer.at_line_start = false;
                Token {
                    kind: TokenKind::Arrow,
                    range: lexer.range(start),
                    text: "->".to_owned(),
                    bytes: Vec::new(),
                    on_own_line: own_line,
                }
            }
            '-' | '0'..='9' => {
                let token = read_number(&mut lexer, start, own_line)?;
                lexer.at_line_start = false;
                token
            }
            c if unicode_ident::is_xid_start(c) || c == '_' => {
                let mut word = String::new();
                while let Some(next) = lexer.peek() {
                    if !unicode_ident::is_xid_continue(next) {
                        break;
                    }
                    word.push(next);
                    lexer.advance();
                }
                // A tagged literal is the keyword immediately followed by a quote.
                let tagged = lexer.peek() == Some('"');
                let token = match (word.as_str(), tagged) {
                    ("bytes", true) => read_bytes_literal(&mut lexer, start, own_line)?,
                    ("datetime", true) => {
                        let (text, range) = read_string(&mut lexer, start)?;
                        Token {
                            kind: TokenKind::DateTimeLiteral,
                            range,
                            text,
                            bytes: Vec::new(),
                            on_own_line: own_line,
                        }
                    }
                    _ => {
                        let kind = Keyword::from_text(&word)
                            .map_or(TokenKind::Identifier, TokenKind::Keyword);
                        Token {
                            kind,
                            range: lexer.range(start),
                            text: word,
                            bytes: Vec::new(),
                            on_own_line: own_line,
                        }
                    }
                };
                lexer.at_line_start = false;
                token
            }
            other => {
                return Err(lexer.error(start, format!("unexpected character {other:?}")));
            }
        };

        tokens.push(token);
    }
}

fn read_string(
    lexer: &mut Lexer<'_>,
    start: SourcePosition,
) -> Result<(String, SourceRange), ParseError> {
    // The opening quote may be preceded by a literal tag, already consumed.
    if lexer.peek() != Some('"') {
        return Err(lexer.error(start, "expected a string literal"));
    }
    lexer.advance();
    let mut text = String::new();
    loop {
        let Some(character) = lexer.peek() else {
            return Err(lexer.error(start, "an unterminated string literal"));
        };
        match character {
            '"' => {
                lexer.advance();
                return Ok((text, lexer.range(start)));
            }
            '\n' | '\r' => {
                return Err(lexer.error(start, "a line terminator inside a string literal"));
            }
            '\\' => {
                lexer.advance();
                let Some(escape) = lexer.advance() else {
                    return Err(lexer.error(start, "an unterminated escape sequence"));
                };
                match escape {
                    '"' => text.push('"'),
                    '\\' => text.push('\\'),
                    'n' => text.push('\n'),
                    'r' => text.push('\r'),
                    't' => text.push('\t'),
                    'u' => {
                        if lexer.advance() != Some('{') {
                            return Err(lexer.error(start, "a unicode escape needs `u{`"));
                        }
                        let mut digits = String::new();
                        loop {
                            let Some(next) = lexer.peek() else {
                                return Err(lexer.error(start, "an unterminated unicode escape"));
                            };
                            if next == '}' {
                                lexer.advance();
                                break;
                            }
                            if !next.is_ascii_hexdigit() {
                                return Err(
                                    lexer.error(start, "a unicode escape takes hexadecimal digits")
                                );
                            }
                            digits.push(next);
                            lexer.advance();
                        }
                        let value = u32::from_str_radix(&digits, 16)
                            .map_err(|_| lexer.error(start, "a unicode escape is out of range"))?;
                        let scalar = char::from_u32(value).ok_or_else(|| {
                            lexer.error(start, "a unicode escape names no scalar value")
                        })?;
                        text.push(scalar);
                    }
                    other => {
                        return Err(
                            lexer.error(start, format!("unknown escape sequence `\\{other}`"))
                        );
                    }
                }
            }
            other => {
                text.push(other);
                lexer.advance();
            }
        }
    }
}

fn read_bytes_literal(
    lexer: &mut Lexer<'_>,
    start: SourcePosition,
    on_own_line: bool,
) -> Result<Token, ParseError> {
    lexer.advance(); // the opening quote
    let mut digits = String::new();
    loop {
        let Some(character) = lexer.peek() else {
            return Err(lexer.error(start, "an unterminated bytes literal"));
        };
        if character == '"' {
            lexer.advance();
            break;
        }
        if !character.is_ascii_hexdigit() {
            return Err(lexer.error(start, "a bytes literal takes hexadecimal digits"));
        }
        digits.push(character);
        lexer.advance();
    }
    if digits.len() % 2 != 0 {
        return Err(lexer.error(
            start,
            "a bytes literal needs an even number of hexadecimal digits",
        ));
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|_| lexer.error(start, "a bytes literal must be ASCII"))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| lexer.error(start, "a bytes literal takes hexadecimal digits"))?;
        bytes.push(byte);
    }
    Ok(Token {
        kind: TokenKind::BytesLiteral,
        range: lexer.range(start),
        text: digits,
        bytes,
        on_own_line,
    })
}

fn read_number(
    lexer: &mut Lexer<'_>,
    start: SourcePosition,
    on_own_line: bool,
) -> Result<Token, ParseError> {
    let mut text = String::new();
    if lexer.peek() == Some('-') {
        text.push('-');
        lexer.advance();
    }
    let mut digits = 0;
    while let Some(next) = lexer.peek() {
        if !next.is_ascii_digit() {
            break;
        }
        text.push(next);
        lexer.advance();
        digits += 1;
    }
    if digits == 0 {
        return Err(lexer.error(start, "expected a digit after `-`"));
    }

    let mut is_float = false;
    if lexer.peek() == Some('.') {
        is_float = true;
        text.push('.');
        lexer.advance();
        let mut fraction = 0;
        while let Some(next) = lexer.peek() {
            if !next.is_ascii_digit() {
                break;
            }
            text.push(next);
            lexer.advance();
            fraction += 1;
        }
        if fraction == 0 {
            return Err(lexer.error(start, "a float needs a digit after `.`"));
        }
    }

    if matches!(lexer.peek(), Some('e' | 'E')) {
        is_float = true;
        text.push('e');
        lexer.advance();
        if matches!(lexer.peek(), Some('+' | '-')) {
            let sign = lexer.advance().unwrap_or('+');
            text.push(sign);
        }
        let mut exponent = 0;
        while let Some(next) = lexer.peek() {
            if !next.is_ascii_digit() {
                break;
            }
            text.push(next);
            lexer.advance();
            exponent += 1;
        }
        if exponent == 0 {
            return Err(lexer.error(start, "an exponent needs at least one digit"));
        }
    }

    Ok(Token {
        kind: if is_float {
            TokenKind::FloatLiteral
        } else {
            TokenKind::IntegerLiteral
        },
        range: lexer.range(start),
        text,
        bytes: Vec::new(),
        on_own_line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<TokenKind> {
        tokenize(source)
            .unwrap()
            .into_iter()
            .filter(|token| !token.is_trivia())
            .map(|token| token.kind)
            .collect()
    }

    #[test]
    fn tokenizes_a_version_header() {
        assert_eq!(
            kinds("@nost 1\n"),
            vec![
                TokenKind::NostDirective,
                TokenKind::IntegerLiteral,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn distinguishes_a_colon_from_a_scope_operator_and_an_arrow_from_a_minus() {
        assert_eq!(
            kinds(":: : -> -1"),
            vec![
                TokenKind::ColonColon,
                TokenKind::Colon,
                TokenKind::Arrow,
                TokenKind::IntegerLiteral,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn a_tagged_literal_needs_the_quote_immediately_after_the_tag() {
        assert_eq!(
            kinds("bytes\"dead\""),
            vec![TokenKind::BytesLiteral, TokenKind::Eof]
        );
        assert_eq!(
            kinds("datetime\"2026-07-26T09:00:00Z\""),
            vec![TokenKind::DateTimeLiteral, TokenKind::Eof]
        );
        // With whitespace between, it is the bare reserved word.
        assert_eq!(
            kinds("bytes \"dead\""),
            vec![
                TokenKind::Keyword(Keyword::Bytes),
                TokenKind::StringLiteral,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn decodes_bytes_and_rejects_an_odd_length() {
        let tokens = tokenize("bytes\"deadBEEF\"").unwrap();
        assert_eq!(tokens[0].bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(tokenize("bytes\"abc\"").is_err());
        assert!(tokenize("bytes\"zz\"").is_err());
    }

    #[test]
    fn unescapes_a_string_and_rejects_a_raw_line_terminator() {
        let tokens = tokenize(r#""a\"b\\c\nd\te\u{1F600}""#).unwrap();
        assert_eq!(tokens[0].text, "a\"b\\c\nd\te\u{1F600}");
        assert!(tokenize("\"line one\nline two\"").is_err());
        assert!(tokenize("\"unterminated").is_err());
        assert!(tokenize(r#""bad \q escape""#).is_err());
    }

    #[test]
    fn separates_integers_from_floats() {
        assert_eq!(kinds("1"), vec![TokenKind::IntegerLiteral, TokenKind::Eof]);
        for float in ["1.5", "-1.5e-3", "2E+10", "0.75"] {
            assert_eq!(
                kinds(float),
                vec![TokenKind::FloatLiteral, TokenKind::Eof],
                "{float}"
            );
        }
        assert!(tokenize("1.").is_err());
        assert!(tokenize("1e").is_err());
        assert!(tokenize("-").is_err());
    }

    #[test]
    fn keeps_comments_and_records_whether_they_began_a_line() {
        let tokens = tokenize("// leading\n@nost 1 // trailing\n").unwrap();
        let comments: Vec<(&str, bool)> = tokens
            .iter()
            .filter(|token| token.is_comment())
            .map(|token| (token.text.as_str(), token.on_own_line))
            .collect();
        assert_eq!(comments, vec![("leading", true), ("trailing", false)]);
    }

    #[test]
    fn a_block_comment_must_close() {
        assert!(tokenize("/* open").is_err());
        let tokens = tokenize("/* closed */").unwrap();
        assert_eq!(tokens[0].text, " closed ");
    }

    #[test]
    fn an_unknown_directive_is_rejected() {
        assert!(tokenize("@unknown 1").is_err());
    }

    #[test]
    fn a_reserved_word_is_not_an_identifier() {
        assert_eq!(
            kinds("module node edge id source as true false"),
            vec![
                TokenKind::Keyword(Keyword::Module),
                TokenKind::Keyword(Keyword::Node),
                TokenKind::Keyword(Keyword::Edge),
                TokenKind::Keyword(Keyword::Id),
                TokenKind::Keyword(Keyword::Source),
                TokenKind::Keyword(Keyword::As),
                TokenKind::Keyword(Keyword::True),
                TokenKind::Keyword(Keyword::False),
                TokenKind::Eof
            ]
        );
        assert_eq!(
            kinds("Module nodes"),
            vec![TokenKind::Identifier, TokenKind::Identifier, TokenKind::Eof]
        );
    }

    #[test]
    fn every_token_carries_a_usable_range() {
        let tokens = tokenize("@nost 1\nmodule m id \"x\" {}\n").unwrap();
        for token in &tokens {
            assert!(token.range.start().line >= 1);
            assert!(token.range.start().column >= 1);
            assert!(token.range.end().offset >= token.range.start().offset);
        }
        // The module keyword starts on line 2.
        let module = tokens
            .iter()
            .find(|token| token.kind == TokenKind::Keyword(Keyword::Module))
            .unwrap();
        assert_eq!(module.range.start().line, 2);
        assert_eq!(module.range.start().column, 1);
    }
}
