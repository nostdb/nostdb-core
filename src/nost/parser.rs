//! Recursive-descent parser for `.nost`.
//!
//! Comment attachment is implemented once, here, by two operations. Before a
//! construct, own-line comments accumulate as its leading comments. Immediately after
//! a construct, a comment on the same line is taken as its trailing comment. Anything
//! left when a block closes attaches to that block.

use super::lexer::{Keyword, Token, TokenKind, TriviaKind, tokenize};
use super::{
    Comment, Comments, EdgeDeclaration, Endpoint, LinkDeclaration, ModuleDeclaration,
    NodeDeclaration, ParseError, Property, SourceFile, Spanned, Value,
};
use crate::evidence::SourceRange;

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    pending: Vec<Comment>,
}

impl Parser {
    fn current(&self) -> &Token {
        // The token stream always ends with Eof, so this index is always valid; the
        // fallback keeps the parser panic-free.
        self.tokens
            .get(self.index)
            .or_else(|| self.tokens.last())
            .unwrap_or(&EOF_SENTINEL)
    }

    fn kind(&self) -> TokenKind {
        self.current().kind
    }

    fn range(&self) -> SourceRange {
        self.current().range
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            range: self.range(),
        }
    }

    /// Skips trivia, collecting own-line comments as pending leading comments.
    fn skip_trivia(&mut self) {
        while self.index < self.tokens.len() {
            let token = self.current();
            match token.kind {
                TokenKind::Trivia(TriviaKind::Whitespace) => self.index += 1,
                TokenKind::Trivia(kind @ (TriviaKind::LineComment | TriviaKind::BlockComment)) => {
                    self.pending.push(Comment {
                        text: token.text.clone(),
                        block: kind == TriviaKind::BlockComment,
                        range: token.range,
                    });
                    self.index += 1;
                }
                _ => break,
            }
        }
    }

    /// Takes a comment on the same line as the construct just parsed.
    fn take_trailing(&mut self) -> Option<Comment> {
        let restore = self.index;
        let mut cursor = self.index;
        while let Some(token) = self.tokens.get(cursor) {
            match token.kind {
                TokenKind::Trivia(TriviaKind::Whitespace) => cursor += 1,
                TokenKind::Trivia(TriviaKind::LineComment | TriviaKind::BlockComment)
                    if !token.on_own_line =>
                {
                    let comment = Comment {
                        text: token.text.clone(),
                        block: matches!(token.kind, TokenKind::Trivia(TriviaKind::BlockComment)),
                        range: token.range,
                    };
                    self.index = cursor + 1;
                    return Some(comment);
                }
                _ => break,
            }
        }
        self.index = restore;
        None
    }

    fn take_pending(&mut self) -> Vec<Comment> {
        std::mem::take(&mut self.pending)
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> Result<Token, ParseError> {
        self.skip_trivia();
        if self.kind() == kind {
            let token = self.current().clone();
            self.index += 1;
            Ok(token)
        } else {
            Err(self.error(format!("expected {what}")))
        }
    }

    fn expect_identifier(&mut self, what: &str) -> Result<Spanned<String>, ParseError> {
        self.skip_trivia();
        match self.kind() {
            TokenKind::Identifier => {
                let token = self.current().clone();
                self.index += 1;
                Ok(Spanned {
                    value: token.text,
                    range: token.range,
                })
            }
            TokenKind::Keyword(word) => Err(self.error(format!(
                "expected {what}, found the reserved word `{}`",
                word.as_str()
            ))),
            _ => Err(self.error(format!("expected {what}"))),
        }
    }

    fn expect_string(&mut self, what: &str) -> Result<Spanned<String>, ParseError> {
        let token = self.expect(TokenKind::StringLiteral, what)?;
        Ok(Spanned {
            value: token.text,
            range: token.range,
        })
    }

    fn parse_id_clause(&mut self) -> Result<Spanned<String>, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Id), "`id`")?;
        self.expect_string("a quoted record identifier")
    }

    fn parse_labels(&mut self) -> Result<Vec<Spanned<String>>, ParseError> {
        let mut labels = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::Colon {
                break;
            }
            self.index += 1;
            labels.push(self.expect_identifier("a label")?);
        }
        if labels.is_empty() {
            return Err(self.error("expected at least one label, written `:Label`"));
        }
        Ok(labels)
    }

    fn parse_endpoint(&mut self) -> Result<Endpoint, ParseError> {
        self.skip_trivia();
        if self.kind() == TokenKind::StringLiteral {
            let locator = self.expect_string("a locator")?;
            self.expect(TokenKind::ColonColon, "`::` after a locator")?;
            let name = self.expect_identifier("a declaration name")?;
            return Ok(Endpoint::Locator { locator, name });
        }
        let first = self.expect_identifier("an endpoint")?;
        self.skip_trivia();
        if self.kind() == TokenKind::ColonColon {
            self.index += 1;
            let name = self.expect_identifier("a declaration name")?;
            return Ok(Endpoint::Aliased { alias: first, name });
        }
        Ok(Endpoint::Local(first))
    }

    fn parse_scalar(&mut self) -> Result<Spanned<Value>, ParseError> {
        self.skip_trivia();
        let token = self.current().clone();
        let value = match token.kind {
            TokenKind::Keyword(Keyword::True) => Value::Boolean(true),
            TokenKind::Keyword(Keyword::False) => Value::Boolean(false),
            TokenKind::IntegerLiteral => Value::Integer(token.text.clone()),
            TokenKind::FloatLiteral => Value::Float(token.text.clone()),
            TokenKind::StringLiteral => Value::String(token.text.clone()),
            TokenKind::BytesLiteral => Value::Bytes {
                decoded: token.bytes.clone(),
                digits: token.text.clone(),
            },
            TokenKind::DateTimeLiteral => Value::DateTime(token.text.clone()),
            TokenKind::LeftBracket => {
                return Err(self.error("a list holds scalars only, so it does not nest"));
            }
            _ => return Err(self.error("expected a scalar value")),
        };
        self.index += 1;
        Ok(Spanned {
            value,
            range: token.range,
        })
    }

    fn parse_value(&mut self) -> Result<Spanned<Value>, ParseError> {
        self.skip_trivia();
        if self.kind() != TokenKind::LeftBracket {
            return self.parse_scalar();
        }
        let open = self.range();
        self.index += 1;
        let mut items = Vec::new();
        self.skip_trivia();
        if self.kind() != TokenKind::RightBracket {
            loop {
                items.push(self.parse_scalar()?);
                self.skip_trivia();
                if self.kind() == TokenKind::Comma {
                    self.index += 1;
                    self.skip_trivia();
                    if self.kind() == TokenKind::RightBracket {
                        return Err(self.error("a list takes no trailing comma"));
                    }
                    continue;
                }
                break;
            }
        }
        let close = self.expect(TokenKind::RightBracket, "`]`")?;
        Ok(Spanned {
            value: Value::List(items),
            range: SourceRange::new(open.start(), close.range.end()).unwrap_or(open),
        })
    }

    fn parse_property_block(&mut self) -> Result<(Vec<Property>, Vec<Comment>), ParseError> {
        self.expect(TokenKind::LeftBrace, "`{`")?;
        let mut properties = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::Identifier {
                break;
            }
            let leading = self.take_pending();
            let key = self.expect_identifier("a property key")?;
            self.expect(TokenKind::Colon, "`:` after a property key")?;
            let value = self.parse_value()?;
            let trailing = self.take_trailing();
            properties.push(Property {
                key,
                value,
                comments: Comments { leading, trailing },
            });
        }
        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close a property block")?;
        Ok((properties, block_comments))
    }

    fn parse_node(
        &mut self,
        comments_leading: Vec<Comment>,
    ) -> Result<NodeDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Node), "`node`")?;
        let name = self.expect_identifier("a node name")?;
        let id = self.parse_id_clause()?;
        let labels = self.parse_labels()?;
        let (properties, block_comments) = self.parse_property_block()?;
        let trailing = self.take_trailing();
        Ok(NodeDeclaration {
            name,
            id,
            labels,
            properties,
            comments: Comments {
                leading: comments_leading,
                trailing,
            },
            block_comments,
        })
    }

    fn parse_edge(
        &mut self,
        comments_leading: Vec<Comment>,
    ) -> Result<EdgeDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Edge), "`edge`")?;
        let name = self.expect_identifier("an edge name")?;
        let id = self.parse_id_clause()?;
        self.expect(TokenKind::Colon, "`:` before a relation name")?;
        let relation = self.expect_identifier("a relation name")?;
        self.expect(TokenKind::LeftParen, "`(` before the endpoints")?;
        let source = self.parse_endpoint()?;
        self.expect(TokenKind::Arrow, "`->` between the endpoints")?;
        let target = self.parse_endpoint()?;
        self.expect(TokenKind::RightParen, "`)` after the endpoints")?;
        let (properties, block_comments) = self.parse_property_block()?;
        let trailing = self.take_trailing();
        Ok(EdgeDeclaration {
            name,
            id,
            relation,
            source,
            target,
            properties,
            comments: Comments {
                leading: comments_leading,
                trailing,
            },
            block_comments,
        })
    }

    fn parse_module(&mut self, leading: Vec<Comment>) -> Result<ModuleDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Module), "`module`")?;
        let name = self.expect_identifier("a module name")?;
        let id = self.parse_id_clause()?;
        self.skip_trivia();
        let source = if self.kind() == TokenKind::Keyword(Keyword::Source) {
            self.index += 1;
            Some(self.expect_string("a quoted source locator")?)
        } else {
            None
        };
        self.expect(TokenKind::LeftBrace, "`{` to open a module body")?;
        let head_trailing = self.take_trailing();

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        loop {
            self.skip_trivia();
            match self.kind() {
                TokenKind::Keyword(Keyword::Node) => {
                    let item_leading = self.take_pending();
                    nodes.push(self.parse_node(item_leading)?);
                }
                TokenKind::Keyword(Keyword::Edge) => {
                    let item_leading = self.take_pending();
                    edges.push(self.parse_edge(item_leading)?);
                }
                TokenKind::RightBrace => break,
                _ => return Err(self.error("expected `node`, `edge`, or `}`")),
            }
        }
        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close a module body")?;

        // A comment after the closing brace is deliberately not taken here. The head
        // already owns this declaration's trailing slot, and taking a second one would
        // have to discard one of the two. Leaving it in the stream lets it attach to
        // whatever follows, so no comment is ever lost.
        Ok(ModuleDeclaration {
            name,
            id,
            source,
            nodes,
            edges,
            comments: Comments {
                leading,
                trailing: head_trailing,
            },
            block_comments,
        })
    }
}

/// A `static` rather than a `const`, so a reference to it can be returned.
static EOF_SENTINEL: Token = Token {
    kind: TokenKind::Eof,
    range: SourceRange::ORIGIN,
    text: String::new(),
    bytes: Vec::new(),
    on_own_line: false,
};

/// Parses a `.nost` file into a comment-preserving tree.
///
/// This reports syntax only. A file that parses may still break a semantic rule; see
/// [`super::validate`].
///
/// # Errors
///
/// Returns a [`ParseError`] carrying a source range for any input the grammar does not
/// accept, including a byte-order mark, a link declaration after a module, a reserved
/// word where a name is required, and a nested or trailing-comma list.
pub fn parse(source: &str) -> Result<SourceFile, ParseError> {
    let tokens = tokenize(source)?;
    let mut parser = Parser {
        tokens,
        index: 0,
        pending: Vec::new(),
    };

    parser.skip_trivia();
    let version_leading = parser.take_pending();
    parser.expect(TokenKind::NostDirective, "`@nost` as the first declaration")?;
    let version_token = parser.expect(TokenKind::IntegerLiteral, "a language version number")?;
    let version_value: u32 = version_token.text.parse().map_err(|_| ParseError {
        message: "the language version must be a non-negative whole number".to_owned(),
        range: version_token.range,
    })?;
    let version_trailing = parser.take_trailing();

    let mut links = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.kind() != TokenKind::LinkDirective {
            break;
        }
        let leading = parser.take_pending();
        parser.index += 1;
        let source_locator = parser.expect_string("a quoted link locator")?;
        parser.skip_trivia();
        let alias = if parser.kind() == TokenKind::Keyword(Keyword::As) {
            parser.index += 1;
            Some(parser.expect_identifier("a link alias")?)
        } else {
            None
        };
        let trailing = parser.take_trailing();
        links.push(LinkDeclaration {
            source: source_locator,
            alias,
            comments: Comments { leading, trailing },
        });
    }

    let mut modules = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.kind() != TokenKind::Keyword(Keyword::Module) {
            break;
        }
        let leading = parser.take_pending();
        modules.push(parser.parse_module(leading)?);
    }

    parser.skip_trivia();
    let trailing_comments = parser.take_pending();
    if parser.kind() != TokenKind::Eof {
        let message = if parser.kind() == TokenKind::LinkDirective {
            "a link declaration must come before every module declaration"
        } else {
            "expected `module` or the end of the file"
        };
        return Err(parser.error(message));
    }

    Ok(SourceFile {
        version: Spanned {
            value: version_value,
            range: version_token.range,
        },
        version_comments: Comments {
            leading: version_leading,
            trailing: version_trailing,
        },
        links,
        modules,
        trailing_comments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_smallest_file() {
        let file = parse("@nost 1\n").unwrap();
        assert_eq!(file.version.value, 1);
        assert!(file.links.is_empty());
        assert!(file.modules.is_empty());
    }

    #[test]
    fn parses_links_with_and_without_an_alias() {
        let file = parse("@nost 1\n@link \"./a\"\n@link \"./b\" as b\n").unwrap();
        assert_eq!(file.links.len(), 2);
        assert_eq!(file.links[0].source.value, "./a");
        assert!(file.links[0].alias.is_none());
        assert_eq!(
            file.links[1].alias.as_ref().map(|a| a.value.as_str()),
            Some("b")
        );
    }

    #[test]
    fn parses_all_three_endpoint_forms() {
        let source = "@nost 1\n@link \"./c\"\n@link \"./s\" as s\n\
            module m id \"m_1\" {\n  node a id \"n_1\" :L {}\n  node b id \"n_2\" :L {}\n\
            edge e1 id \"e_1\" :CALLS (a -> b) {}\n\
            edge e2 id \"e_2\" :CALLS (a -> s::x) {}\n\
            edge e3 id \"e_3\" :CALLS (a -> \"./c\"::y) {}\n}\n";
        let file = parse(source).unwrap();
        let module = &file.modules[0];
        assert_eq!(module.nodes.len(), 2);
        assert_eq!(module.edges.len(), 3);
        assert!(matches!(module.edges[0].source, Endpoint::Local(_)));
        assert!(matches!(module.edges[1].target, Endpoint::Aliased { .. }));
        assert!(matches!(module.edges[2].target, Endpoint::Locator { .. }));
    }

    #[test]
    fn a_module_source_clause_is_optional() {
        assert!(parse("@nost 1\nmodule m id \"m_1\" {}\n").is_ok());
        let file = parse("@nost 1\nmodule m id \"m_1\" source \"src/a.rs\" {}\n").unwrap();
        assert_eq!(
            file.modules[0].source.as_ref().map(|s| s.value.as_str()),
            Some("src/a.rs")
        );
    }

    #[test]
    fn attaches_leading_and_trailing_comments() {
        let source = "// file\n@nost 1 // version\n\
            module m id \"m_1\" {\n  // about the node\n  node n id \"n_1\" :L {\n\
            \x20   // about the key\n    k: \"v\" // after the key\n  }\n}\n";
        let file = parse(source).unwrap();
        assert_eq!(file.version_comments.leading.len(), 1);
        assert_eq!(file.version_comments.leading[0].text, "file");
        assert_eq!(
            file.version_comments
                .trailing
                .as_ref()
                .map(|c| c.text.as_str()),
            Some("version")
        );
        let node = &file.modules[0].nodes[0];
        assert_eq!(node.comments.leading[0].text, "about the node");
        let property = &node.properties[0];
        assert_eq!(property.comments.leading[0].text, "about the key");
        assert_eq!(
            property.comments.trailing.as_ref().map(|c| c.text.as_str()),
            Some("after the key")
        );
    }

    #[test]
    fn a_comment_with_nothing_after_it_attaches_to_the_block() {
        let file = parse("@nost 1\nmodule m id \"m_1\" {\n  // nothing follows\n}\n").unwrap();
        assert_eq!(file.modules[0].block_comments.len(), 1);
        assert_eq!(file.modules[0].block_comments[0].text, "nothing follows");
    }

    #[test]
    fn a_link_after_a_module_is_rejected_with_a_useful_message() {
        let error = parse("@nost 1\nmodule m id \"m_1\" {}\n@link \"./a\"\n").unwrap_err();
        assert!(error.message.contains("before every module"), "{error}");
        assert_eq!(error.range.start().line, 3);
    }

    #[test]
    fn a_reserved_word_where_a_name_belongs_is_named_in_the_message() {
        let error = parse("@nost 1\nmodule module id \"m_1\" {}\n").unwrap_err();
        assert!(error.message.contains("reserved word"), "{error}");
    }

    #[test]
    fn rejects_the_syntax_the_contract_forbids() {
        for (source, note) in [
            ("@link \"./a\"\n", "a missing version header"),
            ("\u{FEFF}@nost 1\n", "a byte-order mark"),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node n id \"x\" {}\n}\n",
                "a node without a label",
            ),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node n id \"x\" :L {\n  k: null\n }\n}\n",
                "a null value",
            ),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node n id \"x\" :L {\n  k: [1, 2,]\n }\n}\n",
                "a trailing comma",
            ),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node n id \"x\" :L {\n  k: [1, [2]]\n }\n}\n",
                "a nested list",
            ),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node a id \"x\" :L {}\n edge e id \"y\" :R (a -> ) {}\n}\n",
                "a missing endpoint",
            ),
            (
                "@nost 1\nmodule m id \"m_1\" {\n node a id \"x\" :L {}\n node b id \"y\" :L {}\n edge e id \"z\" :R :S (a -> b) {}\n}\n",
                "two relation labels",
            ),
        ] {
            let result = parse(source);
            assert!(result.is_err(), "{note} must be rejected");
            let error = result.unwrap_err();
            assert!(error.range.start().line >= 1, "{note} needs a range");
        }
    }

    #[test]
    fn an_out_of_range_integer_parses_because_that_is_a_semantic_rule() {
        let file = parse(
            "@nost 1\nmodule m id \"m_1\" {\n node n id \"x\" :L {\n  k: 9223372036854775808\n }\n}\n",
        )
        .unwrap();
        assert_eq!(
            file.modules[0].nodes[0].properties[0].value.value,
            Value::Integer("9223372036854775808".to_owned())
        );
    }
}
