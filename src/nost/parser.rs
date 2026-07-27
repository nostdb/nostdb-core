//! Recursive-descent parser for `.nost`.
//!
//! Comment attachment is implemented once, here, by two operations. Before a
//! construct, own-line comments accumulate as its leading comments. Immediately after
//! a construct, a comment on the same line is taken as its trailing comment. Anything
//! left when a block closes attaches to that block.

use super::lexer::{Keyword, Token, TokenKind, TriviaKind, tokenize};
use super::{
    Comment, Comments, ContributionBlock, DeclarationRef, EdgeDeclaration, Endpoint,
    EndpointConstraint, EvidenceBlock, EvidenceField, EvidenceValue, FieldType, LinkDeclaration,
    NodeDeclaration, OwnerDeclaration, ParseError, Property, RecordBody, ScalarType,
    SchemaDeclaration, SchemaField, SourceFile, Spanned, Value,
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

    fn eat(&mut self, kind: TokenKind) -> bool {
        self.skip_trivia();
        if self.kind() == kind {
            self.index += 1;
            true
        } else {
            false
        }
    }

    /// Closes one comma-separated entry, returning whether a comma followed and the
    /// comment trailing it.
    ///
    /// A trailing comment may sit on either side of the separator:
    ///
    /// ```text
    /// k: "v" // before the missing comma
    /// k: "v", // after the comma
    /// ```
    ///
    /// The comment is claimed before the comma is looked for, because looking for the
    /// comma skips trivia, and skipping trivia files every comment as a *leading* one.
    /// A same-line comment would then lead the next entry instead of trailing this one,
    /// which moves it a line down on every format pass.
    fn finish_entry(&mut self) -> (bool, Option<Comment>) {
        if let Some(comment) = self.take_trailing() {
            let separated = self.eat(TokenKind::Comma);
            return (separated, Some(comment));
        }
        let separated = self.eat(TokenKind::Comma);
        (separated, self.take_trailing())
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

    /// Parses a record block: comma-separated properties, then contribution blocks.
    ///
    /// The two are separated by shape rather than by a marker. A property starts with an
    /// identifier and a contribution starts with `@by`, so no lookahead beyond the
    /// current token is needed.
    fn parse_record_body(&mut self, leading: Vec<Comment>) -> Result<RecordBody, ParseError> {
        self.expect(TokenKind::LeftBrace, "`{` to open a record block")?;
        let head_trailing = self.take_trailing();

        let mut properties = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::Identifier {
                break;
            }
            let property_leading = self.take_pending();
            let key = self.expect_identifier("a property key")?;
            self.expect(TokenKind::Colon, "`:` after a property key")?;
            let value = self.parse_value()?;
            let (separated, trailing) = self.finish_entry();
            properties.push(Property {
                key,
                value,
                comments: Comments {
                    leading: property_leading,
                    trailing,
                },
            });
            if !separated {
                break;
            }
        }

        let mut contributions = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::ByDirective {
                break;
            }
            let contribution_leading = self.take_pending();
            contributions.push(self.parse_contribution(contribution_leading)?);
        }

        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close a record block")?;
        Ok(RecordBody {
            properties,
            contributions,
            comments: Comments {
                leading,
                trailing: head_trailing,
            },
            block_comments,
        })
    }

    fn parse_contribution(
        &mut self,
        leading: Vec<Comment>,
    ) -> Result<ContributionBlock, ParseError> {
        self.expect(TokenKind::ByDirective, "`@by`")?;
        let owner = self.parse_owner()?;

        self.skip_trivia();
        let unit = if self.kind() == TokenKind::Identifier && self.current().text == "unit" {
            self.index += 1;
            Some(self.expect_string("a quoted source unit identifier")?)
        } else {
            None
        };

        self.expect(TokenKind::LeftBrace, "`{` to open a contribution block")?;
        let head_trailing = self.take_trailing();

        let mut evidence = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::EvidenceDirective {
                break;
            }
            let evidence_leading = self.take_pending();
            evidence.push(self.parse_evidence(evidence_leading)?);
        }

        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close a contribution block")?;
        Ok(ContributionBlock {
            owner,
            unit,
            evidence,
            comments: Comments {
                leading,
                trailing: head_trailing,
            },
            block_comments,
        })
    }

    fn parse_owner(&mut self) -> Result<OwnerDeclaration, ParseError> {
        self.skip_trivia();
        if self.kind() != TokenKind::Identifier {
            return Err(self.error("expected `analyzer`, `ai`, or `user` after `@by`"));
        }
        let token = self.current().clone();
        match token.text.as_str() {
            "analyzer" => {
                self.index += 1;
                let name = self.expect_string("a quoted analyzer name")?;
                let version = self.expect_string("a quoted analyzer version")?;
                Ok(OwnerDeclaration::Analyzer { name, version })
            }
            "ai" => {
                self.index += 1;
                let contract_digest = self.expect_string("a quoted analysis contract digest")?;
                Ok(OwnerDeclaration::Ai { contract_digest })
            }
            "user" => {
                self.index += 1;
                Ok(OwnerDeclaration::User { range: token.range })
            }
            other => Err(self.error(format!(
                "expected `analyzer`, `ai`, or `user` after `@by`, found `{other}`"
            ))),
        }
    }

    fn parse_evidence(&mut self, leading: Vec<Comment>) -> Result<EvidenceBlock, ParseError> {
        let open = self.expect(TokenKind::EvidenceDirective, "`@evidence`")?;
        self.expect(TokenKind::LeftBrace, "`{` to open an evidence block")?;
        let head_trailing = self.take_trailing();

        let mut fields = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::Identifier {
                break;
            }
            let field_leading = self.take_pending();
            let key = self.expect_identifier("an evidence key")?;
            self.expect(TokenKind::Colon, "`:` after an evidence key")?;
            let value = self.parse_evidence_value()?;
            let (separated, trailing) = self.finish_entry();
            fields.push(EvidenceField {
                key,
                value,
                comments: Comments {
                    leading: field_leading,
                    trailing,
                },
            });
            if !separated {
                break;
            }
        }

        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close an evidence block")?;
        Ok(EvidenceBlock {
            fields,
            range: open.range,
            comments: Comments {
                leading,
                trailing: head_trailing,
            },
            block_comments,
        })
    }

    fn parse_evidence_value(&mut self) -> Result<Spanned<EvidenceValue>, ParseError> {
        self.skip_trivia();
        if self.kind() == TokenKind::StringLiteral {
            let text = self.expect_string("a quoted value")?;
            return Ok(Spanned {
                value: EvidenceValue::Text(text.value),
                range: text.range,
            });
        }
        let name = self.expect_identifier("a quoted value or a bare word")?;
        self.skip_trivia();
        let mut score = None;
        let mut range = name.range;
        if self.kind() == TokenKind::LeftParen {
            self.index += 1;
            self.skip_trivia();
            let token = self.current().clone();
            match token.kind {
                TokenKind::FloatLiteral | TokenKind::IntegerLiteral => {
                    self.index += 1;
                    score = Some(token.text);
                }
                _ => return Err(self.error("expected a score, written as a number")),
            }
            let close = self.expect(TokenKind::RightParen, "`)` after a score")?;
            range = SourceRange::new(name.range.start(), close.range.end()).unwrap_or(name.range);
        }
        Ok(Spanned {
            value: EvidenceValue::Enumerator {
                name: name.value,
                score,
            },
            range,
        })
    }

    fn parse_schema(&mut self, leading: Vec<Comment>) -> Result<SchemaDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Schema), "`schema`")?;
        let name = self.expect_identifier("a schema name")?;

        self.skip_trivia();
        let endpoints = if self.kind() == TokenKind::LeftParen {
            self.index += 1;
            let source = self.expect_identifier("the source schema name")?;
            self.expect(TokenKind::Arrow, "`->` between the endpoint schemas")?;
            let target = self.expect_identifier("the target schema name")?;
            self.expect(TokenKind::RightParen, "`)` after the endpoint schemas")?;
            Some(EndpointConstraint { source, target })
        } else {
            None
        };

        self.expect(TokenKind::LeftBrace, "`{` to open a field block")?;
        let head_trailing = self.take_trailing();

        let mut fields = Vec::new();
        loop {
            self.skip_trivia();
            if self.kind() != TokenKind::Identifier {
                break;
            }
            let field_leading = self.take_pending();
            let key = self.expect_identifier("a field key")?;
            let optional = self.eat(TokenKind::Question);
            self.expect(TokenKind::Colon, "`:` after a field key")?;
            let field_type = self.parse_field_type()?;
            let (separated, trailing) = self.finish_entry();
            fields.push(SchemaField {
                key,
                optional,
                field_type,
                comments: Comments {
                    leading: field_leading,
                    trailing,
                },
            });
            if !separated {
                break;
            }
        }

        let block_comments = self.take_pending();
        self.expect(TokenKind::RightBrace, "`}` to close a field block")?;
        Ok(SchemaDeclaration {
            name,
            endpoints,
            fields,
            comments: Comments {
                leading,
                trailing: head_trailing,
            },
            block_comments,
        })
    }

    fn parse_field_type(&mut self) -> Result<Spanned<FieldType>, ParseError> {
        self.skip_trivia();
        let token = self.current().clone();
        // A scalar type name is not a reserved word, so it arrives as an identifier
        // except for `bytes` and `datetime`, which are reserved as literal tags.
        let text = match token.kind {
            TokenKind::Identifier => token.text.clone(),
            TokenKind::Keyword(Keyword::Bytes) => "bytes".to_owned(),
            TokenKind::Keyword(Keyword::Datetime) => "datetime".to_owned(),
            _ => return Err(self.error("expected a field type")),
        };
        let Some(scalar) = ScalarType::from_text(&text) else {
            return Err(self.error(format!(
                "`{text}` is not a field type; expected boolean, integer, double, string, \
                 bytes, or datetime, optionally followed by `[]`"
            )));
        };
        self.index += 1;

        let mut range = token.range;
        let mut array = false;
        if self.kind() == TokenKind::LeftBracket {
            self.index += 1;
            let close = self.expect(TokenKind::RightBracket, "`]` to close an array type")?;
            array = true;
            range = SourceRange::new(token.range.start(), close.range.end()).unwrap_or(token.range);
            self.skip_trivia();
            if self.kind() == TokenKind::LeftBracket {
                return Err(self.error("an array does not nest, so `[][]` is not a field type"));
            }
        }
        Ok(Spanned {
            value: FieldType { scalar, array },
            range,
        })
    }

    fn parse_node(&mut self, leading: Vec<Comment>) -> Result<NodeDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Node), "`node`")?;
        let name = self.expect_identifier("a node name")?;
        self.expect(TokenKind::Colon, "`:` before the schema names")?;

        let mut schemas = vec![self.expect_identifier("a schema name")?];
        while self.eat(TokenKind::Comma) {
            schemas.push(self.expect_identifier("a schema name")?);
        }

        let record = self.parse_record_body(leading)?;
        Ok(NodeDeclaration {
            name,
            schemas,
            record,
        })
    }

    fn parse_edge(&mut self, leading: Vec<Comment>) -> Result<EdgeDeclaration, ParseError> {
        self.expect(TokenKind::Keyword(Keyword::Edge), "`edge`")?;
        let source = self.parse_endpoint()?;
        self.expect(TokenKind::Arrow, "`->` between the endpoints")?;
        let target = self.parse_endpoint()?;
        self.expect(TokenKind::Colon, "`:` before a relation name")?;
        let relation = self.expect_identifier("a relation name")?;
        let record = self.parse_record_body(leading)?;
        Ok(EdgeDeclaration {
            source,
            target,
            relation,
            record,
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
/// [`super::validate`]. In particular an unsupported language version parses, because
/// refusing it is a semantic decision that needs the version's value.
///
/// # Errors
///
/// Returns a [`ParseError`] carrying a source range for any input the grammar does not
/// accept, including a byte-order mark, a link declaration after a record declaration, a
/// reserved word where a name is required, an unknown field type, and a nested or
/// trailing-comma list.
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

    let mut schemas = Vec::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut order = Vec::new();
    loop {
        parser.skip_trivia();
        let leading = match parser.kind() {
            TokenKind::Keyword(Keyword::Schema | Keyword::Node | Keyword::Edge) => {
                parser.take_pending()
            }
            _ => break,
        };
        match parser.kind() {
            TokenKind::Keyword(Keyword::Schema) => {
                order.push(DeclarationRef::Schema(schemas.len()));
                schemas.push(parser.parse_schema(leading)?);
            }
            TokenKind::Keyword(Keyword::Node) => {
                order.push(DeclarationRef::Node(nodes.len()));
                nodes.push(parser.parse_node(leading)?);
            }
            _ => {
                order.push(DeclarationRef::Edge(edges.len()));
                edges.push(parser.parse_edge(leading)?);
            }
        }
    }

    parser.skip_trivia();
    let trailing_comments = parser.take_pending();
    if parser.kind() != TokenKind::Eof {
        let message = if parser.kind() == TokenKind::LinkDirective {
            "a link declaration must come before every schema, node, and edge declaration"
        } else {
            "expected `schema`, `node`, `edge`, or the end of the file"
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
        schemas,
        nodes,
        edges,
        order,
        trailing_comments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_smallest_file() {
        let file = parse("@nost 2\n").unwrap();
        assert_eq!(file.version.value, 2);
        assert!(file.links.is_empty());
        assert!(file.schemas.is_empty());
        assert!(file.nodes.is_empty());
        assert!(file.edges.is_empty());
    }

    #[test]
    fn parses_links_with_and_without_an_alias() {
        let file = parse("@nost 2\n@link \"./a\"\n@link \"./b\" as b\n").unwrap();
        assert_eq!(file.links.len(), 2);
        assert_eq!(file.links[0].source.value, "./a");
        assert!(file.links[0].alias.is_none());
        assert_eq!(
            file.links[1].alias.as_ref().map(|a| a.value.as_str()),
            Some("b")
        );
    }

    #[test]
    fn parses_a_schema_with_required_optional_and_array_fields() {
        let file = parse(
            "@nost 2\nschema S {\n  a: string,\n  b?: integer,\n  c: double[],\n  d?: bytes,\n}\n",
        )
        .unwrap();
        let schema = &file.schemas[0];
        assert_eq!(schema.name.value, "S");
        assert!(schema.endpoints.is_none());
        assert_eq!(schema.fields.len(), 4);
        assert!(!schema.fields[0].optional);
        assert_eq!(schema.fields[0].field_type.value.scalar, ScalarType::String);
        assert!(schema.fields[1].optional);
        assert!(schema.fields[2].field_type.value.array);
        assert_eq!(schema.fields[3].field_type.value.scalar, ScalarType::Bytes);
    }

    #[test]
    fn parses_an_edge_schema_endpoint_constraint() {
        let file = parse("@nost 2\nschema R (A -> B) {\n  since?: datetime,\n}\n").unwrap();
        let constraint = file.schemas[0].endpoints.as_ref().unwrap();
        assert_eq!(constraint.source.value, "A");
        assert_eq!(constraint.target.value, "B");
    }

    #[test]
    fn a_node_may_name_several_schemas() {
        let file = parse("@nost 2\nnode n: A, B, C {}\n").unwrap();
        let names: Vec<&str> = file.nodes[0]
            .schemas
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert_eq!(names, ["A", "B", "C"]);
    }

    #[test]
    fn parses_all_three_endpoint_forms() {
        let source = "@nost 2\n@link \"./c\"\n@link \"./s\" as s\n\
            node a: L {}\nnode b: L {}\n\
            edge a -> b :CALLS {}\n\
            edge a -> s::x :CALLS {}\n\
            edge a -> \"./c\"::y :CALLS {}\n";
        let file = parse(source).unwrap();
        assert_eq!(file.nodes.len(), 2);
        assert_eq!(file.edges.len(), 3);
        assert!(matches!(file.edges[0].source, Endpoint::Local(_)));
        assert!(matches!(file.edges[1].target, Endpoint::Aliased { .. }));
        assert!(matches!(file.edges[2].target, Endpoint::Locator { .. }));
    }

    #[test]
    fn a_trailing_comma_is_accepted_and_optional() {
        assert!(parse("@nost 2\nnode n: L {\n  a: 1,\n  b: 2,\n}\n").is_ok());
        assert!(parse("@nost 2\nnode n: L {\n  a: 1,\n  b: 2\n}\n").is_ok());
        assert!(parse("@nost 2\nschema S {\n  a: string,\n}\n").is_ok());
        assert!(parse("@nost 2\nschema S {\n  a: string\n}\n").is_ok());
    }

    #[test]
    fn a_property_must_be_separated_by_a_comma() {
        // Without the comma the second key is not read as a property, so the block does
        // not close where the author expected.
        let error = parse("@nost 2\nnode n: L {\n  a: 1\n  b: 2\n}\n").unwrap_err();
        assert!(error.message.contains("close a record block"), "{error}");
    }

    #[test]
    fn parses_contributions_and_evidence() {
        let source = "@nost 2\nnode n: L {\n  k: \"v\",\n\n\
            \x20 @by analyzer \"rust\" \"0.1.0\" unit \"u_1\" {\n\
            \x20   @evidence {\n      source: \"./\",\n      method: deterministic,\n\
            \x20     confidence: inferred(0.5),\n    }\n  }\n\n  @by user {}\n}\n";
        let file = parse(source).unwrap();
        let record = &file.nodes[0].record;
        assert_eq!(record.contributions.len(), 2);

        let first = &record.contributions[0];
        assert!(matches!(first.owner, OwnerDeclaration::Analyzer { .. }));
        assert_eq!(first.unit.as_ref().map(|u| u.value.as_str()), Some("u_1"));
        assert_eq!(first.evidence.len(), 1);
        let fields = &first.evidence[0].fields;
        assert_eq!(fields[0].key.value, "source");
        assert_eq!(
            fields[1].value.value,
            EvidenceValue::Enumerator {
                name: "deterministic".to_owned(),
                score: None
            }
        );
        assert_eq!(
            fields[2].value.value,
            EvidenceValue::Enumerator {
                name: "inferred".to_owned(),
                score: Some("0.5".to_owned())
            }
        );

        assert!(matches!(
            record.contributions[1].owner,
            OwnerDeclaration::User { .. }
        ));
        assert!(record.contributions[1].evidence.is_empty());
    }

    #[test]
    fn an_ai_owner_carries_its_contract_digest() {
        let file = parse("@nost 2\nnode n: L {\n  @by ai \"sha256:abc\" {}\n}\n").unwrap();
        match &file.nodes[0].record.contributions[0].owner {
            OwnerDeclaration::Ai { contract_digest } => {
                assert_eq!(contract_digest.value, "sha256:abc");
            }
            other => panic!("expected an AI owner, found {other:?}"),
        }
    }

    #[test]
    fn declaration_order_is_preserved() {
        let file = parse("@nost 2\nnode a: L {}\nschema L {}\nedge a -> a :R {}\n").unwrap();
        assert_eq!(
            file.order,
            [
                DeclarationRef::Node(0),
                DeclarationRef::Schema(0),
                DeclarationRef::Edge(0)
            ]
        );
    }

    #[test]
    fn attaches_leading_and_trailing_comments() {
        let source = "// file\n@nost 2 // version\n\
            // about the node\nnode n: L {\n\
            \x20 // about the key\n  k: \"v\", // after the key\n}\n";
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
        let node = &file.nodes[0];
        assert_eq!(node.record.comments.leading[0].text, "about the node");
        let property = &node.record.properties[0];
        assert_eq!(property.comments.leading[0].text, "about the key");
        assert_eq!(
            property.comments.trailing.as_ref().map(|c| c.text.as_str()),
            Some("after the key")
        );
    }

    #[test]
    fn a_comment_with_nothing_after_it_attaches_to_the_block() {
        let file = parse("@nost 2\nnode n: L {\n  // nothing follows\n}\n").unwrap();
        assert_eq!(file.nodes[0].record.block_comments.len(), 1);
        assert_eq!(
            file.nodes[0].record.block_comments[0].text,
            "nothing follows"
        );
    }

    #[test]
    fn a_link_after_a_declaration_is_rejected_with_a_useful_message() {
        let error = parse("@nost 2\nschema S {}\n@link \"./a\"\n").unwrap_err();
        assert!(error.message.contains("before every schema"), "{error}");
        assert_eq!(error.range.start().line, 3);
    }

    #[test]
    fn a_reserved_word_where_a_name_belongs_is_named_in_the_message() {
        let error = parse("@nost 2\nschema schema {}\n").unwrap_err();
        assert!(error.message.contains("reserved word"), "{error}");
    }

    #[test]
    fn the_version_1_module_declaration_no_longer_parses() {
        let error = parse("@nost 2\nmodule auth id \"m_1\" {\n}\n").unwrap_err();
        assert!(error.message.contains("expected `schema`"), "{error}");
    }

    #[test]
    fn the_version_1_edge_form_no_longer_parses() {
        let error = parse("@nost 2\nedge e id \"e_1\" :CALLS (a -> b) {}\n").unwrap_err();
        assert!(error.message.contains("`->`"), "{error}");
    }

    #[test]
    fn rejects_the_syntax_the_contract_forbids() {
        for (source, note) in [
            ("@link \"./a\"\n", "a missing version header"),
            ("\u{FEFF}@nost 2\n", "a byte-order mark"),
            ("@nost 2\nnode n {\n}\n", "a node without a schema"),
            (
                "@nost 2\nnode n: A, {\n}\n",
                "a trailing comma in a schema list",
            ),
            ("@nost 2\nnode n: L {\n k: null\n}\n", "a null value"),
            (
                "@nost 2\nnode n: L {\n k: [1, 2,]\n}\n",
                "a trailing comma in a list",
            ),
            ("@nost 2\nnode n: L {\n k: [1, [2]]\n}\n", "a nested list"),
            ("@nost 2\nedge a -> :R {}\n", "a missing endpoint"),
            ("@nost 2\nedge a -> b :R :S {}\n", "two relation names"),
            (
                "@nost 2\nschema S {\n name: text,\n}\n",
                "an unknown field type",
            ),
            (
                "@nost 2\nschema S {\n g: string[][],\n}\n",
                "a nested array type",
            ),
            ("@nost 2\nschema S {\n name,\n}\n", "a field without a type"),
        ] {
            let result = parse(source);
            assert!(result.is_err(), "{note} must be rejected");
            let error = result.unwrap_err();
            assert!(error.range.start().line >= 1, "{note} needs a range");
        }
    }

    #[test]
    fn an_unknown_field_type_says_what_is_accepted() {
        let error = parse("@nost 2\nschema S {\n  name: text,\n}\n").unwrap_err();
        assert!(
            error.message.contains("`text` is not a field type"),
            "{error}"
        );
        assert!(error.message.contains("double"), "{error}");
    }

    #[test]
    fn an_out_of_range_integer_parses_because_that_is_a_semantic_rule() {
        let file = parse("@nost 2\nnode n: L {\n  k: 9223372036854775808,\n}\n").unwrap();
        assert_eq!(
            file.nodes[0].record.properties[0].value.value,
            Value::Integer("9223372036854775808".to_owned())
        );
    }

    #[test]
    fn an_unsupported_version_parses_because_refusing_it_is_semantic() {
        assert_eq!(parse("@nost 1\n").unwrap().version.value, 1);
        assert_eq!(parse("@nost 99\n").unwrap().version.value, 99);
    }
}
