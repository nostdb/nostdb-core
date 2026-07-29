//! Reads Go structure, without resolving anything.
//!
//! # Declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `package p` | consumed |
//! | `import "p"`, `import a "p"`, `import ( … )` | an import, whose path is `p` |
//! | `type T struct { … }` | [`ItemKind::Struct`], its fields as children |
//! | `type T interface { … }` | [`ItemKind::Trait`], its methods as children |
//! | `type T = U`, `type T U` | [`ItemKind::TypeAlias`] |
//! | `func f()` | [`ItemKind::Function`] |
//! | `func (r T) m()` | [`ItemKind::Method`], with `T` as its target |
//! | `const`, `var` at file scope, grouped or not | [`ItemKind::Constant`] |
//! | a call in a body | a reference |
//!
//! # The receiver, which no other language here writes
//!
//! `func (s *Service) Do()` declares a method **and** says what type it is on, in the declaration itself.
//! Every other language in this module puts a method inside the type's body, so its owner is where it
//! sits; Go's methods may live in any file of the package, and often not the file the type is declared in.
//!
//! So the method is recorded at file scope with [`Item::target`] naming the receiver's type, and
//! [`crate::build`] draws the `FOR_TYPE` edge from it. What is deliberately **not** done is inventing a
//! grouping declaration to hold them: Rust has an `impl` block because somebody wrote one, and
//! manufacturing one here would put a declaration in the graph that appears nowhere in the source.
//!
//! The pointer is dropped from the target, because `*Service` and `Service` are one type to a reader
//! asking what methods it has.
//!
//! # Why `interface` is a trait and its embedded names are references
//!
//! An interface lists method signatures and may embed another interface. The signatures are its members;
//! an embedded name is a reference, because at [`PrecisionClass::DeterministicSyntactic`] there is no
//! telling an embedded interface from a method with no parentheses yet in a file being edited.

use super::go_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads.
pub const LANGUAGE: &str = "go";

/// This analyzer's version, which is part of its identity for ownership purposes.
pub const VERSION: &str = "1";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// What this analyzer declares it extracts.
#[must_use]
pub fn capability() -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(LANGUAGE).unwrap_or_else(|_| NonEmptyText::literal("go")),
        precision: PRECISION,
        facts: vec![
            FactKind::File,
            FactKind::Type,
            FactKind::Function,
            FactKind::Method,
            FactKind::Field,
            FactKind::Declaration,
            FactKind::Definition,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::SourceRange,
            FactKind::ContentHash,
        ],
        version: NonEmptyText::new(VERSION).unwrap_or_else(|_| NonEmptyText::literal("1")),
    }
}

/// Reads one Go file.
///
/// Never fails. Malformed input yields whatever declarations could be read.
#[must_use]
pub fn analyze(source: &str) -> FileAnalysis {
    let tokens = tokenize(source);
    let mut reader = Reader {
        tokens: &tokens,
        at: 0,
        imports: Vec::new(),
    };
    let items = reader.declarations();
    FileAnalysis {
        language: LANGUAGE.to_owned(),
        digest: crate::sync::digest_bytes(source.as_bytes()),
        items,
        imports: reader.imports,
    }
}

struct Reader<'a> {
    tokens: &'a [Spanned],
    at: usize,
    imports: Vec<Import>,
}

impl Reader<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at).map(|held| &held.token)
    }

    fn name_here(&self) -> Option<&str> {
        self.peek().and_then(Token::name)
    }

    fn position(&self) -> SourcePosition {
        let held = self
            .tokens
            .get(self.at)
            .or_else(|| self.tokens.last())
            .map(|held| (held.line, held.column))
            .unwrap_or((1, 1));
        SourcePosition {
            line: held.0,
            column: held.1,
            offset: 0,
        }
    }

    fn previous_position(&self) -> SourcePosition {
        let index = self.at.saturating_sub(1);
        let held = self
            .tokens
            .get(index)
            .map(|held| (held.line, held.column))
            .unwrap_or((1, 1));
        SourcePosition {
            line: held.0,
            column: held.1,
            offset: 0,
        }
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.at).map(|held| &held.token);
        if token.is_some() {
            self.at += 1;
        }
        token
    }

    /// Every declaration in the file. Go has no nested declaration at file scope.
    fn declarations(&mut self) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            let Some(token) = self.peek() else {
                return items;
            };
            if matches!(token, Token::Close(Delimiter::Brace)) {
                // A stray brace in a file being edited. Consumed rather than returned on, so the
                // declarations after it are still read.
                self.advance();
                continue;
            }
            match self.name_here() {
                Some("package") => {
                    self.advance();
                    self.advance();
                }
                Some("import") => self.import_declaration(),
                Some("type") => items.extend(self.type_declaration()),
                Some("func") => {
                    if let Some(item) = self.function_declaration() {
                        items.push(item);
                    }
                }
                Some("const" | "var") => items.extend(self.value_declaration()),
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// `import "p"`, `import a "p"`, `import _ "p"`, and a parenthesised group of them.
    fn import_declaration(&mut self) {
        let start = self.position();
        self.advance();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.advance();
            loop {
                match self.peek() {
                    Some(Token::Close(Delimiter::Paren)) | None => {
                        self.advance();
                        return;
                    }
                    Some(Token::Text(path)) => {
                        let path = path.clone();
                        self.advance();
                        self.push_import(path, start);
                    }
                    // An alias, `_`, or a `.`, each of which precedes the path.
                    _ => {
                        self.advance();
                    }
                }
            }
        }
        // A single import, with or without an alias before the path.
        while let Some(token) = self.peek() {
            match token {
                Token::Text(path) => {
                    let path = path.clone();
                    self.advance();
                    self.push_import(path, start);
                    return;
                }
                Token::Ident(_) | Token::Punct('.') | Token::Punct('_') => {
                    self.advance();
                }
                _ => return,
            }
        }
    }

    fn push_import(&mut self, path: String, start: SourcePosition) {
        if path.is_empty() {
            return;
        }
        self.imports.push(Import {
            path,
            alias: None,
            range: range(start, self.previous_position()),
        });
    }

    /// `type T …`, and a parenthesised group of them.
    fn type_declaration(&mut self) -> Vec<Item> {
        self.advance();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.advance();
            let mut found = Vec::new();
            loop {
                match self.peek() {
                    Some(Token::Close(Delimiter::Paren)) | None => {
                        self.advance();
                        return found;
                    }
                    Some(token) if token.name().is_some() => {
                        if let Some(item) = self.one_type() {
                            found.push(item);
                        }
                    }
                    _ => {
                        self.advance();
                    }
                }
            }
        }
        self.one_type().into_iter().collect()
    }

    /// One `T struct { … }`, `T interface { … }`, or `T U`, with `type` already consumed.
    fn one_type(&mut self) -> Option<Item> {
        let start = self.position();
        let name = self.advance().and_then(Token::name)?.to_owned();
        // Type parameters, which are written in brackets.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
        }
        // `type T = U` is an alias; the `=` says nothing about the kind.
        if self.peek().is_some_and(|token| token.is_punct('=')) {
            self.advance();
        }
        let (kind, children, references) = match self.name_here() {
            Some("struct") => {
                self.advance();
                let (children, references) = self.struct_body();
                (ItemKind::Struct, children, references)
            }
            Some("interface") => {
                self.advance();
                let (children, references) = self.interface_body();
                (ItemKind::Trait, children, references)
            }
            // Anything else is a name for another type.
            _ => {
                let references = self.underlying_type();
                (ItemKind::TypeAlias, Vec::new(), references)
            }
        };
        Some(Item {
            kind,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children,
        })
    }

    /// A struct's fields, and the types it embeds as references.
    ///
    /// An embedded field — `struct { io.Reader }` — has a type and no name, so it is a reference rather
    /// than a field: there is no name to record it under.
    fn struct_body(&mut self) -> (Vec<Item>, Vec<Reference>) {
        let mut fields = Vec::new();
        let mut references = Vec::new();
        if !matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            return (fields, references);
        }
        self.advance();
        loop {
            match self.peek() {
                Some(Token::Close(Delimiter::Brace)) | None => {
                    self.advance();
                    return (fields, references);
                }
                Some(token) if token.name().is_some() => {
                    let start = self.position();
                    let name = token.name().unwrap_or_default().to_owned();
                    self.advance();
                    // An embedded type is a lone name, or a qualified one, with no field name before it.
                    if self.peek().is_some_and(|token| token.is_punct('.')) {
                        self.advance();
                        let embedded = self
                            .peek()
                            .and_then(Token::name)
                            .map(str::to_owned)
                            .unwrap_or(name.clone());
                        self.advance();
                        references.push(Reference {
                            name: embedded,
                            qualifier: Some(name),
                            is_method: false,
                            range: range(start, self.previous_position()),
                        });
                        self.skip_to_field_end();
                        continue;
                    }
                    // A name followed by the end of the line is an embedded type of this package. The
                    // end of the line is the inserted semicolon; guessing from the next token instead
                    // made `string` in `Name string` read as a second embedded type.
                    if matches!(self.peek(), Some(Token::Close(Delimiter::Brace)))
                        || self.peek().is_some_and(|token| token.is_punct(';'))
                    {
                        references.push(Reference {
                            name,
                            qualifier: None,
                            is_method: false,
                            range: range(start, self.previous_position()),
                        });
                        self.skip_to_field_end();
                        continue;
                    }
                    fields.push(Item::new(
                        ItemKind::Field,
                        name,
                        range(start, self.previous_position()),
                    ));
                    self.skip_to_field_end();
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// An interface's method signatures, and the interfaces it embeds as references.
    fn interface_body(&mut self) -> (Vec<Item>, Vec<Reference>) {
        let mut methods = Vec::new();
        let mut references = Vec::new();
        if !matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            return (methods, references);
        }
        self.advance();
        loop {
            match self.peek() {
                Some(Token::Close(Delimiter::Brace)) | None => {
                    self.advance();
                    return (methods, references);
                }
                Some(token) if token.name().is_some() => {
                    let start = self.position();
                    let name = token.name().unwrap_or_default().to_owned();
                    self.advance();
                    if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                        self.skip_balanced(Delimiter::Paren);
                        self.skip_result_type();
                        methods.push(Item::new(
                            ItemKind::Method,
                            name,
                            range(start, self.previous_position()),
                        ));
                        continue;
                    }
                    // An embedded interface, qualified or not.
                    let mut name = name;
                    let mut qualifier = None;
                    if self.peek().is_some_and(|token| token.is_punct('.')) {
                        self.advance();
                        if let Some(segment) = self.peek().and_then(Token::name) {
                            qualifier = Some(name);
                            name = segment.to_owned();
                            self.advance();
                        }
                    }
                    references.push(Reference {
                        name,
                        qualifier,
                        is_method: false,
                        range: range(start, self.previous_position()),
                    });
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// The type a `type T U` names, as a reference.
    fn underlying_type(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        let start = self.position();
        // Skip the pointer, slice, map, and channel decorations to reach a name.
        while self
            .peek()
            .is_some_and(|token| token.is_punct('*') || token.is_punct('<') || token.is_punct('-'))
        {
            self.advance();
        }
        if matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
        }
        if let Some(name) = self.name_here().map(str::to_owned) {
            self.advance();
            let mut name = name;
            let mut qualifier = None;
            if self.peek().is_some_and(|token| token.is_punct('.')) {
                self.advance();
                if let Some(segment) = self.peek().and_then(Token::name) {
                    qualifier = Some(name);
                    name = segment.to_owned();
                    self.advance();
                }
            }
            found.push(Reference {
                name,
                qualifier,
                is_method: false,
                range: range(start, self.previous_position()),
            });
        }
        found
    }

    /// `func f()`, `func (r T) m()`, and their bodies.
    fn function_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        // A receiver comes before the name and makes this a method.
        let mut target = None;
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            target = self.receiver();
        }
        let name = self.advance().and_then(Token::name)?.to_owned();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
        }
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
        }
        self.skip_result_type();
        let references = if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.body()
        } else {
            Vec::new()
        };
        Some(Item {
            kind: if target.is_some() {
                ItemKind::Method
            } else {
                ItemKind::Function
            },
            name,
            range: range(start, self.previous_position()),
            target,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    /// The type in a receiver, with its pointer dropped.
    ///
    /// `*Service` and `Service` are one type to a reader asking what methods it has, so the star is not
    /// part of the name.
    fn receiver(&mut self) -> Option<String> {
        let mut found = None;
        let mut depth = 0_u32;
        while let Some(token) = self.peek() {
            match token {
                Token::Open(Delimiter::Paren) => {
                    depth += 1;
                    self.advance();
                }
                Token::Close(Delimiter::Paren) => {
                    depth -= 1;
                    self.advance();
                    if depth == 0 {
                        return found;
                    }
                }
                // The last name inside the parentheses is the type; anything before it is the variable.
                Token::Ident(name) => {
                    found = Some(name.clone());
                    self.advance();
                }
                _ => {
                    self.advance();
                }
            }
        }
        found
    }

    /// A result type, which may be one name or a parenthesised list, before the body.
    fn skip_result_type(&mut self) {
        loop {
            match self.peek() {
                Some(Token::Open(Delimiter::Brace)) | None => return,
                Some(Token::Close(_)) => return,
                // The line ending, which is where an interface's signature stops. Without this the next
                // method's name was consumed as part of this one's result type.
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return;
                }
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// `const x = 1`, `var x T`, and a parenthesised group of either.
    fn value_declaration(&mut self) -> Vec<Item> {
        self.advance();
        let mut found = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.advance();
            loop {
                match self.peek() {
                    Some(Token::Close(Delimiter::Paren)) | None => {
                        self.advance();
                        return found;
                    }
                    Some(token) if token.name().is_some() => {
                        let start = self.position();
                        let name = token.name().unwrap_or_default().to_owned();
                        self.advance();
                        found.push(Item::new(
                            ItemKind::Constant,
                            name,
                            range(start, self.previous_position()),
                        ));
                        self.skip_to_value_end();
                    }
                    _ => {
                        self.advance();
                    }
                }
            }
        }
        // `var a, b = 1, 2` declares both.
        loop {
            let Some(name) = self.name_here().map(str::to_owned) else {
                return found;
            };
            let start = self.position();
            self.advance();
            found.push(Item::new(
                ItemKind::Constant,
                name,
                range(start, self.previous_position()),
            ));
            if self.peek().is_some_and(|token| token.is_punct(',')) {
                self.advance();
                continue;
            }
            self.skip_to_value_end();
            return found;
        }
    }

    /// A body, returning the calls made in it.
    fn body(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        let mut depth = 0_u32;
        loop {
            let start = self.position();
            match self.peek() {
                Some(Token::Open(Delimiter::Brace)) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::Close(Delimiter::Brace)) => {
                    self.advance();
                    depth -= 1;
                    if depth == 0 {
                        return found;
                    }
                }
                Some(token) if token.name().is_some() => {
                    let name = token.name().unwrap_or_default().to_owned();
                    self.advance();
                    let mut name = Some(name);
                    let mut qualifier = None;
                    let mut is_method = false;
                    while self.peek().is_some_and(|token| token.is_punct('.')) {
                        self.advance();
                        match self.peek().and_then(Token::name) {
                            Some(segment) => {
                                qualifier = name;
                                name = Some(segment.to_owned());
                                is_method = true;
                                self.advance();
                            }
                            None => break,
                        }
                    }
                    if matches!(self.peek(), Some(Token::Open(Delimiter::Paren)))
                        && let Some(name) = name
                    {
                        found.push(Reference {
                            name,
                            qualifier,
                            is_method,
                            range: range(start, self.previous_position()),
                        });
                    }
                }
                None => return found,
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes the rest of one struct field, up to the semicolon the lexer inserted at the line ending.
    ///
    /// The type and any struct tag are consumed on the way.
    fn skip_to_field_end(&mut self) {
        loop {
            match self.peek() {
                Some(Token::Close(Delimiter::Brace)) | None => return,
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return;
                }
                Some(Token::Open(Delimiter::Brace)) => self.skip_balanced(Delimiter::Brace),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes the rest of a `const` or `var` line.
    fn skip_to_value_end(&mut self) {
        loop {
            match self.peek() {
                Some(Token::Close(Delimiter::Paren) | Token::Close(Delimiter::Brace)) | None => {
                    return;
                }
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return;
                }
                Some(Token::Open(Delimiter::Brace)) => self.skip_balanced(Delimiter::Brace),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn skip_balanced(&mut self, delimiter: Delimiter) {
        let mut depth = 0_u32;
        while let Some(token) = self.peek() {
            match token {
                Token::Open(found) if *found == delimiter => depth += 1,
                Token::Close(found) if *found == delimiter => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return;
                    }
                }
                _ => {}
            }
            self.advance();
        }
    }
}

fn range(start: SourcePosition, end: SourcePosition) -> SourceRange {
    super::range(
        (start.line, start.column, start.offset),
        (end.line, end.column, end.offset),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(ItemKind, String)> {
        analyze(source)
            .walk()
            .map(|item| (item.kind, item.name.clone()))
            .collect()
    }

    fn paths(source: &str) -> Vec<String> {
        analyze(source)
            .imports
            .into_iter()
            .map(|held| held.path)
            .collect()
    }

    #[test]
    fn a_struct_its_fields_and_its_methods_are_read() {
        let found = analyze(
            "package main\n\n\
             type Service struct {\n\
             \tName string `json:\"name\"`\n\
             \tCount int\n\
             }\n\n\
             func (s *Service) Do() error {\n\
             \treturn run(s.Name)\n\
             }\n\n\
             func main() {\n\
             \tNewService().Do()\n\
             }\n",
        );
        assert_eq!(
            found
                .walk()
                .map(|item| (item.kind, item.name.clone(), item.target.clone()))
                .collect::<Vec<_>>(),
            [
                (ItemKind::Struct, "Service".to_owned(), None),
                (ItemKind::Field, "Name".to_owned(), None),
                (ItemKind::Field, "Count".to_owned(), None),
                (
                    ItemKind::Method,
                    "Do".to_owned(),
                    Some("Service".to_owned())
                ),
                (ItemKind::Function, "main".to_owned(), None),
            ]
        );
    }

    #[test]
    fn a_receiver_names_the_type_and_drops_the_pointer() {
        // `*Service` and `Service` are one type to a reader asking what methods it has.
        let found = analyze("package p\nfunc (s *Service) A() {}\nfunc (s Service) B() {}\n");
        assert_eq!(
            found
                .items
                .iter()
                .map(|item| (item.name.clone(), item.target.clone()))
                .collect::<Vec<_>>(),
            [
                ("A".to_owned(), Some("Service".to_owned())),
                ("B".to_owned(), Some("Service".to_owned())),
            ]
        );
    }

    #[test]
    fn a_method_is_not_held_by_an_invented_grouping_declaration() {
        // Rust has an `impl` block because somebody wrote one. Go has nothing to hold its methods, and
        // manufacturing one would put a declaration in the graph that appears nowhere in the source.
        let found = analyze("package p\ntype T struct{}\nfunc (t T) M() {}\n");
        assert!(
            found
                .walk()
                .all(|item| item.kind != ItemKind::Implementation),
            "no grouping declaration is invented"
        );
        assert_eq!(
            found.items.len(),
            2,
            "the type and the method, side by side"
        );
    }

    #[test]
    fn every_import_form_is_recorded() {
        assert_eq!(
            paths(
                "package main\n\n\
                 import \"fmt\"\n\
                 import alias \"net/http\"\n\
                 import (\n\
                 \t\"os\"\n\
                 \t_ \"embed\"\n\
                 \tm \"example.com/pkg/module\"\n\
                 )\n"
            ),
            ["fmt", "net/http", "os", "embed", "example.com/pkg/module"]
        );
    }

    #[test]
    fn an_interface_is_a_trait_and_its_signatures_are_methods() {
        let found = analyze(
            "package p\n\
             type Reader interface {\n\
             \tRead(p []byte) (int, error)\n\
             \tClose() error\n\
             \tio.Writer\n\
             }\n",
        );
        assert_eq!(found.items[0].kind, ItemKind::Trait);
        assert_eq!(
            found.items[0]
                .children
                .iter()
                .map(|item| (item.kind, item.name.clone()))
                .collect::<Vec<_>>(),
            [
                (ItemKind::Method, "Read".to_owned()),
                (ItemKind::Method, "Close".to_owned()),
            ]
        );
        // The embedded interface is a reference, because it has no signature to be a member.
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| (held.qualifier.clone(), held.name.clone()))
                .collect::<Vec<_>>(),
            [(Some("io".to_owned()), "Writer".to_owned())]
        );
    }

    #[test]
    fn an_embedded_struct_field_is_a_reference_because_it_has_no_name() {
        let found = analyze("package p\ntype A struct {\n\tio.Reader\n\tName string\n}\n");
        assert_eq!(
            found.items[0]
                .children
                .iter()
                .map(|item| item.name.clone())
                .collect::<Vec<_>>(),
            ["Name"]
        );
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["Reader"]
        );
    }

    #[test]
    fn a_type_alias_and_a_named_type_are_both_aliases_here() {
        assert_eq!(
            kinds("package p\ntype Id = string\ntype Count int\n"),
            [
                (ItemKind::TypeAlias, "Id".to_owned()),
                (ItemKind::TypeAlias, "Count".to_owned()),
            ]
        );
    }

    #[test]
    fn a_grouped_type_declaration_yields_each_type() {
        assert_eq!(
            kinds("package p\ntype (\n\tA struct{}\n\tB interface{}\n)\n"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Trait, "B".to_owned()),
            ]
        );
    }

    #[test]
    fn const_and_var_are_read_grouped_or_not() {
        assert_eq!(
            kinds(
                "package p\n\
                 const Limit = 10\n\
                 var logger = newLogger()\n\
                 const (\n\
                 \tA = 1\n\
                 \tB = 2\n\
                 )\n"
            ),
            [
                (ItemKind::Constant, "Limit".to_owned()),
                (ItemKind::Constant, "logger".to_owned()),
                (ItemKind::Constant, "A".to_owned()),
                (ItemKind::Constant, "B".to_owned()),
            ]
        );
    }

    #[test]
    fn a_call_in_a_body_is_a_reference() {
        let found = analyze("package p\nfunc f() {\n\thelper()\n\tobj.Thing()\n}\n");
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["helper", "Thing"]
        );
        assert!(found.items[0].references[1].is_method);
    }

    #[test]
    fn a_raw_string_in_a_body_does_not_hide_the_declaration_after_it() {
        // The lexer's ambiguity, reaching the analyzer.
        assert_eq!(
            kinds("package p\nfunc f() {\n\tq := `{\"a\": 1}`\n\t_ = q\n}\nfunc after() {}\n"),
            [
                (ItemKind::Function, "f".to_owned()),
                (ItemKind::Function, "after".to_owned()),
            ]
        );
    }

    #[test]
    fn a_generic_declaration_does_not_hide_its_name() {
        assert_eq!(
            kinds("package p\nfunc Map[T any, U any](in []T) []U { return nil }\n"),
            [(ItemKind::Function, "Map".to_owned())]
        );
        assert_eq!(
            kinds("package p\ntype List[T any] struct { head *T }"),
            [
                (ItemKind::Struct, "List".to_owned()),
                (ItemKind::Field, "head".to_owned()),
            ]
        );
    }

    #[test]
    fn malformed_source_yields_what_could_be_read_and_stops() {
        assert_eq!(
            kinds("package p\nfunc f() {"),
            [(ItemKind::Function, "f".to_owned())]
        );
        assert_eq!(
            kinds("package p\ntype A struct {"),
            [(ItemKind::Struct, "A".to_owned())]
        );
        assert!(kinds("package p\nfunc").is_empty());
        assert!(kinds("").is_empty());
        // A stray closing brace must not end the parse of what follows.
        assert_eq!(
            kinds("package p\n}\nfunc after() {}\n"),
            [(ItemKind::Function, "after".to_owned())]
        );
    }

    #[test]
    fn a_declaration_carries_the_range_it_was_written_at() {
        let found = analyze("package p\n\ntype A struct {\n\tName string\n}\n");
        assert_eq!(found.items[0].range.start().line, 3);
        assert_eq!(found.items[0].children[0].range.start().line, 4);
    }

    #[test]
    fn the_capability_declares_only_what_this_analyzer_produces() {
        let declared = capability();
        assert_eq!(declared.language.as_str(), "go");
        for fact in [
            FactKind::Method,
            FactKind::Field,
            FactKind::Function,
            FactKind::ImportExport,
            FactKind::Call,
        ] {
            assert!(declared.extracts(fact), "{fact} is declared and produced");
        }
        // Go's interfaces are satisfied implicitly, so nothing here can state an implementation. Declaring
        // `InterfaceImplementation` would advertise a fact only a type checker can produce.
        assert!(!declared.extracts(FactKind::InterfaceImplementation));
        assert!(!declared.extracts(FactKind::EntryPoint));
    }
}
