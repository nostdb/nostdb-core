//! Reads Python structure, without resolving anything.
//!
//! # Declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `import a.b`, `import a as b` | an import, whose path is `a.b` |
//! | `from a.b import c`, `from . import c`, `from ..p import c` | an import |
//! | `class C:` | [`ItemKind::Struct`] |
//! | `def f():` at module level | [`ItemKind::Function`] |
//! | `def m(self):` in a class | [`ItemKind::Method`] |
//! | `async def` | the same as `def` |
//! | `NAME = …` at module level | [`ItemKind::Constant`] |
//! | `name = …` or `name: T` in a class body | [`ItemKind::Field`] |
//! | a base class | a reference |
//! | a call in a body | a reference |
//! | decorators, with their arguments as written | on the declaration they precede |
//!
//! # Why a relative import keeps its dots
//!
//! `from . import x` and `from ..pkg import y` are relative to the importing module's own package, and the
//! leading dots are how deep. They are kept, so the path recorded is `.` and `..pkg` rather than the
//! empty string and `pkg` — which would name the wrong module and, worse, would name a plausible one.
//!
//! Resolution against the file tree happens in [`crate::build`], which is where the tree is known. What
//! this analyzer must not do is throw away the part that says where to start.
//!
//! # What an instance attribute is not
//!
//! `self.total = 0` inside `__init__` declares an attribute every reader would name. It is **not**
//! recorded, because at [`PrecisionClass::DeterministicSyntactic`] there is no way to tell it from an
//! assignment to an attribute of something else that happens to be called `self`, and no way to tell one
//! declaration from a reassignment of the same name in another method. A class body's assignments are
//! recorded because they are unambiguous; `self.x` needs a resolver this does not have.

use super::python_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{Annotation, FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads.
pub const LANGUAGE: &str = "python";

/// This analyzer's version, which is part of its identity for ownership purposes.
pub const VERSION: &str = "1";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// What this analyzer declares it extracts.
#[must_use]
pub fn capability() -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(LANGUAGE).unwrap_or_else(|_| NonEmptyText::literal("python")),
        precision: PRECISION,
        facts: vec![
            FactKind::File,
            FactKind::Module,
            FactKind::Class,
            FactKind::Function,
            FactKind::Method,
            FactKind::Field,
            FactKind::Declaration,
            FactKind::Definition,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::Inheritance,
            FactKind::SourceRange,
            FactKind::ContentHash,
        ],
        version: NonEmptyText::new(VERSION).unwrap_or_else(|_| NonEmptyText::literal("1")),
    }
}

/// Reads one Python file.
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
    let items = reader.declarations(None);
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

    fn peek_at(&self, ahead: usize) -> Option<&Token> {
        self.tokens.get(self.at + ahead).map(|held| &held.token)
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

    /// Reads declarations until the input ends or a `Dedent` closes the enclosing block.
    ///
    /// `container` is the kind of declaration this is inside: `None` is module scope, and a class is what
    /// makes a `def` a method and an assignment a field.
    fn declarations(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            let annotations = self.decorators();
            match self.peek() {
                None => return items,
                Some(Token::Dedent) => {
                    self.advance();
                    if container.is_some() {
                        return items;
                    }
                    continue;
                }
                // An empty statement, or the newline that ended a header line.
                Some(Token::Newline | Token::Indent) => {
                    self.advance();
                    continue;
                }
                _ => {}
            }
            match self.name_here() {
                Some("import") => self.import_statement(),
                Some("from") => self.import_from_statement(),
                Some("class") => {
                    if let Some(mut item) = self.class_declaration() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("def") => {
                    if let Some(mut item) = self.function_declaration(container) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("async") if self.peek_at(1).and_then(Token::name) == Some("def") => {
                    self.advance();
                    if let Some(mut item) = self.function_declaration(container) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                // A binding, when the line is `NAME =` or `NAME:` and nothing else.
                Some(_) if self.at_binding() => {
                    if let Some(item) = self.binding(container) {
                        items.push(item);
                    }
                }
                // Not a declaration. Consumed so a call at module scope is still read.
                _ => {
                    self.logical_line();
                }
            }
        }
    }

    /// `@name`, `@name(...)`, `@a.b.c`, repeated.
    ///
    /// The newline between the last decorator and the declaration it applies to is consumed here. Leaving
    /// it made the caller treat it as an empty statement, and the annotations collected in that iteration
    /// were dropped before the declaration was read — every decorator in the file was lost, silently, with
    /// the declarations themselves looking correct.
    fn decorators(&mut self) -> Vec<Annotation> {
        let mut found = Vec::new();
        while self.peek().is_some_and(|token| token.is_punct('@')) {
            let start = self.position();
            self.advance();
            let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) else {
                break;
            };
            self.advance();
            // A qualified decorator, `@app.route`, keeps its final segment the way an annotation does
            // everywhere else in this module.
            let mut name = name;
            while self.peek().is_some_and(|token| token.is_punct('.')) {
                self.advance();
                match self.peek().and_then(Token::name) {
                    Some(segment) => {
                        name = segment.to_owned();
                        self.advance();
                    }
                    None => break,
                }
            }
            let arguments = if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                Some(self.balanced_text(Delimiter::Paren))
            } else {
                None
            };
            if NonEmptyText::new(name.as_str()).is_ok() {
                found.push(Annotation {
                    name,
                    arguments,
                    range: range(start, self.previous_position()),
                });
            }
            // Past the newline that ends this decorator's line, whether the next line holds another
            // decorator or the declaration itself.
            while matches!(self.peek(), Some(Token::Newline)) {
                self.advance();
            }
        }
        found
    }

    /// `import a.b`, `import a.b as c`, `import a, b`.
    fn import_statement(&mut self) {
        let start = self.position();
        self.advance();
        loop {
            let path = self.dotted_name();
            if !path.is_empty() {
                self.push_import(path, start);
            }
            // `as name` renames the binding, not the module.
            if self.name_here() == Some("as") {
                self.advance();
                self.advance();
            }
            if self.peek().is_some_and(|token| token.is_punct(',')) {
                self.advance();
                continue;
            }
            self.logical_line();
            return;
        }
    }

    /// `from a.b import c`, `from . import c`, `from ..p import (c, d)`.
    fn import_from_statement(&mut self) {
        let start = self.position();
        self.advance();
        // The leading dots are how deep a relative import reaches, and dropping them would name a
        // different module. `.` alone is the current package.
        let mut path = String::new();
        while self.peek().is_some_and(|token| token.is_punct('.')) {
            path.push('.');
            self.advance();
        }
        path.push_str(&self.dotted_name());
        if !path.is_empty() {
            self.push_import(path, start);
        }
        self.logical_line();
    }

    fn push_import(&mut self, path: String, start: SourcePosition) {
        self.imports.push(Import {
            path,
            alias: None,
            range: range(start, self.previous_position()),
        });
    }

    /// A dotted name, and a trailing `*`.
    fn dotted_name(&mut self) -> String {
        let mut segments = Vec::new();
        loop {
            match self.peek() {
                Some(token) if token.name().is_some() => {
                    if let Some(name) = token.name() {
                        // `import` inside a `from` clause ends the module path.
                        if name == "import" || name == "as" {
                            break;
                        }
                        segments.push(name.to_owned());
                    }
                    self.advance();
                }
                Some(token) if token.is_punct('*') => {
                    segments.push("*".to_owned());
                    self.advance();
                    break;
                }
                _ => break,
            }
            if self.peek().is_some_and(|token| token.is_punct('.')) {
                self.advance();
                continue;
            }
            break;
        }
        segments.join(".")
    }

    fn class_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let mut references = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            references = self.base_classes();
        }
        let children = self.suite(Some(ItemKind::Struct));
        Some(Item {
            kind: ItemKind::Struct,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children,
        })
    }

    /// The names in a class's parenthesised base list, as references.
    ///
    /// A keyword argument — `class C(Base, metaclass=Meta)` — contributes its value rather than its
    /// keyword, because the value is the name being referred to.
    fn base_classes(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        let mut depth = 0_u32;
        let mut pending: Option<(String, Option<String>, SourcePosition)> = None;
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
                        if let Some((name, qualifier, start)) = pending.take() {
                            found.push(Reference {
                                name,
                                qualifier,
                                is_method: false,
                                range: range(start, self.previous_position()),
                            });
                        }
                        return found;
                    }
                }
                Token::Punct(',') => {
                    self.advance();
                    if let Some((name, qualifier, start)) = pending.take() {
                        found.push(Reference {
                            name,
                            qualifier,
                            is_method: false,
                            range: range(start, self.previous_position()),
                        });
                    }
                }
                // `metaclass=Meta`: the keyword is discarded and the value kept.
                Token::Punct('=') => {
                    self.advance();
                    pending = None;
                }
                Token::Punct('.') => {
                    self.advance();
                    if let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) {
                        if let Some(held) = pending.as_mut() {
                            held.1 = Some(held.0.clone());
                            held.0 = name;
                        }
                        self.advance();
                    }
                }
                Token::Ident(name) => {
                    let name = name.clone();
                    let start = self.position();
                    self.advance();
                    pending = Some((name, None, start));
                }
                _ => {
                    self.advance();
                }
            }
        }
        found
    }

    fn function_declaration(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
        }
        // A `-> T` return annotation.
        while let Some(token) = self.peek() {
            if token.is_punct(':') || matches!(token, Token::Newline | Token::Indent) {
                break;
            }
            self.advance();
        }
        let kind = match container {
            // A `def` inside a class is a method; one inside a function is still a function.
            Some(ItemKind::Struct) => ItemKind::Method,
            _ => ItemKind::Function,
        };
        // A nested declaration is a child, and a nested `def` inside a method is a function of its own.
        let children = self.suite(Some(kind));
        let references = children_calls(&children);
        let mut item = Item {
            kind,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references: Vec::new(),
            annotations: Vec::new(),
            children: Vec::new(),
        };
        item.references = references;
        Some(item)
    }

    /// Reports whether the line starting here binds a name.
    ///
    /// `NAME =` or `NAME:` and nothing between. A subscripted or attribute target — `a[0] = 1`,
    /// `self.x = 1` — is not a declaration this analyzer records, and neither is a comparison.
    fn at_binding(&self) -> bool {
        if self.name_here().is_none() {
            return false;
        }
        match self.peek_at(1) {
            Some(token) if token.is_punct('=') => {
                // `==` is a comparison.
                !self.peek_at(2).is_some_and(|token| token.is_punct('='))
            }
            Some(token) => token.is_punct(':'),
            None => false,
        }
    }

    /// `NAME = …` or `NAME: T = …`, which is a constant at module scope and a field in a class body.
    fn binding(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let references = self.logical_line();
        let kind = match container {
            Some(ItemKind::Struct) => ItemKind::Field,
            _ => ItemKind::Constant,
        };
        let mut item = Item::new(kind, name, range(start, self.previous_position()));
        item.references = references;
        Some(item)
    }

    /// The body a `:` introduces.
    ///
    /// An indented block is read as declarations. A one-line body — `def f(): return 1` — has no
    /// `Indent`, so nothing is nested and the line is consumed.
    fn suite(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
        }
        if matches!(self.peek(), Some(Token::Newline)) {
            self.advance();
        } else {
            // A one-line body.
            self.logical_line();
            return Vec::new();
        }
        if matches!(self.peek(), Some(Token::Indent)) {
            self.advance();
            return self.declarations(container);
        }
        Vec::new()
    }

    /// Consumes to the end of a logical line, returning the calls made in it.
    fn logical_line(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        loop {
            match self.peek() {
                None | Some(Token::Newline) => {
                    self.advance();
                    return found;
                }
                // A nested block on a line this is skipping: an `if` inside a body, for instance. Its
                // declarations are not read, but its calls are.
                Some(Token::Indent) => {
                    self.advance();
                    found.extend(self.nested_block());
                }
                Some(Token::Dedent) => return found,
                Some(token) if token.name().is_some() => {
                    let start = self.position();
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
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes an indented block that holds no declaration this analyzer records, keeping its calls.
    fn nested_block(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.peek() {
                None => return found,
                Some(Token::Indent) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::Dedent) => {
                    depth -= 1;
                    self.advance();
                }
                _ => found.extend(self.logical_line()),
            }
        }
        found
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

    /// Consumes a balanced pair and returns its contents as written.
    fn balanced_text(&mut self, delimiter: Delimiter) -> String {
        let mut text = String::new();
        let mut depth = 0_u32;
        while let Some(token) = self.peek() {
            match token {
                Token::Open(found) if *found == delimiter => {
                    depth += 1;
                    if depth > 1 {
                        text.push(open_character(delimiter));
                    }
                }
                Token::Close(found) if *found == delimiter => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return text;
                    }
                    text.push(close_character(delimiter));
                }
                Token::Ident(name) => text.push_str(name),
                Token::Text(content) => {
                    text.push('"');
                    text.push_str(content);
                    text.push('"');
                }
                Token::Literal => text.push_str("<literal>"),
                Token::Open(found) => text.push(open_character(*found)),
                Token::Close(found) => text.push(close_character(*found)),
                Token::Punct(character) => text.push(*character),
                Token::Newline | Token::Indent | Token::Dedent => text.push(' '),
            }
            self.advance();
        }
        text
    }
}

/// The calls a declaration's body made, taken from the statements read inside it.
///
/// A `def`'s body yields declarations for a nested `def` or `class` and references for everything else.
/// The references belong to the enclosing declaration, because that is where the call is written.
fn children_calls(children: &[Item]) -> Vec<Reference> {
    children
        .iter()
        .filter(|item| item.kind == ItemKind::Constant || item.kind == ItemKind::Field)
        .flat_map(|item| item.references.iter().cloned())
        .collect()
}

fn open_character(delimiter: Delimiter) -> char {
    match delimiter {
        Delimiter::Brace => '{',
        Delimiter::Paren => '(',
        Delimiter::Bracket => '[',
    }
}

fn close_character(delimiter: Delimiter) -> char {
    match delimiter {
        Delimiter::Brace => '}',
        Delimiter::Paren => ')',
        Delimiter::Bracket => ']',
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
    fn a_module_its_classes_and_its_functions_are_read() {
        assert_eq!(
            kinds(
                "import os\n\
                 \n\
                 TIMEOUT = 30\n\
                 \n\
                 class Service:\n\
                 \x20   name = \"svc\"\n\
                 \n\
                 \x20   def __init__(self, url):\n\
                 \x20       self.url = url\n\
                 \n\
                 \x20   def fetch(self):\n\
                 \x20       return get(self.url)\n\
                 \n\
                 def main():\n\
                 \x20   Service(\"x\").fetch()\n"
            ),
            [
                (ItemKind::Constant, "TIMEOUT".to_owned()),
                (ItemKind::Struct, "Service".to_owned()),
                (ItemKind::Field, "name".to_owned()),
                (ItemKind::Method, "__init__".to_owned()),
                (ItemKind::Method, "fetch".to_owned()),
                (ItemKind::Function, "main".to_owned()),
            ]
        );
    }

    #[test]
    fn every_import_form_is_recorded_with_its_path() {
        assert_eq!(
            paths(
                "import os\n\
                 import os.path\n\
                 import numpy as np\n\
                 import json, csv\n\
                 from a.b import c\n\
                 from a.b import (c, d)\n\
                 from x import *\n"
            ),
            ["os", "os.path", "numpy", "json", "csv", "a.b", "a.b", "x"]
        );
    }

    #[test]
    fn a_relative_import_keeps_its_dots() {
        // Dropping them names a different module, and a plausible one. `.` is the current package.
        assert_eq!(
            paths(
                "from . import sibling\nfrom .models import User\nfrom ..pkg.deep import Thing\n"
            ),
            [".", ".models", "..pkg.deep"]
        );
    }

    #[test]
    fn an_async_def_is_read_like_a_def() {
        assert_eq!(
            kinds("class A:\n    async def run(self):\n        await go()\n"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "run".to_owned()),
            ]
        );
        assert_eq!(
            kinds("async def main():\n    pass\n"),
            [(ItemKind::Function, "main".to_owned())]
        );
    }

    #[test]
    fn a_base_class_is_a_reference_and_a_metaclass_keyword_is_not() {
        let found = analyze("class C(Base, other.Mixin, metaclass=Meta):\n    pass\n");
        assert!(found.items[0].implements.is_none());
        let referenced: Vec<String> = found.items[0]
            .references
            .iter()
            .map(|held| held.name.clone())
            .collect();
        assert_eq!(
            referenced,
            ["Base", "Mixin", "Meta"],
            "the keyword is discarded and its value kept"
        );
        assert_eq!(
            found.items[0].references[1].qualifier.as_deref(),
            Some("other")
        );
    }

    #[test]
    fn a_decorator_keeps_its_arguments_as_written() {
        let found = analyze(
            "@app.route(\"/api/x\", methods=[\"GET\"])\n\
             def handler():\n\
             \x20   return \"\"\n",
        );
        let handler = &found.items[0];
        assert_eq!(handler.name, "handler");
        assert_eq!(handler.annotations[0].name, "route");
        assert!(
            handler.annotations[0]
                .arguments
                .as_deref()
                .is_some_and(|held| held.contains("/api/x")),
            "{:?}",
            handler.annotations[0].arguments
        );
    }

    #[test]
    fn several_decorators_all_attach_to_the_declaration_below_them() {
        let found = analyze("@one\n@two()\nclass C:\n    pass\n");
        assert_eq!(
            found.items[0]
                .annotations
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn an_instance_attribute_is_not_a_declaration() {
        // `self.total = 0` names an attribute every reader would, and at syntactic precision there is no
        // telling it from an assignment to something else called `self`, or one declaration from a
        // reassignment in another method.
        let found = analyze("class A:\n    def __init__(self):\n        self.total = 0\n");
        assert_eq!(
            found
                .walk()
                .map(|item| item.name.clone())
                .collect::<Vec<_>>(),
            ["A", "__init__"]
        );
    }

    #[test]
    fn a_class_body_binding_is_a_field_and_a_module_binding_is_a_constant() {
        assert_eq!(
            kinds("LIMIT: int = 5\nclass A:\n    count: int = 0\n"),
            [
                (ItemKind::Constant, "LIMIT".to_owned()),
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Field, "count".to_owned()),
            ]
        );
    }

    #[test]
    fn a_subscripted_or_compared_name_is_not_a_binding() {
        assert!(kinds("a[0] = 1\n").is_empty());
        assert!(kinds("if x == 1:\n    pass\n").is_empty());
    }

    #[test]
    fn a_docstring_does_not_hide_the_declarations_after_it() {
        assert_eq!(
            kinds(
                "\"\"\"Module docstring.\n\n\
                 Holds a # and 'quotes'.\n\
                 \"\"\"\n\
                 \n\
                 def after():\n\
                 \x20   \"\"\"Another.\"\"\"\n\
                 \x20   pass\n"
            ),
            [(ItemKind::Function, "after".to_owned())]
        );
    }

    #[test]
    fn a_multiline_call_does_not_hide_the_declaration_after_it() {
        // The lexer's implicit line joining, reaching the analyzer.
        assert_eq!(
            kinds("VALUE = call(\n    1,\n    2,\n)\n\ndef after():\n    pass\n"),
            [
                (ItemKind::Constant, "VALUE".to_owned()),
                (ItemKind::Function, "after".to_owned()),
            ]
        );
    }

    #[test]
    fn a_nested_declaration_is_a_child() {
        let found =
            analyze("class Outer:\n    class Inner:\n        def m(self):\n            pass\n");
        assert_eq!(found.items[0].name, "Outer");
        assert_eq!(found.items[0].children[0].name, "Inner");
        assert_eq!(found.items[0].children[0].children[0].name, "m");
        assert_eq!(
            found.items[0].children[0].children[0].kind,
            ItemKind::Method
        );
    }

    #[test]
    fn a_one_line_body_declares_nothing_inside_itself() {
        assert_eq!(
            kinds("def f(): return 1\ndef g():\n    pass\n"),
            [
                (ItemKind::Function, "f".to_owned()),
                (ItemKind::Function, "g".to_owned()),
            ]
        );
    }

    #[test]
    fn a_call_in_a_body_is_a_reference() {
        let found = analyze("def f():\n    x = helper()\n    y = obj.thing()\n");
        let referenced: Vec<String> = found.items[0]
            .references
            .iter()
            .map(|held| held.name.clone())
            .collect();
        assert_eq!(referenced, ["helper", "thing"]);
    }

    #[test]
    fn a_blank_line_or_a_comment_inside_a_class_does_not_end_it() {
        assert_eq!(
            kinds(
                "class A:\n\
                 \x20   def m(self):\n\
                 \x20       pass\n\
                 \n\
                 # a comment at column zero\n\
                 \x20   def n(self):\n\
                 \x20       pass\n"
            ),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "m".to_owned()),
                (ItemKind::Method, "n".to_owned()),
            ]
        );
    }

    #[test]
    fn malformed_source_yields_what_could_be_read_and_stops() {
        assert_eq!(
            kinds("class A:\n    def m(self):"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "m".to_owned()),
            ]
        );
        assert_eq!(kinds("class A:"), [(ItemKind::Struct, "A".to_owned())]);
        assert!(kinds("class").is_empty());
        assert!(kinds("").is_empty());
    }

    #[test]
    fn a_declaration_carries_the_range_it_was_written_at() {
        let found = analyze("class A:\n    def m(self):\n        pass\n");
        assert_eq!(found.items[0].range.start().line, 1);
        assert_eq!(found.items[0].children[0].range.start().line, 2);
    }

    #[test]
    fn the_capability_declares_only_what_this_analyzer_produces() {
        let declared = capability();
        assert_eq!(declared.language.as_str(), "python");
        for fact in [
            FactKind::Method,
            FactKind::Field,
            FactKind::Function,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::Inheritance,
        ] {
            assert!(declared.extracts(fact), "{fact} is declared and produced");
        }
        assert!(!declared.extracts(FactKind::EntryPoint));
        assert!(!declared.extracts(FactKind::Package));
    }
}
