//! Reads TypeScript and JavaScript structure, without resolving anything.
//!
//! One analyzer for both, for the reason [`super::typescript_lexer`] gives: every JavaScript file is a
//! TypeScript file that declares no types. `interface`, `type`, and `enum` simply do not appear in a
//! `.js` file, and reading for them costs nothing when they are absent.
//!
//! # Declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `import x from "p"`, `import "p"`, `export … from "p"` | an import, whose path is `p` |
//! | `require("p")`, `import("p")` at any depth | an import |
//! | `class` | [`ItemKind::Struct`] |
//! | `interface` | [`ItemKind::Trait`] |
//! | `type X = …` | [`ItemKind::TypeAlias`] |
//! | `enum X` | [`ItemKind::Enum`] |
//! | `function` at file scope | [`ItemKind::Function`] |
//! | a method in a class | [`ItemKind::Method`] |
//! | a property in a class | [`ItemKind::Field`] |
//! | `const`/`let`/`var` at file scope | [`ItemKind::Constant`] |
//! | `extends`, `implements` | references |
//! | a call in a body | a reference |
//! | decorators, with their arguments as written | on the declaration they precede |
//!
//! # Why an import's path is the whole point here
//!
//! Java and Kotlin import a *name* and the file it lives in is inferred from it. JavaScript imports a
//! **path**, written as a string: `import logo from "./assets/logo.png"`. So this analyzer is the one
//! whose imports name files directly, and the reason `IMPORTS` resolution in [`crate::build`] matches by
//! path correspondence rather than by name — a rule written for Kotlin that this language needs.
//!
//! A path is recorded exactly as written, extension included. Resolving `"./x"` to `x.ts` against
//! `x/index.ts` is a module-resolution algorithm with a configuration file behind it, and guessing at one
//! would put a file in the graph that nobody imported.
//!
//! # What a `const` at file scope is, and is not
//!
//! `const f = () => {}` declares a function in every sense a reader means, and this records it as a
//! [`ItemKind::Constant`] rather than a [`ItemKind::Function`]. The distinction the graph keeps is the one
//! the source makes: `function f() {}` and `const f = () => {}` are different declarations, and a build
//! that reported them identically would make a rename of one look like a move of the other. What both
//! produce is a named record at file scope, which is what a reference to `f` resolves against.

use super::typescript_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{Annotation, FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads when the source is TypeScript.
pub const LANGUAGE: &str = "typescript";

/// The language this analyzer reads when the source is JavaScript.
pub const JAVASCRIPT: &str = "javascript";

/// This analyzer's version, which is part of its identity for ownership purposes.
pub const VERSION: &str = "1";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// What this analyzer declares it extracts, for one of the two languages it reads.
///
/// Two capabilities rather than one, because a capability is keyed by language and a caller asking about
/// `javascript` must get an answer. They declare the same facts and carry the same version, which is the
/// truth: it is one analyzer.
#[must_use]
pub fn capability_for(language: &str) -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(language)
            .unwrap_or_else(|_| NonEmptyText::literal("typescript")),
        precision: PRECISION,
        facts: vec![
            FactKind::File,
            FactKind::Module,
            FactKind::Type,
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

/// Reads one TypeScript or JavaScript file.
///
/// `language` is recorded as given, so a `.js` file reports `javascript` and a `.ts` file
/// `typescript`, even though one analyzer read both.
///
/// Never fails. Malformed input yields whatever declarations could be read.
#[must_use]
pub fn analyze_as(language: &str, source: &str) -> FileAnalysis {
    let tokens = tokenize(source);
    let mut reader = Reader {
        tokens: &tokens,
        at: 0,
        imports: Vec::new(),
    };
    let items = reader.declarations(None);
    FileAnalysis {
        language: language.to_owned(),
        digest: crate::sync::digest_bytes(source.as_bytes()),
        items,
        imports: reader.imports,
    }
}

/// Words that precede a declaration without being one.
const MODIFIERS: [&str; 10] = [
    "abstract",
    "async",
    "declare",
    "export",
    "override",
    "private",
    "protected",
    "public",
    "readonly",
    "static",
];

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

    /// Reads declarations until the input ends or a closing brace closes the enclosing body.
    fn declarations(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            let annotations = self.decorators();
            self.modifiers();
            let Some(token) = self.peek() else {
                return items;
            };
            if matches!(token, Token::Close(Delimiter::Brace)) {
                self.advance();
                if container.is_some() {
                    return items;
                }
                continue;
            }
            match self.name_here() {
                Some("import") => self.import_declaration(),
                Some("export") => {
                    // `export` is consumed as a modifier above, so reaching it here means
                    // `export * from "p"` or `export { a } from "p"`, which is an import of `p`.
                    self.advance();
                    self.export_declaration();
                }
                Some("class") if container.is_none() || container.is_some() => {
                    if let Some(mut item) = self.class_declaration() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("interface") => {
                    if let Some(mut item) = self.interface_declaration() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("enum") => {
                    if let Some(mut item) = self.enum_declaration() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                // `type` is contextual: `type X = …` declares an alias, and `type` alone is a name.
                Some("type") if self.peek_at(1).and_then(Token::name).is_some() => {
                    if let Some(item) = self.type_alias() {
                        items.push(item);
                    }
                }
                Some("function") => {
                    if let Some(mut item) = self.function_declaration() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("const" | "let" | "var") if container.is_none() => {
                    items.extend(self.bindings());
                }
                Some(_) if container.is_some() => {
                    if let Some(mut item) = self.member() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                _ => {
                    // Not a declaration. Consumed so a call at file scope still yields its import.
                    self.statement();
                }
            }
        }
    }

    /// `@Name`, `@Name(...)`, repeated. TypeScript's decorators, in the same slot Java's annotations use.
    fn decorators(&mut self) -> Vec<Annotation> {
        let mut found = Vec::new();
        while self.peek().is_some_and(|token| token.is_punct('@')) {
            let start = self.position();
            self.advance();
            let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) else {
                return found;
            };
            self.advance();
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
        }
        found
    }

    fn modifiers(&mut self) {
        while let Some(name) = self.name_here() {
            // `export default class`, and `export` before a declaration, are modifiers. `export * from`
            // and `export { } from` are not — they are re-exports, which the caller reads as imports.
            if name == "export"
                && matches!(
                    self.peek_at(1).and_then(Token::name),
                    Some(
                        "class"
                            | "interface"
                            | "enum"
                            | "type"
                            | "function"
                            | "const"
                            | "let"
                            | "var"
                            | "default"
                            | "abstract"
                            | "async"
                            | "declare"
                    )
                )
            {
                self.advance();
                continue;
            }
            if name == "default" || (MODIFIERS.contains(&name) && name != "export") {
                self.advance();
                continue;
            }
            return;
        }
    }

    /// `import x from "p"`, `import { a, b } from "p"`, `import "p"`, `import type { T } from "p"`.
    fn import_declaration(&mut self) {
        let start = self.position();
        self.advance();
        // `import(` is a dynamic import expression, not a declaration.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.record_path_in(Delimiter::Paren, start);
            return;
        }
        // The clause, up to `from` or to the path itself.
        while let Some(token) = self.peek() {
            match token {
                Token::Text(path) => {
                    let path = path.clone();
                    self.advance();
                    self.push_import(path, start);
                    return;
                }
                Token::Ident(name) if name == "from" => {
                    self.advance();
                    if let Some(Token::Text(path)) = self.peek() {
                        let path = path.clone();
                        self.advance();
                        self.push_import(path, start);
                    }
                    return;
                }
                // A clause ends at a semicolon on a malformed line.
                Token::Punct(';') => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// `export * from "p"`, `export { a } from "p"`, and `export = x`.
    fn export_declaration(&mut self) {
        let start = self.previous_position();
        while let Some(token) = self.peek() {
            match token {
                Token::Ident(name) if name == "from" => {
                    self.advance();
                    if let Some(Token::Text(path)) = self.peek() {
                        let path = path.clone();
                        self.advance();
                        self.push_import(path, start);
                    }
                    return;
                }
                Token::Punct(';') => {
                    self.advance();
                    return;
                }
                Token::Open(Delimiter::Brace) => self.skip_balanced(Delimiter::Brace),
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Records the first string inside a balanced pair as an import, consuming the pair.
    ///
    /// `require("p")` and `import("p")` both arrive here. A call whose argument is not a literal string
    /// records nothing: a path built at run time is not a path this build can name.
    fn record_path_in(&mut self, delimiter: Delimiter, start: SourcePosition) {
        let mut depth = 0_u32;
        let mut path: Option<String> = None;
        while let Some(token) = self.peek() {
            match token {
                Token::Open(found) if *found == delimiter => depth += 1,
                Token::Close(found) if *found == delimiter => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        if let Some(path) = path {
                            self.push_import(path, start);
                        }
                        return;
                    }
                }
                Token::Text(found) if depth == 1 && path.is_none() => path = Some(found.clone()),
                _ => {}
            }
            self.advance();
        }
    }

    fn push_import(&mut self, path: String, start: SourcePosition) {
        if path.is_empty() {
            return;
        }
        // An interpolated path names no file. The lexer keeps a template's `${...}` as written and emits
        // it as text like any other string, so this is where the two are told apart — and a template with
        // no interpolation, `` require(`./m`) ``, is a static path and is still recorded.
        //
        // Recording `./${name}` would add an import that nothing can ever resolve, inflating the
        // unresolved count with something that was never resolvable rather than something missing.
        if path.contains("${") {
            return;
        }
        self.imports.push(Import {
            path,
            // A default or named binding renames what is imported rather than the module, so there is no
            // module alias to record. The field stays for the shared contract.
            alias: None,
            range: range(start, self.previous_position()),
        });
    }

    fn class_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = match self.peek().and_then(Token::name) {
            Some(name) => {
                let name = name.to_owned();
                self.advance();
                name
            }
            // `export default class { }` and a class expression declare nothing named.
            None => {
                self.skip_type_parameters();
                if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
                    self.skip_balanced(Delimiter::Brace);
                }
                return None;
            }
        };
        self.skip_type_parameters();
        let mut references = Vec::new();
        while let Some("extends" | "implements") = self.name_here() {
            self.advance();
            references.extend(self.supertypes());
        }
        let mut children = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.advance();
            children.extend(self.declarations(Some(ItemKind::Struct)));
        }
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

    fn interface_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        self.skip_type_parameters();
        let mut references = Vec::new();
        while let Some("extends") = self.name_here() {
            self.advance();
            references.extend(self.supertypes());
        }
        let mut children = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.advance();
            children.extend(self.declarations(Some(ItemKind::Trait)));
        }
        Some(Item {
            kind: ItemKind::Trait,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children,
        })
    }

    fn enum_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let mut children = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.advance();
            children.extend(self.enum_members());
        }
        Some(Item {
            kind: ItemKind::Enum,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references: Vec::new(),
            annotations: Vec::new(),
            children,
        })
    }

    /// An enum's members, each a field, separated by commas.
    fn enum_members(&mut self) -> Vec<Item> {
        let mut found = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Close(Delimiter::Brace)) | None => {
                    self.advance();
                    return found;
                }
                Some(token) if token.is_punct(',') => {
                    self.advance();
                }
                Some(token) if token.name().is_some() => {
                    let start = self.position();
                    let name = token.name().unwrap_or_default().to_owned();
                    self.advance();
                    // `A = 1` and `A = "x"`.
                    if self.peek().is_some_and(|token| token.is_punct('=')) {
                        while let Some(token) = self.peek() {
                            if token.is_punct(',')
                                || matches!(token, Token::Close(Delimiter::Brace))
                            {
                                break;
                            }
                            self.advance();
                        }
                    }
                    found.push(Item::new(
                        ItemKind::Field,
                        name,
                        range(start, self.previous_position()),
                    ));
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// `type X = …` and `type X<T> = …`.
    fn type_alias(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        self.skip_type_parameters();
        self.statement();
        Some(Item::new(
            ItemKind::TypeAlias,
            name,
            range(start, self.previous_position()),
        ))
    }

    fn function_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        // `function*` is a generator.
        if self.peek().is_some_and(|token| token.is_punct('*')) {
            self.advance();
        }
        let name = match self.peek().and_then(Token::name) {
            Some(name) => {
                let name = name.to_owned();
                self.advance();
                name
            }
            // An anonymous function expression declares nothing named.
            None => {
                self.skip_signature_and_body();
                return None;
            }
        };
        self.skip_type_parameters();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
        }
        self.skip_return_type();
        let references = if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.body()
        } else {
            self.statement();
            Vec::new()
        };
        Some(Item {
            kind: ItemKind::Function,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    /// `const a = …, b = …` at file scope, each a constant.
    ///
    /// A destructuring binding — `const { a, b } = obj` — declares names this does not record. Each is a
    /// name whose declaration is the object's shape rather than the source's, and recording them as
    /// declarations of this file would assert something the file does not say.
    fn bindings(&mut self) -> Vec<Item> {
        self.advance();
        let mut found = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Open(Delimiter::Brace)) => {
                    self.skip_balanced(Delimiter::Brace);
                    self.skip_initializer();
                }
                Some(Token::Open(Delimiter::Bracket)) => {
                    self.skip_balanced(Delimiter::Bracket);
                    self.skip_initializer();
                }
                Some(token) if token.name().is_some() => {
                    let start = self.position();
                    let name = token.name().unwrap_or_default().to_owned();
                    self.advance();
                    self.skip_type_annotation();
                    let references = self.skip_initializer();
                    let mut item = Item::new(
                        ItemKind::Constant,
                        name,
                        range(start, self.previous_position()),
                    );
                    item.references = references;
                    found.push(item);
                }
                _ => return found,
            }
            match self.peek() {
                Some(token) if token.is_punct(',') => {
                    self.advance();
                }
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return found;
                }
                _ => return found,
            }
        }
    }

    /// One member of a class or interface: a method, a property, or an accessor.
    fn member(&mut self) -> Option<Item> {
        let start = self.position();
        // `get x()`, `set x()`, `async m()`, `*gen()`.
        if matches!(self.name_here(), Some("get" | "set"))
            && self.peek_at(1).and_then(Token::name).is_some()
        {
            self.advance();
        }
        if self.peek().is_some_and(|token| token.is_punct('*')) {
            self.advance();
        }
        // A computed member name, `[Symbol.iterator]()`.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
            self.skip_signature_and_body();
            return None;
        }
        let name = self.peek().and_then(Token::name)?.to_owned();
        self.advance();
        // An optional or definite property, `x?: T` and `x!: T`.
        if self
            .peek()
            .is_some_and(|token| token.is_punct('?') || token.is_punct('!'))
        {
            self.advance();
        }
        self.skip_type_parameters();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
            self.skip_return_type();
            let references = if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
                self.body()
            } else {
                // An interface member or an abstract method has no body.
                self.statement();
                Vec::new()
            };
            let mut item = Item::new(
                ItemKind::Method,
                name,
                range(start, self.previous_position()),
            );
            item.references = references;
            return Some(item);
        }
        self.skip_type_annotation();
        let references = self.skip_initializer();
        let mut item = Item::new(
            ItemKind::Field,
            name,
            range(start, self.previous_position()),
        );
        item.references = references;
        Some(item)
    }

    /// The names a supertype list holds, as references.
    fn supertypes(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        loop {
            let start = self.position();
            let Some(name) = self.name_here().map(str::to_owned) else {
                return found;
            };
            self.advance();
            let mut name = name;
            let mut qualifier = None;
            while self.peek().is_some_and(|token| token.is_punct('.')) {
                self.advance();
                match self.peek().and_then(Token::name) {
                    Some(segment) => {
                        qualifier = Some(name);
                        name = segment.to_owned();
                        self.advance();
                    }
                    None => break,
                }
            }
            self.skip_type_parameters();
            found.push(Reference {
                name,
                qualifier,
                is_method: false,
                range: range(start, self.previous_position()),
            });
            if self.peek().is_some_and(|token| token.is_punct(',')) {
                self.advance();
                continue;
            }
            return found;
        }
    }

    /// A body, returning the calls made in it and recording any import it performs.
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
                    // `require("p")` and `import("p")` are imports wherever they appear.
                    if matches!(name.as_str(), "require" | "import")
                        && matches!(self.peek_at(1), Some(Token::Open(Delimiter::Paren)))
                    {
                        self.advance();
                        self.record_path_in(Delimiter::Paren, start);
                        continue;
                    }
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

    /// Consumes to the end of a statement, recording any import it performs.
    fn statement(&mut self) {
        loop {
            match self.peek() {
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return;
                }
                Some(Token::Open(Delimiter::Brace)) => {
                    self.body();
                }
                Some(Token::Close(Delimiter::Brace)) | None => return,
                Some(Token::Ident(name)) if matches!(name.as_str(), "require" | "import") => {
                    let start = self.position();
                    if matches!(self.peek_at(1), Some(Token::Open(Delimiter::Paren))) {
                        self.advance();
                        self.record_path_in(Delimiter::Paren, start);
                    } else {
                        self.advance();
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes `= …` up to the end of the binding, returning the calls in it.
    fn skip_initializer(&mut self) -> Vec<Reference> {
        if !self.peek().is_some_and(|token| token.is_punct('=')) {
            self.skip_statement_end();
            return Vec::new();
        }
        self.advance();
        let mut found = Vec::new();
        loop {
            match self.peek() {
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return found;
                }
                // A comma at this level ends one binding of several.
                Some(token) if token.is_punct(',') => return found,
                Some(Token::Open(Delimiter::Brace)) => found.extend(self.body()),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Close(Delimiter::Brace)) | None => return found,
                Some(Token::Ident(name)) if matches!(name.as_str(), "require" | "import") => {
                    let start = self.position();
                    if matches!(self.peek_at(1), Some(Token::Open(Delimiter::Paren))) {
                        self.advance();
                        self.record_path_in(Delimiter::Paren, start);
                    } else {
                        self.advance();
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes a `: T` type annotation, stopping before an initializer or the end of the declaration.
    fn skip_type_annotation(&mut self) {
        if !self.peek().is_some_and(|token| token.is_punct(':')) {
            return;
        }
        self.advance();
        loop {
            match self.peek() {
                Some(token)
                    if token.is_punct('=') || token.is_punct(';') || token.is_punct(',') =>
                {
                    return;
                }
                Some(Token::Open(Delimiter::Brace)) => self.skip_balanced(Delimiter::Brace),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                Some(Token::Close(_)) | None => return,
                Some(token) if token.is_punct('<') => self.skip_type_parameters(),
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes a `: T` return type, stopping at the body or the statement's end.
    fn skip_return_type(&mut self) {
        if !self.peek().is_some_and(|token| token.is_punct(':')) {
            return;
        }
        self.advance();
        loop {
            match self.peek() {
                Some(Token::Open(Delimiter::Brace)) | Some(Token::Close(_)) | None => return,
                Some(token) if token.is_punct(';') => return,
                Some(token) if token.is_punct('<') => self.skip_type_parameters(),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn skip_signature_and_body(&mut self) {
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
        }
        self.skip_return_type();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.skip_balanced(Delimiter::Brace);
        }
    }

    fn skip_statement_end(&mut self) {
        if self.peek().is_some_and(|token| token.is_punct(';')) {
            self.advance();
        }
    }

    /// Consumes a balanced `<...>` when one is next.
    fn skip_type_parameters(&mut self) {
        if !self.peek().is_some_and(|token| token.is_punct('<')) {
            return;
        }
        let mut depth = 0_u32;
        while let Some(token) = self.peek() {
            if token.is_punct('<') {
                depth += 1;
            } else if token.is_punct('>') {
                depth -= 1;
                if depth == 0 {
                    self.advance();
                    return;
                }
            } else if matches!(token, Token::Open(Delimiter::Brace)) {
                // Not a type parameter list. Stopping beats consuming a body.
                return;
            }
            self.advance();
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
            }
            self.advance();
        }
        text
    }
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

    fn analyze(source: &str) -> FileAnalysis {
        analyze_as(LANGUAGE, source)
    }

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
    fn every_form_that_names_a_module_is_an_import() {
        assert_eq!(
            paths(
                "import a from \"./a\";\n\
                 import { b, c } from './b';\n\
                 import \"./side-effect.css\";\n\
                 import type { T } from \"./types\";\n\
                 import * as ns from \"pkg\";\n"
            ),
            ["./a", "./b", "./side-effect.css", "./types", "pkg"]
        );
    }

    #[test]
    fn a_re_export_is_an_import_of_what_it_re_exports() {
        assert_eq!(
            paths("export * from \"./a\";\nexport { b } from \"./b\";\n"),
            ["./a", "./b"]
        );
    }

    #[test]
    fn a_require_or_a_dynamic_import_is_an_import_wherever_it_appears() {
        assert_eq!(paths("const fs = require(\"node:fs\");"), ["node:fs"]);
        assert_eq!(
            paths("async function load() { const m = await import(\"./lazy\"); }"),
            ["./lazy"]
        );
        assert_eq!(paths("function f() { require(\"./deep\"); }"), ["./deep"]);
    }

    #[test]
    fn an_asset_import_keeps_its_path_and_its_extension() {
        // The reason `IMPORTS` resolves by path correspondence. Java and Kotlin import a name; this
        // language imports a path, and an asset is imported the same way a module is.
        assert_eq!(
            paths("import logo from \"./assets/logo.png\";\nimport \"./styles/app.css\";"),
            ["./assets/logo.png", "./styles/app.css"]
        );
    }

    #[test]
    fn a_path_built_at_run_time_records_nothing() {
        // A template is kept as written by the lexer, so this would record `./${name}` — a path no file
        // answers to. Recording it would put an unresolvable import in every count.
        assert!(paths("const m = require(`./${name}`);").is_empty());
    }

    #[test]
    fn a_class_its_methods_and_its_properties_are_read() {
        assert_eq!(
            kinds(
                "export class Service {\n\
                   private readonly url: string = \"/api\";\n\
                   #secret = 1;\n\
                   constructor(private http: Http) { }\n\
                   async find(id: number): Promise<string> { return this.http.get(id); }\n\
                   get ready(): boolean { return true; }\n\
                 }\n"
            ),
            [
                (ItemKind::Struct, "Service".to_owned()),
                (ItemKind::Field, "url".to_owned()),
                (ItemKind::Field, "#secret".to_owned()),
                (ItemKind::Method, "constructor".to_owned()),
                (ItemKind::Method, "find".to_owned()),
                (ItemKind::Method, "ready".to_owned()),
            ]
        );
    }

    #[test]
    fn an_interface_is_a_trait_and_a_type_alias_is_an_alias() {
        assert_eq!(
            kinds("export interface Shape { area(): number; name: string; }"),
            [
                (ItemKind::Trait, "Shape".to_owned()),
                (ItemKind::Method, "area".to_owned()),
                (ItemKind::Field, "name".to_owned()),
            ]
        );
        assert_eq!(
            kinds("export type Id = string | number;"),
            [(ItemKind::TypeAlias, "Id".to_owned())]
        );
    }

    #[test]
    fn type_is_only_a_declaration_when_a_name_follows_it() {
        // `type` is contextual. Read as a keyword everywhere, `const type = 1` would declare an alias.
        assert_eq!(
            kinds("const type = 1;"),
            [(ItemKind::Constant, "type".to_owned())]
        );
    }

    #[test]
    fn an_enum_and_its_members_are_read() {
        assert_eq!(
            kinds("export enum Level { Low = 1, High = \"h\" }"),
            [
                (ItemKind::Enum, "Level".to_owned()),
                (ItemKind::Field, "Low".to_owned()),
                (ItemKind::Field, "High".to_owned()),
            ]
        );
    }

    #[test]
    fn a_function_and_a_const_arrow_are_both_declarations_and_stay_distinguishable() {
        // Both are functions to a reader, and the graph keeps the distinction the source makes: a rename
        // of one must not look like a move of the other.
        assert_eq!(
            kinds("export function one() { }\nexport const two = () => { };"),
            [
                (ItemKind::Function, "one".to_owned()),
                (ItemKind::Constant, "two".to_owned()),
            ]
        );
    }

    #[test]
    fn a_generator_and_an_async_function_are_read() {
        assert_eq!(
            kinds("export async function* stream() { yield 1; }"),
            [(ItemKind::Function, "stream".to_owned())]
        );
    }

    #[test]
    fn an_anonymous_default_export_declares_nothing_named() {
        assert!(kinds("export default class { m() { } }").is_empty());
        assert!(kinds("export default function () { }").is_empty());
    }

    #[test]
    fn a_destructuring_binding_declares_no_record() {
        // Each name's declaration is the object's shape rather than this file's, so recording them would
        // assert something the file does not say.
        assert!(kinds("const { a, b } = require(\"./m\");").is_empty());
        // The import is still recorded, which is the part the file does say.
        assert_eq!(paths("const { a, b } = require(\"./m\");"), ["./m"]);
    }

    #[test]
    fn a_supertype_is_a_reference_and_nothing_claims_to_be_implemented() {
        let found = analyze("class A extends B implements C, D { }");
        assert!(found.items[0].implements.is_none());
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["B", "C", "D"]
        );
    }

    #[test]
    fn a_call_in_a_body_is_a_reference_and_a_bare_name_is_not() {
        let found = analyze("class A { run() { const x = 1; helper(); other.thing(); } }");
        let method = &found.items[0].children[0];
        assert_eq!(
            method
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["helper", "thing"]
        );
        assert!(method.references[1].is_method);
    }

    #[test]
    fn a_decorator_keeps_its_arguments_as_written() {
        let found = analyze(
            "@Component({ selector: \"app-root\" })\n\
             export class AppComponent {\n\
               @Input() name: string;\n\
             }\n",
        );
        let component = &found.items[0];
        assert_eq!(component.annotations[0].name, "Component");
        assert!(
            component.annotations[0]
                .arguments
                .as_deref()
                .is_some_and(|held| held.contains("app-root"))
        );
        assert_eq!(component.children[0].annotations[0].name, "Input");
    }

    #[test]
    fn a_regex_in_a_body_does_not_hide_the_declaration_after_it() {
        // The lexer's ambiguity, reaching the analyzer. Read as division, the regex body would unbalance
        // the file and `After` would be lost or nested wrongly.
        assert_eq!(
            kinds("function f(s) { return /^\\{a\\}$/.test(s); }\nexport class After { }"),
            [
                (ItemKind::Function, "f".to_owned()),
                (ItemKind::Struct, "After".to_owned()),
            ]
        );
    }

    #[test]
    fn jsx_in_a_body_does_not_hide_the_declaration_after_it() {
        assert_eq!(
            kinds(
                "export function Card() {\n\
                   return <div className=\"card\"><span>hello</span></div>;\n\
                 }\n\
                 export class After { }\n"
            ),
            [
                (ItemKind::Function, "Card".to_owned()),
                (ItemKind::Struct, "After".to_owned()),
            ]
        );
    }

    #[test]
    fn a_generic_signature_does_not_hide_the_name() {
        assert_eq!(
            kinds("export function pick<T, U extends keyof T>(a: T, b: U): T[U] { return a[b]; }"),
            [(ItemKind::Function, "pick".to_owned())]
        );
        assert_eq!(
            kinds("class A { grouped<T>(x: Map<string, Array<T>>): void { } }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "grouped".to_owned()),
            ]
        );
    }

    #[test]
    fn malformed_source_yields_what_could_be_read_and_stops() {
        assert_eq!(
            kinds("class A { m() { "),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "m".to_owned()),
            ]
        );
        assert_eq!(
            kinds("export class A {"),
            [(ItemKind::Struct, "A".to_owned())]
        );
        assert!(kinds("class").is_empty());
        assert!(kinds("").is_empty());
    }

    #[test]
    fn the_language_is_recorded_as_given_so_one_analyzer_serves_two() {
        assert_eq!(analyze_as(LANGUAGE, "class A { }").language, "typescript");
        assert_eq!(analyze_as(JAVASCRIPT, "class A { }").language, "javascript");
    }

    #[test]
    fn both_languages_declare_the_same_capability_and_version() {
        let typescript = capability_for(LANGUAGE);
        let javascript = capability_for(JAVASCRIPT);
        assert_eq!(typescript.facts, javascript.facts);
        assert_eq!(typescript.version, javascript.version);
        assert_eq!(typescript.precision, javascript.precision);
        assert_eq!(javascript.language.as_str(), "javascript");
        // Declared and produced, each with a test above.
        for fact in [
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::Method,
            FactKind::Field,
            FactKind::Function,
            FactKind::Inheritance,
        ] {
            assert!(typescript.extracts(fact), "{fact} is declared and produced");
        }
        assert!(!typescript.extracts(FactKind::EntryPoint));
        assert!(!typescript.extracts(FactKind::Package));
    }
}
