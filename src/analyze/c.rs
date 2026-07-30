//! Reads C and C++ structure, without resolving anything.
//!
//! One analyzer for both, on the reasoning [`super::c_lexer`] gives: a C file is a C++ file that declares
//! no class. `language` is recorded as given, so a `.c` file reports `c` and a `.cpp` file `cpp`, even
//! though one analyzer read both.
//!
//! # Declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `#include <p>`, `#include "p"` | an import, whose path is `p` |
//! | `#define NAME …` | [`ItemKind::Constant`] |
//! | `struct S { … }`, `class C { … }` | [`ItemKind::Struct`], its members as children |
//! | `union U { … }` | [`ItemKind::Union`] |
//! | `enum E { … }`, `enum class E { … }` | [`ItemKind::Enum`], its enumerators as fields |
//! | `namespace n { … }` | [`ItemKind::Module`], its declarations as children |
//! | `typedef … N;`, `using N = …;` | [`ItemKind::TypeAlias`] |
//! | a function at file scope | [`ItemKind::Function`] |
//! | a function in a class body | [`ItemKind::Method`] |
//! | `void C::m() { … }` out of line | [`ItemKind::Method`], with `C` as its target |
//! | a member variable | [`ItemKind::Field`] |
//! | a base class | a reference |
//! | a call in a body | a reference |
//!
//! # An out-of-line definition names its class, the way Go's receiver does
//!
//! `void Service::Do() { … }` is a definition of a member declared elsewhere, and the qualifier says which
//! class. It is recorded with [`Item::target`] naming that class, which is the mechanism Go's receiver
//! uses — so [`crate::build`] draws the same `FOR_TYPE` edge without knowing which language wrote it.
//!
//! # What a macro costs, stated rather than hidden
//!
//! A macro may expand to anything, including a declaration or half of one. `DECLARE_CLASS(Foo)` declares a
//! class in many codebases and is a call here, because expanding it means implementing the preprocessor and
//! knowing the build's flags. So this analyzer reads what is written, and a macro-generated declaration is
//! absent rather than guessed at — the same choice every other analyzer here makes about what it cannot
//! see.
//!
//! Both arms of a `#if` are read, for the reason the lexer documents: a declaration in a branch is a
//! declaration the source contains, and picking one arm means picking a build.

use super::c_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads when the source is C.
pub const LANGUAGE: &str = "c";

/// The language this analyzer reads when the source is C++.
pub const CPP: &str = "cpp";

/// The language this analyzer reads for an Objective-C++ translation unit.
///
/// Read as C++, which is what the file mostly is. Objective-C's own message syntax and `@interface` are not
/// read, so a file using them yields its C++ declarations and not its Objective-C ones — which is why the
/// capability is registered under a name a report can name rather than being folded into `cpp`.
pub const OBJCPP: &str = "objcpp";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// What this analyzer declares it extracts, for one of the languages it reads.
#[must_use]
pub fn capability_for(language: &str) -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(language).unwrap_or_else(|_| NonEmptyText::literal("c")),
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
    }
}

/// Reads one C or C++ file.
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
        // C and C++ declare no package. An `#include` names a path and is resolved as one; a C++ namespace
        // is a declaration rather than a file-level fact.
        package: None,
        items,
        imports: reader.imports,
    }
}

/// Words that precede a declaration without being one.
const MODIFIERS: [&str; 17] = [
    "constexpr",
    "consteval",
    "explicit",
    "extern",
    "friend",
    "inline",
    "mutable",
    "noexcept",
    "override",
    "private",
    "protected",
    "public",
    "register",
    "static",
    "thread_local",
    "virtual",
    "volatile",
];

/// Words that begin a type declaration, and the kind each one makes.
const TYPE_KEYWORDS: [(&str, ItemKind); 4] = [
    ("class", ItemKind::Struct),
    ("enum", ItemKind::Enum),
    ("struct", ItemKind::Struct),
    ("union", ItemKind::Union),
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
            if let Token::Directive { name, rest } = token {
                let (name, rest) = (name.clone(), rest.clone());
                let start = self.position();
                self.advance();
                if let Some(item) = self.directive(&name, &rest, start) {
                    items.push(item);
                }
                continue;
            }
            match self.name_here() {
                Some("namespace") => {
                    if let Some(item) = self.namespace_declaration() {
                        items.push(item);
                    }
                }
                // A template's parameters precede whatever it declares.
                Some("template") => {
                    self.advance();
                    self.skip_angle_brackets();
                }
                Some("typedef") => {
                    if let Some(item) = self.typedef_declaration() {
                        items.push(item);
                    }
                }
                // `using N = T;` is an alias. `using namespace n;` and `using B::m;` bring a name into
                // scope and declare nothing, so they are consumed — falling through to the declarator
                // rule recorded `std` as a file-scope constant.
                Some("using") => {
                    if self.declares_an_alias() {
                        if let Some(item) = self.using_alias() {
                            items.push(item);
                        }
                    } else {
                        self.advance();
                        self.skip_to_statement_end();
                    }
                }
                Some(keyword) if kind_for(keyword).is_some() => {
                    let keyword = keyword.to_owned();
                    match self.type_declaration(&keyword) {
                        Some(item) => items.push(item),
                        // No type was declared: `struct S *p;` names one, and `struct { … } instance;`
                        // declares an anonymous one. Either way the declarator after it is still a
                        // declaration, so it is read rather than skipped.
                        None => {
                            if let Some(item) = self.member_or_function(container) {
                                items.push(item);
                            }
                        }
                    }
                }
                Some(_) => {
                    if let Some(item) = self.member_or_function(container) {
                        items.push(item);
                    }
                }
                None => {
                    self.advance();
                }
            }
        }
    }

    /// One preprocessor directive: an `#include` becomes an import, a `#define` a constant.
    ///
    /// Every other directive is read and contributes nothing. `#ifdef` in particular is *not* acted on —
    /// both arms of a conditional are read, because a declaration in a branch is one the source contains.
    fn directive(&mut self, name: &str, rest: &str, start: SourcePosition) -> Option<Item> {
        match name {
            "include" | "import" => {
                let path = header_path(rest)?;
                self.imports.push(Import {
                    path,
                    alias: None,
                    range: range(start, self.previous_position()),
                });
                None
            }
            "define" => {
                // The macro's name is everything up to a `(` or whitespace. A function-like macro's
                // parameter list is part of neither.
                let name: String = rest
                    .chars()
                    .take_while(|character| *character != '(' && !character.is_whitespace())
                    .collect();
                if name.is_empty() {
                    return None;
                }
                Some(Item::new(
                    ItemKind::Constant,
                    name,
                    range(start, self.previous_position()),
                ))
            }
            _ => None,
        }
    }

    fn modifiers(&mut self) {
        loop {
            match self.name_here() {
                Some(name) if MODIFIERS.contains(&name) => {
                    self.advance();
                    // `private:` and `public:` carry a colon.
                    if self.peek().is_some_and(|token| token.is_punct(':')) {
                        self.advance();
                    }
                }
                _ => return,
            }
        }
    }

    /// `namespace n { … }`, and an anonymous or nested one.
    fn namespace_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let mut name = String::new();
        while let Some(found) = self.name_here() {
            name = found.to_owned();
            self.advance();
            // `namespace a::b { }` names the innermost.
            if self.peek().is_some_and(|token| token.is_punct(':')) {
                self.advance();
                if self.peek().is_some_and(|token| token.is_punct(':')) {
                    self.advance();
                }
                continue;
            }
            break;
        }
        if !matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            // `namespace a = b;` is an alias of a namespace, which declares no scope.
            self.skip_to_statement_end();
            return None;
        }
        self.advance();
        let children = self.declarations(Some(ItemKind::Module));
        if name.is_empty() {
            // An anonymous namespace has no name to record it under. Its declarations belong to the file,
            // and returning them as a nameless item would put an unnamed record in the graph.
            return None;
        }
        let mut item = Item::new(
            ItemKind::Module,
            name,
            range(start, self.previous_position()),
        );
        item.children = children;
        Some(item)
    }

    /// `typedef <type> Name;`, whose name is the last one before the semicolon.
    fn typedef_declaration(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let mut last = None;
        // Once a declarator has been read from inside parentheses, a later group is the parameter list.
        // Letting it overwrite made `typedef int (*Callback)(void);` name the alias `void`.
        let mut declarator_found = false;
        loop {
            match self.peek() {
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    break;
                }
                Some(Token::Close(Delimiter::Brace)) | None => break,
                Some(Token::Open(Delimiter::Brace)) => self.skip_balanced(Delimiter::Brace),
                // A function pointer typedef names its type inside parentheses: `typedef int (*F)(void);`
                Some(Token::Open(Delimiter::Paren)) if !declarator_found => {
                    if let Some(found) = self.name_in_parentheses() {
                        last = Some(found);
                        declarator_found = true;
                    }
                }
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(token) if token.name().is_some() => {
                    last = token.name().map(str::to_owned);
                    self.advance();
                }
                _ => {
                    self.advance();
                }
            }
        }
        Some(Item::new(
            ItemKind::TypeAlias,
            last?,
            range(start, self.previous_position()),
        ))
    }

    /// The last name inside a balanced parenthesis, consumed.
    fn name_in_parentheses(&mut self) -> Option<String> {
        let mut found = None;
        let mut depth = 0_u32;
        while let Some(token) = self.peek() {
            match token {
                Token::Open(Delimiter::Paren) => depth += 1,
                Token::Close(Delimiter::Paren) => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return found;
                    }
                }
                Token::Ident(name) => found = Some(name.clone()),
                _ => {}
            }
            self.advance();
        }
        found
    }

    /// Reports whether a `using` here declares an alias rather than importing a name.
    fn declares_an_alias(&self) -> bool {
        self.peek_at(1).and_then(Token::name).is_some()
            && self.peek_at(2).is_some_and(|token| token.is_punct('='))
    }

    fn using_alias(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        self.skip_to_statement_end();
        Some(Item::new(
            ItemKind::TypeAlias,
            name,
            range(start, self.previous_position()),
        ))
    }

    /// `struct S { … }`, `class C : public B { … }`, `enum class E { … }`.
    ///
    /// Returns `None` when the keyword is an elaborated type specifier — `struct S *p;` — which names a type
    /// rather than declaring one.
    fn type_declaration(&mut self, keyword: &str) -> Option<Item> {
        let start = self.position();
        let kind = kind_for(keyword)?;
        self.advance();
        // `enum class E` and `enum struct E`.
        if keyword == "enum" && matches!(self.name_here(), Some("class" | "struct")) {
            self.advance();
        }
        // An attribute specifier, `class [[deprecated]] C`.
        while matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
        }
        let name = match self.name_here() {
            Some(found) => {
                let found = found.to_owned();
                self.advance();
                found
            }
            // An anonymous struct or enum, which has no name to record it under.
            None => String::new(),
        };
        let mut references = Vec::new();
        // An enum's underlying type, or a class's base list.
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            references.extend(self.base_list());
        }
        if !matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            // Not a definition: the keyword was naming a type.
            return None;
        }
        self.advance();
        let children = if kind == ItemKind::Enum {
            self.enumerators()
        } else {
            self.declarations(Some(kind))
        };
        if name.is_empty() {
            return None;
        }
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

    /// A base class list, whose access specifiers are consumed and whose names are references.
    fn base_list(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        loop {
            self.modifiers();
            // `virtual` is a modifier and consumed above; a `::` qualifier is read below.
            let start = self.position();
            let Some(name) = self.name_here().map(str::to_owned) else {
                return found;
            };
            self.advance();
            let mut name = name;
            let mut qualifier = None;
            while self.peek().is_some_and(|token| token.is_punct(':'))
                && self.peek_at(1).is_some_and(|token| token.is_punct(':'))
            {
                self.advance();
                self.advance();
                if let Some(segment) = self.peek().and_then(Token::name) {
                    qualifier = Some(name);
                    name = segment.to_owned();
                    self.advance();
                }
            }
            self.skip_angle_brackets();
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

    /// An enum's enumerators, each a field.
    fn enumerators(&mut self) -> Vec<Item> {
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
                    // `RED = 1 << 2` runs to the comma or the brace.
                    while let Some(token) = self.peek() {
                        if token.is_punct(',') || matches!(token, Token::Close(Delimiter::Brace)) {
                            break;
                        }
                        self.advance();
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

    /// A function, a method, or a variable, told apart by what follows the name.
    ///
    /// The same rule Java uses, with one addition: a `::` before the name makes this an out-of-line
    /// definition, and the qualifier is the class it belongs to.
    fn member_or_function(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        let mut last_name: Option<String> = None;
        let mut target: Option<String> = None;
        loop {
            match self.peek() {
                Some(Token::Open(Delimiter::Paren)) => {
                    let name = last_name?;
                    self.skip_balanced(Delimiter::Paren);
                    // Trailing specifiers: `const`, `noexcept`, `override`, `= 0`, `-> T`.
                    let mut references = Vec::new();
                    loop {
                        match self.peek() {
                            Some(Token::Open(Delimiter::Brace)) => {
                                references = self.body();
                                break;
                            }
                            Some(token) if token.is_punct(';') => {
                                self.advance();
                                break;
                            }
                            // A constructor's initializer list, which holds calls.
                            Some(token) if token.is_punct(':') => {
                                self.advance();
                            }
                            Some(Token::Close(Delimiter::Brace)) | None => break,
                            _ => {
                                self.advance();
                            }
                        }
                    }
                    let kind = if target.is_some() || holds_members(container) {
                        ItemKind::Method
                    } else {
                        ItemKind::Function
                    };
                    let mut item = Item::new(kind, name, range(start, self.previous_position()));
                    item.references = references;
                    item.target = target;
                    return Some(item);
                }
                // `Service::Do` — the qualifier is the class.
                Some(token)
                    if token.is_punct(':')
                        && self.peek_at(1).is_some_and(|held| held.is_punct(':')) =>
                {
                    self.advance();
                    self.advance();
                    target = last_name.take();
                    last_name = None;
                }
                Some(token) if token.is_punct('=') || token.is_punct(';') => {
                    let name = last_name?;
                    self.skip_to_statement_end();
                    let kind = if holds_members(container) {
                        ItemKind::Field
                    } else {
                        ItemKind::Constant
                    };
                    return Some(Item::new(
                        kind,
                        name,
                        range(start, self.previous_position()),
                    ));
                }
                Some(token) if token.is_punct('<') => self.skip_angle_brackets(),
                Some(Token::Open(Delimiter::Bracket)) => self.skip_balanced(Delimiter::Bracket),
                Some(token) if token.name().is_some() => {
                    last_name = token.name().map(str::to_owned);
                    self.advance();
                }
                Some(Token::Close(Delimiter::Brace)) | None => return None,
                Some(Token::Directive { .. }) => return None,
                _ => {
                    self.advance();
                }
            }
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
                    loop {
                        // `a.b()`, `a->b()`, and `A::b()` are all a call to `b`.
                        let separated = self.peek().is_some_and(|token| token.is_punct('.'))
                            || (self.peek().is_some_and(|token| token.is_punct('-'))
                                && self.peek_at(1).is_some_and(|held| held.is_punct('>')))
                            || (self.peek().is_some_and(|token| token.is_punct(':'))
                                && self.peek_at(1).is_some_and(|held| held.is_punct(':')));
                        if !separated {
                            break;
                        }
                        self.advance();
                        if self
                            .peek()
                            .is_some_and(|token| token.is_punct('>') || token.is_punct(':'))
                        {
                            self.advance();
                        }
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

    fn skip_to_statement_end(&mut self) {
        loop {
            match self.peek() {
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return;
                }
                Some(Token::Close(Delimiter::Brace)) | None => return,
                Some(Token::Open(Delimiter::Brace)) => self.skip_balanced(Delimiter::Brace),
                Some(Token::Open(Delimiter::Paren)) => self.skip_balanced(Delimiter::Paren),
                Some(Token::Directive { .. }) => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// Consumes a balanced `<…>` when one is next.
    fn skip_angle_brackets(&mut self) {
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
            } else if matches!(
                token,
                Token::Open(Delimiter::Brace) | Token::Directive { .. }
            ) {
                // Not a template argument list. Stopping beats consuming a body.
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
}

/// Reports whether a container is a type body, whose members are fields and methods.
///
/// A union's members are its fields exactly as a struct's are; deciding on `Struct` alone recorded them as
/// file-scope constants.
fn holds_members(container: Option<ItemKind>) -> bool {
    matches!(
        container,
        Some(ItemKind::Struct | ItemKind::Union | ItemKind::Enum | ItemKind::Trait)
    )
}

/// The kind a type keyword declares.
fn kind_for(keyword: &str) -> Option<ItemKind> {
    TYPE_KEYWORDS
        .iter()
        .find(|(found, _)| *found == keyword)
        .map(|(_, kind)| *kind)
}

/// The header an `#include` names, from either bracket form.
///
/// `<vector>` and `"local.h"` both yield their inside. Anything else — `#include MACRO_PATH` — names no
/// path this build can read, and recording the macro's name as a path would be a path nothing answers to.
fn header_path(rest: &str) -> Option<String> {
    let trimmed = rest.trim();
    let inside = trimmed
        .strip_prefix('<')
        .and_then(|held| held.split('>').next())
        .or_else(|| {
            trimmed
                .strip_prefix('"')
                .and_then(|held| held.split('"').next())
        })?;
    (!inside.is_empty()).then(|| inside.to_owned())
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
        analyze_as(CPP, source)
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
    fn an_include_is_an_import_in_either_bracket_form() {
        assert_eq!(
            paths("#include <vector>\n#include \"local/thing.h\"\n#include <sys/types.h>\n"),
            ["vector", "local/thing.h", "sys/types.h"]
        );
    }

    #[test]
    fn an_include_of_a_macro_records_no_path() {
        // Recording `HEADER` would put a path in the graph that nothing answers to.
        assert!(paths("#define HEADER <a.h>\n#include HEADER\n").is_empty());
    }

    #[test]
    fn a_define_is_a_constant_and_a_function_like_one_keeps_only_its_name() {
        assert_eq!(
            kinds("#define MAX 10\n#define SQUARE(x) ((x)*(x))\n#define BARE\n"),
            [
                (ItemKind::Constant, "MAX".to_owned()),
                (ItemKind::Constant, "SQUARE".to_owned()),
                (ItemKind::Constant, "BARE".to_owned()),
            ]
        );
    }

    #[test]
    fn a_class_its_methods_and_its_fields_are_read() {
        assert_eq!(
            kinds(
                "class Service {\n\
                 public:\n\
                 \x20 Service(int n);\n\
                 \x20 int Count() const;\n\
                 private:\n\
                 \x20 int count_;\n\
                 };\n"
            ),
            [
                (ItemKind::Struct, "Service".to_owned()),
                (ItemKind::Method, "Service".to_owned()),
                (ItemKind::Method, "Count".to_owned()),
                (ItemKind::Field, "count_".to_owned()),
            ]
        );
    }

    #[test]
    fn an_out_of_line_definition_names_its_class() {
        // The mechanism Go's receiver uses, so `build` draws the same `FOR_TYPE` edge without knowing which
        // language wrote it.
        let found = analyze("void Service::Do() { run(); }\n");
        assert_eq!(
            found
                .items
                .iter()
                .map(|item| (item.kind, item.name.clone(), item.target.clone()))
                .collect::<Vec<_>>(),
            [(
                ItemKind::Method,
                "Do".to_owned(),
                Some("Service".to_owned())
            )]
        );
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["run"]
        );
    }

    #[test]
    fn a_base_list_holds_references_and_its_access_specifiers_are_not_names() {
        let found = analyze("class D : public B, private ns::C { };\n");
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| (held.qualifier.clone(), held.name.clone()))
                .collect::<Vec<_>>(),
            [
                (None, "B".to_owned()),
                (Some("ns".to_owned()), "C".to_owned())
            ]
        );
    }

    #[test]
    fn a_struct_a_union_and_an_enum_each_take_their_own_kind() {
        assert_eq!(
            kinds("struct S { int a; };\nunion U { int a; float b; };\nenum E { RED, GREEN };\n"),
            [
                (ItemKind::Struct, "S".to_owned()),
                (ItemKind::Field, "a".to_owned()),
                (ItemKind::Union, "U".to_owned()),
                (ItemKind::Field, "a".to_owned()),
                (ItemKind::Field, "b".to_owned()),
                (ItemKind::Enum, "E".to_owned()),
                (ItemKind::Field, "RED".to_owned()),
                (ItemKind::Field, "GREEN".to_owned()),
            ]
        );
    }

    #[test]
    fn an_enum_class_and_its_underlying_type_are_read() {
        assert_eq!(
            kinds("enum class Level : int { Low = 1, High };\n"),
            [
                (ItemKind::Enum, "Level".to_owned()),
                (ItemKind::Field, "Low".to_owned()),
                (ItemKind::Field, "High".to_owned()),
            ]
        );
    }

    #[test]
    fn an_elaborated_type_specifier_declares_nothing() {
        // `struct S *p;` names a type rather than declaring one, and recording `S` here would assert this
        // file declares it.
        assert_eq!(
            kinds("struct S *p;\n"),
            [(ItemKind::Constant, "p".to_owned())]
        );
    }

    #[test]
    fn a_namespace_is_a_module_holding_its_declarations() {
        let found = analyze("namespace app {\nvoid run();\nclass C { };\n}\n");
        assert_eq!(found.items[0].kind, ItemKind::Module);
        assert_eq!(found.items[0].name, "app");
        assert_eq!(
            found.items[0]
                .children
                .iter()
                .map(|item| (item.kind, item.name.clone()))
                .collect::<Vec<_>>(),
            [
                (ItemKind::Function, "run".to_owned()),
                (ItemKind::Struct, "C".to_owned()),
            ]
        );
    }

    #[test]
    fn an_anonymous_namespace_contributes_no_unnamed_record() {
        // There is no name to record it under, and an unnamed record is not a record.
        let found = analyze("namespace {\nvoid helper();\n}\n");
        assert!(
            found.walk().all(|item| !item.name.is_empty()),
            "{:?}",
            found.items
        );
    }

    #[test]
    fn a_typedef_and_a_using_alias_are_both_aliases() {
        assert_eq!(
            kinds("typedef unsigned long Size;\nusing Id = int;\ntypedef int (*Callback)(void);\n"),
            [
                (ItemKind::TypeAlias, "Size".to_owned()),
                (ItemKind::TypeAlias, "Id".to_owned()),
                (ItemKind::TypeAlias, "Callback".to_owned()),
            ]
        );
    }

    #[test]
    fn using_a_namespace_or_a_member_declares_nothing() {
        assert!(kinds("using namespace std;\n").is_empty());
        assert!(
            kinds("class D : B { using B::m; };\n")
                .iter()
                .all(|(kind, _)| *kind != ItemKind::TypeAlias)
        );
    }

    #[test]
    fn a_template_does_not_hide_what_it_declares() {
        assert_eq!(
            kinds("template <typename T>\nclass Holder {\n public:\n  T get();\n};\n"),
            [
                (ItemKind::Struct, "Holder".to_owned()),
                (ItemKind::Method, "get".to_owned()),
            ]
        );
        assert_eq!(
            kinds("template <typename T, int N>\nT pick(T a) { return a; }\n"),
            [(ItemKind::Function, "pick".to_owned())]
        );
    }

    #[test]
    fn a_call_through_any_accessor_is_a_reference() {
        let found = analyze("void f() { helper(); obj.thing(); ptr->other(); Ns::scoped(); }\n");
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["helper", "thing", "other", "scoped"]
        );
    }

    #[test]
    fn a_raw_string_in_a_body_does_not_hide_the_declaration_after_it() {
        assert_eq!(
            kinds("void f() { auto q = R\"({\"a\": 1})\"; }\nvoid after() { }\n"),
            [
                (ItemKind::Function, "f".to_owned()),
                (ItemKind::Function, "after".to_owned()),
            ]
        );
    }

    #[test]
    fn both_arms_of_a_conditional_are_read() {
        // Neither can be evaluated without the build's flags, and a declaration in a branch is one the
        // source contains. Picking an arm would mean picking a build.
        assert_eq!(
            kinds("#ifdef WINDOWS\nvoid platform_a();\n#else\nvoid platform_b();\n#endif\n"),
            [
                (ItemKind::Function, "platform_a".to_owned()),
                (ItemKind::Function, "platform_b".to_owned()),
            ]
        );
    }

    #[test]
    fn malformed_source_yields_what_could_be_read_and_stops() {
        assert_eq!(
            kinds("class A {\n  void m();"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "m".to_owned()),
            ]
        );
        assert!(kinds("class").is_empty());
        assert!(kinds("").is_empty());
    }

    #[test]
    fn the_language_is_recorded_as_given_so_one_analyzer_serves_three() {
        assert_eq!(analyze_as(LANGUAGE, "int a;").language, "c");
        assert_eq!(analyze_as(CPP, "int a;").language, "cpp");
        assert_eq!(analyze_as(OBJCPP, "int a;").language, "objcpp");
    }

    #[test]
    fn every_language_declares_the_same_capability() {
        let c = capability_for(LANGUAGE);
        let cpp = capability_for(CPP);
        assert_eq!(c.facts, cpp.facts);
        for fact in [
            FactKind::Method,
            FactKind::Field,
            FactKind::Function,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::Inheritance,
            FactKind::Module,
        ] {
            assert!(c.extracts(fact), "{fact} is declared and produced");
        }
        assert!(!c.extracts(FactKind::EntryPoint));
        assert!(!c.extracts(FactKind::Package));
    }
}
