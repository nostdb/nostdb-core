//! The Rust structural analyzer.
//!
//! Reads item structure — modules, types, functions, methods, fields, implementations,
//! imports, and call sites — without resolving a single name. That is
//! [`PrecisionClass::DeterministicSyntactic`], and it is what the analyzer declares.
//!
//! # What "skim" means here
//!
//! The parser understands item *headers* and treats everything else as a balanced group to
//! step over. It knows that `fn` starts a function and that the next identifier is its
//! name; it does not know what a `where` clause means, and it does not need to. Anything
//! it does not recognize is skipped to the next item boundary, so a construct added to the
//! language in a future edition costs the items around it nothing.
//!
//! # What it deliberately does not claim
//!
//! - A call is recorded as a reference to a name, never as an edge to a function. Deciding
//!   which `parse` a bare `parse(` means requires imports, generics, and trait resolution.
//! - A macro invocation's body is skipped. `macro_rules!` can put anything inside a
//!   balanced group, including text that is not Rust, and guessing is how a skim parser
//!   starts inventing items that do not exist.
//! - `#[cfg]` is not evaluated. An item behind a disabled `cfg` is still an item in the
//!   file, and reporting only one configuration's view would make the graph depend on the
//!   platform that built it.
//!
//! Each of those is a place a fuller front end would do better, and each is why the
//! precision class is `DeterministicSyntactic` rather than `DeterministicSemantic`.

use super::rust_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{At, FileAnalysis, Import, Item, ItemKind, PRECISION, Reference, range};
use crate::analysis::AnalyzerCapability;
use crate::analysis::FactKind;
use crate::text::NonEmptyText;

/// The language this analyzer reads.
pub const LANGUAGE: &str = "rust";

/// This analyzer's version, which is part of its identity for ownership purposes.
pub const VERSION: &str = "1";

/// What this analyzer declares.
///
/// # Panics
///
/// Never. The language and version are non-empty literals.
#[must_use]
pub fn capability() -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(LANGUAGE).unwrap_or_else(|_| NonEmptyText::literal("rust")),
        precision: PRECISION,
        facts: vec![
            FactKind::Module,
            FactKind::File,
            FactKind::Type,
            FactKind::Function,
            FactKind::Method,
            FactKind::Field,
            FactKind::Declaration,
            FactKind::Definition,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::InterfaceImplementation,
            FactKind::SourceRange,
            FactKind::ContentHash,
        ],
        version: NonEmptyText::new(VERSION).unwrap_or_else(|_| NonEmptyText::literal("1")),
    }
}

/// Analyzes one Rust file.
///
/// Never fails. Source that does not parse yields whatever structure was readable before
/// the confusion, because a structural analyzer runs over files somebody is still editing
/// and refusing to report anything for one syntax error would make the common case the
/// failing case.
#[must_use]
pub fn analyze(source: &str) -> FileAnalysis {
    let tokens = tokenize(source);
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        imports: Vec::new(),
    };
    let items = parser.items(None);
    FileAnalysis {
        language: LANGUAGE.to_owned(),
        digest: crate::sync::digest_bytes(source.as_bytes()),
        items,
        imports: parser.imports,
    }
}

struct Parser<'a> {
    tokens: &'a [Spanned],
    at: usize,
    imports: Vec<Import>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at).map(|spanned| &spanned.token)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Token> {
        self.tokens
            .get(self.at + ahead)
            .map(|spanned| &spanned.token)
    }

    fn position(&self) -> At {
        self.tokens.get(self.at).map_or_else(
            || self.end_position(),
            |spanned| (spanned.line, spanned.column, spanned.offset),
        )
    }

    /// The position of the last token consumed, which ends a range.
    fn previous_position(&self) -> At {
        match self.at.checked_sub(1).and_then(|at| self.tokens.get(at)) {
            Some(spanned) => (spanned.line, spanned.column, spanned.offset),
            None => (1, 1, 0),
        }
    }

    /// The position past the last token, for a range that runs to end of input.
    fn end_position(&self) -> At {
        self.tokens.last().map_or((1, 1, 0), |spanned| {
            (spanned.line, spanned.column, spanned.offset)
        })
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.at).map(|spanned| &spanned.token);
        if token.is_some() {
            self.at += 1;
        }
        token
    }

    fn keyword(&self) -> Option<&str> {
        self.peek().and_then(Token::keyword)
    }

    fn eat_keyword(&mut self, word: &str) -> bool {
        if self.keyword() == Some(word) {
            self.at += 1;
            return true;
        }
        false
    }

    fn eat_punct(&mut self, character: char) -> bool {
        if self.peek().is_some_and(|token| token.is_punct(character)) {
            self.at += 1;
            return true;
        }
        false
    }

    /// Consumes the next identifier, when one is there.
    fn name(&mut self) -> Option<String> {
        let name = self.peek().and_then(Token::name)?.to_owned();
        self.at += 1;
        Some(name)
    }

    /// Steps over a balanced group, having not yet consumed its opener.
    ///
    /// Returns whether one was there. This is the parser's whole strategy for everything
    /// it does not understand: the lexer already guaranteed the nesting is real, so
    /// stepping over a group is always safe even when its contents are not Rust.
    fn skip_group(&mut self) -> bool {
        let Some(Token::Open(opener)) = self.peek().cloned() else {
            return false;
        };
        self.at += 1;
        let mut depth = 1_usize;
        while depth > 0 {
            match self.advance() {
                None => return true,
                Some(Token::Open(_)) => depth += 1,
                Some(Token::Close(_)) => depth -= 1,
                Some(_) => {}
            }
        }
        let _ = opener;
        true
    }

    /// Skips attributes, `#[...]` and `#![...]`, and reports whether any were there.
    fn skip_attributes(&mut self) {
        while self.peek().is_some_and(|token| token.is_punct('#')) {
            let mut ahead = 1_usize;
            if self.peek_at(ahead).is_some_and(|token| token.is_punct('!')) {
                ahead += 1;
            }
            if !matches!(self.peek_at(ahead), Some(Token::Open(Delimiter::Bracket))) {
                return;
            }
            self.at += ahead;
            self.skip_group();
        }
    }

    /// Skips `pub`, `pub(crate)`, `pub(in path)`, and the item modifiers.
    fn skip_qualifiers(&mut self) {
        loop {
            match self.keyword() {
                Some("pub") => {
                    self.at += 1;
                    if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                        self.skip_group();
                    }
                }
                Some("async" | "unsafe" | "default" | "move") => self.at += 1,
                // `const` and `static` are modifiers in `const fn` and items in
                // `const NAME: T = ...`. Only the first form is skipped here; the second
                // is an item in its own right.
                Some("const" | "static") if self.is_modifier() => self.at += 1,
                Some("extern") => {
                    self.at += 1;
                    // `extern "C"` carries an ABI string; `extern crate` does not and is
                    // handled as an item.
                    if matches!(self.peek(), Some(Token::Literal)) {
                        self.at += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// Distinguishes `const fn f()` from `const NAME: T = ...`.
    ///
    /// A `const` or `static` is a modifier exactly when something that can carry one
    /// follows it. Anything else names a constant.
    fn is_modifier(&self) -> bool {
        matches!(
            self.peek_at(1).and_then(Token::keyword),
            Some("fn" | "unsafe" | "extern" | "async")
        )
    }

    /// Steps over generic parameters or arguments, `<...>`, when they are there.
    ///
    /// The lexer emits `<` and `>` as separate punctuation, so this counts them, treating
    /// `>>` as two closes. That is the same shortcut a real parser takes and it is exact
    /// for anything an item header can contain.
    fn skip_generics(&mut self) {
        if !self.peek().is_some_and(|token| token.is_punct('<')) {
            return;
        }
        let entry = self.at;
        self.at += 1;
        let mut depth = 1_usize;
        while depth > 0 {
            match self.peek() {
                None => return,
                // A closing delimiter belongs to something that opened before the `<`, so
                // the `<` was not generics after all. Backing out is what keeps a
                // misreading local instead of swallowing the rest of the enclosing group.
                Some(Token::Close(_)) => {
                    self.at = entry;
                    return;
                }
                Some(Token::Punct('<')) => {
                    depth += 1;
                    self.at += 1;
                }
                Some(Token::Punct('>')) => {
                    depth -= 1;
                    self.at += 1;
                }
                // A nested group inside a generic argument — an array length, a closure —
                // is stepped over whole so its punctuation cannot be miscounted.
                Some(Token::Open(_)) => {
                    self.skip_group();
                }
                Some(_) => self.at += 1,
            }
        }
    }

    /// Reads a path in item position, where a bare `<` begins generic arguments.
    fn path(&mut self) -> Vec<String> {
        self.path_with(true)
    }

    /// Reads a path in expression position, where a bare `<` is less-than.
    ///
    /// This distinction is not cosmetic. Reading the `<` in `if float < -LIMIT {` as the
    /// start of generic arguments makes the scan run forward to the next `>`, consuming
    /// braces on the way, and from there the body's depth count is wrong and the rest of
    /// the file collapses into one item. Rust requires a turbofish in expression position
    /// for exactly the same reason.
    fn expression_path(&mut self) -> Vec<String> {
        self.path_with(false)
    }

    /// Reads a path, returning its segments.
    fn path_with(&mut self, bare_generics: bool) -> Vec<String> {
        let mut segments = Vec::new();
        loop {
            self.eat_punct(':');
            self.eat_punct(':');
            let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) else {
                break;
            };
            self.at += 1;
            segments.push(name);
            // Generic arguments belong to the segment, not to the path.
            if bare_generics {
                self.skip_generics();
            }
            if !(self.peek().is_some_and(|token| token.is_punct(':'))
                && self.peek_at(1).is_some_and(|token| token.is_punct(':')))
            {
                break;
            }
            // `collect::<Vec<u8>>()` — this `::` introduces a turbofish rather than
            // another segment. The path may still continue past it, as in
            // `Vec::<u8>::with_capacity`, so the check for a following `::` is repeated.
            if self.peek_at(2).is_some_and(|token| token.is_punct('<')) {
                self.at += 2;
                self.skip_generics();
                if !(self.peek().is_some_and(|token| token.is_punct(':'))
                    && self.peek_at(1).is_some_and(|token| token.is_punct(':')))
                {
                    break;
                }
            }
        }
        segments
    }

    /// Reads the type a `for` or an `impl` names, reduced to its last path segment.
    ///
    /// A type is reported by name rather than by its full spelling, because the spelling
    /// carries lifetimes and generic arguments that say nothing about which type it is.
    fn type_name(&mut self) -> Option<String> {
        // Step over the leading punctuation a type can start with: `&`, `&'a`, `*`, `dyn`.
        loop {
            match self.peek() {
                Some(Token::Punct('&' | '*')) => self.at += 1,
                Some(Token::Lifetime(_)) => self.at += 1,
                Some(token) if token.keyword() == Some("mut") => self.at += 1,
                Some(token) if token.keyword() == Some("dyn") => self.at += 1,
                Some(Token::Open(Delimiter::Bracket | Delimiter::Paren)) => {
                    // A slice, array, or tuple type has no single name to report.
                    self.skip_group();
                    return None;
                }
                _ => break,
            }
        }
        self.path().pop()
    }

    /// Steps to the end of an item this parser does not recognize.
    ///
    /// Stops after a `;` or a balanced group at this level, which between them terminate
    /// every item form. Guaranteed to consume at least one token, so a caller looping on
    /// this cannot spin.
    fn skip_unknown_item(&mut self) {
        let start = self.at;
        loop {
            match self.peek() {
                None => return,
                Some(Token::Punct(';')) => {
                    self.at += 1;
                    return;
                }
                Some(Token::Open(_)) => {
                    self.skip_group();
                    return;
                }
                // A closing brace belongs to the enclosing block, not to this item.
                Some(Token::Close(_)) => {
                    if self.at == start {
                        self.at += 1;
                    }
                    return;
                }
                Some(_) => self.at += 1,
            }
        }
    }

    /// Parses items until the enclosing group closes or input runs out.
    ///
    /// `container` names what the items belong to, which is what decides whether a `fn` is
    /// a function or a method.
    fn items(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            self.skip_attributes();
            match self.peek() {
                None | Some(Token::Close(_)) => return items,
                _ => {}
            }
            let before = self.at;
            if let Some(item) = self.item(container) {
                items.push(item);
            }
            if self.at == before {
                // Nothing recognized and nothing consumed: step over whatever this is
                // rather than looping on it.
                self.skip_unknown_item();
                if self.at == before {
                    self.at += 1;
                }
            }
        }
    }

    /// Parses one item, when the next tokens begin one.
    fn item(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        let entry = self.at;
        self.skip_qualifiers();

        // A macro invocation at item position — `foo! { ... }` — is stepped over whole.
        if self.peek().and_then(Token::name).is_some()
            && self.peek_at(1).is_some_and(|token| token.is_punct('!'))
        {
            self.at += 2;
            if self.keyword().is_some() {
                // `macro_rules! name { ... }`: the name is not an item this reports.
                self.at += 1;
            }
            self.skip_group();
            self.eat_punct(';');
            return None;
        }

        let keyword = self.keyword()?.to_owned();
        match keyword.as_str() {
            "mod" => self.module(start),
            "fn" => self.function(start, container),
            "struct" => self.record(start, ItemKind::Struct),
            "union" => self.record(start, ItemKind::Union),
            "enum" => self.enumeration(start),
            "trait" => self.trait_item(start),
            "impl" => self.implementation(start),
            "type" => self.alias(start),
            "const" | "static" => self.constant(start),
            "use" => {
                self.import();
                None
            }
            _ => {
                self.at = entry;
                None
            }
        }
    }

    fn module(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        let mut item = Item::new(
            ItemKind::Module,
            name,
            range(start, self.previous_position()),
        );
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.at += 1;
            item.children = self.items(Some(ItemKind::Module));
            self.eat_punct('}');
            let _ = self.advance_if_close();
        } else {
            // `mod name;` — the module is declared here and lives in another file. It is
            // still a module of this crate, and cross-file work joins the two later.
            self.eat_punct(';');
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    /// Consumes a closing delimiter, when the next token is one.
    fn advance_if_close(&mut self) -> bool {
        if matches!(self.peek(), Some(Token::Close(_))) {
            self.at += 1;
            return true;
        }
        false
    }

    fn function(&mut self, start: At, container: Option<ItemKind>) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        // A method is a function whose container associates it with a type or a trait.
        let kind = match container {
            Some(ItemKind::Implementation | ItemKind::Trait) => ItemKind::Method,
            _ => ItemKind::Function,
        };
        let mut item = Item::new(kind, name, range(start, self.previous_position()));

        self.skip_generics();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_group();
        }
        // Return type, `where` clause, and everything else up to the body or the `;`.
        while !matches!(
            self.peek(),
            None | Some(Token::Open(Delimiter::Brace))
                | Some(Token::Punct(';'))
                | Some(Token::Close(_))
        ) {
            if matches!(self.peek(), Some(Token::Open(_))) {
                self.skip_group();
            } else {
                self.at += 1;
            }
        }

        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            item.references = self.body();
        } else {
            // A signature with no body: a trait method or an `extern` declaration.
            self.eat_punct(';');
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    /// Reads a function body, collecting the names it refers to.
    ///
    /// Every `name(` is a reference, and a `.name(` is one written as a method call. Which
    /// definition each names is not decided here, and cannot be: it needs imports,
    /// generics, and trait resolution.
    fn body(&mut self) -> Vec<Reference> {
        let mut references = Vec::new();
        let Some(Token::Open(_)) = self.peek() else {
            return references;
        };
        self.at += 1;
        let mut depth = 1_usize;

        while depth > 0 {
            let position = self.position();
            match self.peek() {
                None => break,
                Some(Token::Open(_)) => {
                    depth += 1;
                    self.at += 1;
                }
                Some(Token::Close(_)) => {
                    depth -= 1;
                    self.at += 1;
                }
                Some(Token::Ident { .. }) => {
                    // `call_site` consumes the path either way. Advancing again here would
                    // step over the token after it — and when that token is a brace, the
                    // depth count is wrong from then on and every later item lands in the
                    // wrong parent. Found by `Self { .. }` in a constructor.
                    let before = self.at;
                    if let Some(reference) = self.call_site(position) {
                        references.push(reference);
                    }
                    if self.at == before {
                        self.at += 1;
                    }
                }
                Some(_) => self.at += 1,
            }
        }
        references
    }

    /// Reads a call at the current identifier, when there is one.
    ///
    /// Consumes the identifier either way, so a caller cannot loop on a name that turned
    /// out not to be a call.
    fn call_site(&mut self, position: At) -> Option<Reference> {
        // A `.` immediately before makes this a method call on a receiver.
        let is_method = self
            .at
            .checked_sub(1)
            .and_then(|before| self.tokens.get(before))
            .is_some_and(|spanned| spanned.token.is_punct('.'));

        let segments = self.expression_path();
        if segments.is_empty() {
            return None;
        }
        // A macro invocation is not a call to a function of that name.
        if self.peek().is_some_and(|token| token.is_punct('!')) {
            self.at += 1;
            self.skip_group();
            return None;
        }
        if !matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            return None;
        }

        let mut segments = segments;
        let name = segments.pop()?;
        let qualifier = (!segments.is_empty()).then(|| segments.join("::"));
        Some(Reference {
            name,
            qualifier,
            is_method,
            range: range(position, self.previous_position()),
        })
    }

    /// Parses a struct or union: a name, then fields in whichever form.
    fn record(&mut self, start: At, kind: ItemKind) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        let mut item = Item::new(kind, name, range(start, self.previous_position()));
        self.skip_generics();
        self.skip_where_clause();

        match self.peek() {
            Some(Token::Open(Delimiter::Brace)) => {
                self.at += 1;
                item.children = self.fields();
                self.advance_if_close();
            }
            Some(Token::Open(Delimiter::Paren)) => {
                // A tuple struct's fields are positional and have no names to report.
                self.skip_group();
                self.eat_punct(';');
            }
            _ => {
                self.eat_punct(';');
            }
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    /// Reads named fields until the enclosing brace closes.
    fn fields(&mut self) -> Vec<Item> {
        let mut fields = Vec::new();
        loop {
            self.skip_attributes();
            match self.peek() {
                None | Some(Token::Close(_)) => return fields,
                _ => {}
            }
            let start = self.position();
            let before = self.at;
            self.skip_qualifiers();
            let Some(name) = self.name() else {
                if self.at == before {
                    self.at += 1;
                }
                continue;
            };
            // `name: Type` — anything else at this position is not a field.
            if !self.eat_punct(':') {
                self.skip_to_comma();
                continue;
            }
            self.skip_to_comma();
            fields.push(Item::new(
                ItemKind::Field,
                name,
                range(start, self.previous_position()),
            ));
        }
    }

    /// Steps to just past the next comma that separates two fields.
    ///
    /// A comma inside a type does not. `fields: BTreeMap<&'a str, (FieldType, bool)>` has
    /// two of them and one field, and treating the first as a separator ends the field
    /// list at the closing paren — taking the rest of the file with it.
    ///
    /// Bracketing groups are stepped over whole. Angle brackets are not tokens the lexer
    /// pairs, so they are counted here, saturating on the way down because `-> ` in a
    /// function-pointer type contributes a `>` that never opened.
    fn skip_to_comma(&mut self) {
        let mut angle = 0_usize;
        loop {
            match self.peek() {
                None | Some(Token::Close(_)) => return,
                Some(Token::Punct(',')) if angle == 0 => {
                    self.at += 1;
                    return;
                }
                Some(Token::Punct('<')) => {
                    angle += 1;
                    self.at += 1;
                }
                Some(Token::Punct('>')) => {
                    angle = angle.saturating_sub(1);
                    self.at += 1;
                }
                Some(Token::Open(_)) => {
                    self.skip_group();
                }
                Some(_) => self.at += 1,
            }
        }
    }

    /// Parses an enum: a name, then variants, whose named fields are fields of the enum.
    fn enumeration(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        let mut item = Item::new(ItemKind::Enum, name, range(start, self.previous_position()));
        self.skip_generics();
        self.skip_where_clause();

        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.at += 1;
            loop {
                self.skip_attributes();
                match self.peek() {
                    None | Some(Token::Close(_)) => break,
                    _ => {}
                }
                let variant_start = self.position();
                let before = self.at;
                let Some(variant) = self.name() else {
                    if self.at == before {
                        self.at += 1;
                    }
                    continue;
                };
                let mut child = Item::new(
                    ItemKind::Field,
                    variant,
                    range(variant_start, self.previous_position()),
                );
                match self.peek() {
                    Some(Token::Open(Delimiter::Brace)) => {
                        self.at += 1;
                        child.children = self.fields();
                        self.advance_if_close();
                    }
                    Some(Token::Open(Delimiter::Paren)) => {
                        self.skip_group();
                    }
                    _ => {}
                }
                child.range = range(variant_start, self.previous_position());
                item.children.push(child);
                self.skip_to_comma();
            }
            self.advance_if_close();
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    fn trait_item(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        let mut item = Item::new(
            ItemKind::Trait,
            name,
            range(start, self.previous_position()),
        );
        self.skip_generics();
        self.skip_supertraits();
        self.skip_where_clause();

        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.at += 1;
            item.children = self.items(Some(ItemKind::Trait));
            self.advance_if_close();
        } else {
            self.eat_punct(';');
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    /// Steps over `: Bound + Bound` after a trait name.
    fn skip_supertraits(&mut self) {
        if !self.peek().is_some_and(|token| token.is_punct(':')) {
            return;
        }
        while !matches!(
            self.peek(),
            None | Some(Token::Open(Delimiter::Brace))
                | Some(Token::Punct(';'))
                | Some(Token::Close(_))
        ) {
            if self.keyword() == Some("where") {
                return;
            }
            self.at += 1;
        }
    }

    /// Steps over a `where` clause, which can appear before a body or a semicolon.
    fn skip_where_clause(&mut self) {
        if self.keyword() != Some("where") {
            return;
        }
        while !matches!(
            self.peek(),
            None | Some(Token::Open(Delimiter::Brace))
                | Some(Token::Punct(';'))
                | Some(Token::Close(_))
        ) {
            if matches!(self.peek(), Some(Token::Open(_))) {
                self.skip_group();
            } else {
                self.at += 1;
            }
        }
    }

    /// Parses `impl Type { .. }` or `impl Trait for Type { .. }`.
    ///
    /// An implementation is reported as an item of its own rather than folded into the
    /// type, because a type can have several and they can implement different traits. Its
    /// name is the type it is for, so a reader sees `impl Parser` rather than an anonymous
    /// block.
    fn implementation(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        self.skip_generics();

        let first = self.type_name();
        let (target, implements) = if self.eat_keyword("for") {
            (self.type_name(), first)
        } else {
            (first, None)
        };

        let name = target.clone().unwrap_or_else(|| "impl".to_owned());
        let mut item = Item::new(
            ItemKind::Implementation,
            name,
            range(start, self.previous_position()),
        );
        item.target = target;
        item.implements = implements;

        self.skip_where_clause();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.at += 1;
            item.children = self.items(Some(ItemKind::Implementation));
            self.advance_if_close();
        }
        item.range = range(start, self.previous_position());
        Some(item)
    }

    fn alias(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        let name = self.name()?;
        self.skip_generics();
        self.skip_unknown_item();
        Some(Item::new(
            ItemKind::TypeAlias,
            name,
            range(start, self.previous_position()),
        ))
    }

    fn constant(&mut self, start: At) -> Option<Item> {
        self.at += 1;
        // `static mut NAME`.
        self.eat_keyword("mut");
        let name = self.name()?;
        self.skip_unknown_item();
        Some(Item::new(
            ItemKind::Constant,
            name,
            range(start, self.previous_position()),
        ))
    }

    /// Records a `use` declaration, including every name a brace group brings in.
    fn import(&mut self) {
        let start = self.position();
        self.at += 1;
        let mut prefix = Vec::new();

        loop {
            match self.peek() {
                None | Some(Token::Punct(';')) => break,
                Some(Token::Open(Delimiter::Brace)) => {
                    // `use a::{b, c::d};` — one import for each name it brings in, so a
                    // reader of the graph sees what was imported rather than a group.
                    let group_start = self.at;
                    self.at += 1;
                    self.import_group(&prefix, start);
                    self.at = group_start;
                    self.skip_group();
                    // The group emitted one import per name it named, so the prefix it
                    // hung from is spent. Leaving it would emit `std::io` as well.
                    prefix.clear();
                }
                Some(Token::Punct(':')) => {
                    self.at += 1;
                }
                Some(Token::Punct('*')) => {
                    self.at += 1;
                    let mut path = prefix.clone();
                    path.push("*".to_owned());
                    self.imports.push(Import {
                        path: path.join("::"),
                        alias: None,
                        range: range(start, self.previous_position()),
                    });
                    prefix.clear();
                }
                Some(token) if token.keyword() == Some("as") => {
                    self.at += 1;
                    let alias = self.name();
                    if !prefix.is_empty() {
                        self.imports.push(Import {
                            path: prefix.join("::"),
                            alias,
                            range: range(start, self.previous_position()),
                        });
                        prefix.clear();
                    }
                }
                Some(Token::Ident { .. }) => {
                    if let Some(name) = self.name() {
                        prefix.push(name);
                    }
                }
                Some(_) => self.at += 1,
            }
        }
        if !prefix.is_empty() {
            self.imports.push(Import {
                path: prefix.join("::"),
                alias: None,
                range: range(start, self.previous_position()),
            });
        }
        self.eat_punct(';');
    }

    /// Records each name inside a `use` brace group, having consumed the opening brace.
    fn import_group(&mut self, prefix: &[String], start: At) {
        let mut segments: Vec<String> = Vec::new();
        let mut depth = 1_usize;

        let flush =
            |segments: &mut Vec<String>, alias: Option<String>, imports: &mut Vec<Import>, end| {
                if segments.is_empty() {
                    return;
                }
                let mut path = prefix.to_vec();
                path.append(segments);
                imports.push(Import {
                    path: path.join("::"),
                    alias,
                    range: range(start, end),
                });
            };

        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::Open(_)) => {
                    depth += 1;
                    self.at += 1;
                }
                Some(Token::Close(_)) => {
                    depth -= 1;
                    self.at += 1;
                    if depth == 0 {
                        let end = self.previous_position();
                        flush(&mut segments, None, &mut self.imports, end);
                    }
                }
                Some(Token::Punct(',')) => {
                    self.at += 1;
                    let end = self.previous_position();
                    flush(&mut segments, None, &mut self.imports, end);
                    segments.clear();
                }
                Some(Token::Punct(':')) => self.at += 1,
                Some(token) if token.keyword() == Some("as") => {
                    self.at += 1;
                    let alias = self.name();
                    let end = self.previous_position();
                    flush(&mut segments, alias, &mut self.imports, end);
                    segments.clear();
                }
                Some(Token::Ident { .. }) => {
                    if let Some(name) = self.name() {
                        segments.push(name);
                    }
                }
                Some(_) => self.at += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(source: &str) -> Vec<Item> {
        analyze(source).items
    }

    fn named(source: &str, kind: ItemKind) -> Vec<String> {
        analyze(source)
            .walk()
            .filter(|item| item.kind == kind)
            .map(|item| item.name.clone())
            .collect()
    }

    fn calls(source: &str) -> Vec<String> {
        analyze(source)
            .walk()
            .flat_map(|item| item.references.iter())
            .map(|reference| match &reference.qualifier {
                Some(qualifier) => format!("{qualifier}::{}", reference.name),
                None => reference.name.clone(),
            })
            .collect()
    }

    #[test]
    fn a_free_function_is_a_function() {
        let found = items("fn main() {}");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ItemKind::Function);
        assert_eq!(found[0].name, "main");
    }

    #[test]
    fn visibility_and_modifiers_do_not_hide_an_item() {
        assert_eq!(
            named(
                "pub async unsafe fn a() {} pub(crate) fn b() {} pub(in crate::x) fn c() {}",
                ItemKind::Function
            ),
            ["a", "b", "c"]
        );
        assert_eq!(named("pub const fn d() {}", ItemKind::Function), ["d"]);
        assert_eq!(
            named("pub extern \"C\" fn e() {}", ItemKind::Function),
            ["e"]
        );
    }

    #[test]
    fn a_const_item_is_not_read_as_a_const_function() {
        assert_eq!(
            named("const LIMIT: u32 = 4;", ItemKind::Constant),
            ["LIMIT"]
        );
        assert_eq!(
            named("static NAME: &str = \"x\";", ItemKind::Constant),
            ["NAME"]
        );
        assert_eq!(
            named("static mut COUNT: u32 = 0;", ItemKind::Constant),
            ["COUNT"]
        );
        assert!(named("const LIMIT: u32 = 4;", ItemKind::Function).is_empty());
    }

    #[test]
    fn attributes_are_stepped_over_including_doc_comments_written_as_attributes() {
        let source = "#![allow(dead_code)]\n#[derive(Debug)]\n#[cfg(test)]\npub fn a() {}";
        assert_eq!(named(source, ItemKind::Function), ["a"]);
    }

    #[test]
    fn a_disabled_cfg_item_is_still_an_item_in_the_file() {
        // Reporting only one configuration's view would make the graph depend on the
        // platform that built it.
        let source = "#[cfg(windows)] fn only_windows() {} #[cfg(unix)] fn only_unix() {}";
        assert_eq!(
            named(source, ItemKind::Function),
            ["only_windows", "only_unix"]
        );
    }

    #[test]
    fn a_module_holds_the_items_declared_inside_it() {
        let found = items("mod inner { fn a() {} struct S; }");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, ItemKind::Module);
        assert_eq!(found[0].name, "inner");
        assert_eq!(found[0].children.len(), 2);
        assert_eq!(named("mod inner { fn a() {} }", ItemKind::Function), ["a"]);
    }

    #[test]
    fn a_module_declared_in_another_file_is_still_a_module() {
        assert_eq!(named("mod other;", ItemKind::Module), ["other"]);
    }

    #[test]
    fn modules_nest() {
        let source = "mod a { mod b { fn deep() {} } }";
        assert_eq!(named(source, ItemKind::Module), ["a", "b"]);
        assert_eq!(named(source, ItemKind::Function), ["deep"]);
    }

    #[test]
    fn a_struct_reports_its_named_fields() {
        let source = "pub struct Point { pub x: f64, y: f64 }";
        assert_eq!(named(source, ItemKind::Struct), ["Point"]);
        assert_eq!(named(source, ItemKind::Field), ["x", "y"]);
    }

    #[test]
    fn a_tuple_struct_and_a_unit_struct_have_no_named_fields() {
        assert_eq!(
            named("struct Wrapper(u32, String);", ItemKind::Struct),
            ["Wrapper"]
        );
        assert!(named("struct Wrapper(u32);", ItemKind::Field).is_empty());
        assert_eq!(named("struct Marker;", ItemKind::Struct), ["Marker"]);
    }

    #[test]
    fn a_comma_inside_a_field_type_does_not_separate_two_fields() {
        // Found by running this analyzer over its own crate. The first version split at
        // every comma, so a generic type ended the field list at its closing bracket and
        // took the rest of the file with it. The earlier test passed by luck: splitting
        // `BTreeMap<String, Vec<u8>>` still happened to leave `b` recognizable.
        let source = "struct S { a: BTreeMap<&'a str, (FieldType, bool)>, b: u32 }";
        assert_eq!(named(source, ItemKind::Field), ["a", "b"]);
        assert_eq!(
            named(
                "struct S { a: BTreeMap<String, Vec<u8>>, b: u32 } fn after() {}",
                ItemKind::Function
            ),
            ["after"],
            "the item after the struct must survive"
        );
        assert_eq!(
            named("struct S { f: fn(u32) -> u32, g: u8 }", ItemKind::Field),
            ["f", "g"],
            "a function-pointer type contributes a `>` that never opened"
        );
    }

    #[test]
    fn an_enum_reports_its_variants_and_their_named_fields() {
        let source = "enum E { Unit, Tuple(u32), Struct { inner: u8 } }";
        assert_eq!(named(source, ItemKind::Enum), ["E"]);
        assert_eq!(
            named(source, ItemKind::Field),
            ["Unit", "Tuple", "Struct", "inner"]
        );
    }

    #[test]
    fn a_trait_holds_methods_rather_than_functions() {
        let source = "trait Reader { fn read(&self) -> u8; fn peek(&self) -> u8 { 0 } }";
        assert_eq!(named(source, ItemKind::Trait), ["Reader"]);
        assert_eq!(named(source, ItemKind::Method), ["read", "peek"]);
        assert!(named(source, ItemKind::Function).is_empty());
    }

    #[test]
    fn a_trait_with_supertraits_and_a_where_clause_still_finds_its_methods() {
        let source = "trait A: B + C where Self: Sized { fn m(&self); }";
        assert_eq!(named(source, ItemKind::Trait), ["A"]);
        assert_eq!(named(source, ItemKind::Method), ["m"]);
    }

    #[test]
    fn an_inherent_impl_names_the_type_it_is_for() {
        let found = items("impl Parser { fn new() -> Self { Self } }");
        assert_eq!(found[0].kind, ItemKind::Implementation);
        assert_eq!(found[0].name, "Parser");
        assert_eq!(found[0].target.as_deref(), Some("Parser"));
        assert_eq!(found[0].implements, None);
        assert_eq!(
            named("impl Parser { fn new() {} }", ItemKind::Method),
            ["new"]
        );
    }

    #[test]
    fn a_trait_impl_records_both_sides() {
        let found = items("impl fmt::Display for Parser { fn fmt(&self) {} }");
        assert_eq!(found[0].target.as_deref(), Some("Parser"));
        assert_eq!(
            found[0].implements.as_deref(),
            Some("Display"),
            "the trait is reported by name, not by its full path spelling"
        );
    }

    #[test]
    fn a_generic_impl_with_lifetimes_and_bounds_still_names_its_type() {
        let found = items(
            "impl<'a, T: Clone> Iterator for Cursor<'a, T> where T: Send { fn next(&mut self) {} }",
        );
        assert_eq!(found[0].target.as_deref(), Some("Cursor"));
        assert_eq!(found[0].implements.as_deref(), Some("Iterator"));
        assert_eq!(
            named(
                "impl<'a, T: Clone> Iterator for Cursor<'a, T> where T: Send { fn next(&mut self) {} }",
                ItemKind::Method
            ),
            ["next"]
        );
    }

    #[test]
    fn a_type_alias_is_an_item_and_does_not_consume_what_follows() {
        let source = "type Pair = (u32, u32); fn after() {}";
        assert_eq!(named(source, ItemKind::TypeAlias), ["Pair"]);
        assert_eq!(named(source, ItemKind::Function), ["after"]);
    }

    #[test]
    fn a_call_is_recorded_as_a_name_and_never_as_a_target() {
        // The whole precision claim in one test: this analyzer says a name was called, not
        // which definition was called.
        assert_eq!(calls("fn a() { helper(); }"), ["helper"]);
        assert_eq!(calls("fn a() { module::helper(); }"), ["module::helper"]);
        assert_eq!(calls("fn a() { self.method(); }"), ["method"]);
    }

    #[test]
    fn a_method_call_is_marked_as_one() {
        let found = analyze("fn a() { value.parse(); }");
        let reference = &found.items[0].references[0];
        assert_eq!(reference.name, "parse");
        assert!(reference.is_method);

        let plain = analyze("fn a() { parse(); }");
        assert!(!plain.items[0].references[0].is_method);
    }

    #[test]
    fn a_turbofish_belongs_to_the_name_rather_than_hiding_it() {
        assert_eq!(calls("fn a() { collect::<Vec<u8>>(); }"), ["collect"]);
        assert_eq!(
            calls("fn a() { Vec::<u8>::with_capacity(4); }"),
            ["Vec::with_capacity"]
        );
    }

    #[test]
    fn a_macro_invocation_is_not_a_call_to_a_function_of_that_name() {
        assert!(
            calls("fn a() { println!(\"x\"); }").is_empty(),
            "a macro is not a function"
        );
        assert_eq!(calls("fn a() { println!(\"x\"); helper(); }"), ["helper"]);
    }

    #[test]
    fn a_macro_at_item_position_does_not_invent_items() {
        // `macro_rules!` can put anything inside a balanced group, including text that is
        // not Rust. Guessing is how a skim parser starts reporting items that do not exist.
        let source = "macro_rules! define { ($n:ident) => { fn $n() {} } }\nfn real() {}";
        assert_eq!(named(source, ItemKind::Function), ["real"]);
    }

    #[test]
    fn a_use_declaration_records_each_name_it_brings_in() {
        let found = analyze("use std::collections::BTreeMap;");
        assert_eq!(found.imports.len(), 1);
        assert_eq!(found.imports[0].path, "std::collections::BTreeMap");
        assert_eq!(found.imports[0].alias, None);
    }

    #[test]
    fn a_use_group_becomes_one_import_per_name() {
        let found = analyze("use std::io::{Read, Write};");
        let paths: Vec<&str> = found.imports.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, ["std::io::Read", "std::io::Write"]);
    }

    #[test]
    fn a_renamed_import_keeps_both_names() {
        let found = analyze("use std::fmt::Result as FmtResult;");
        assert_eq!(found.imports[0].path, "std::fmt::Result");
        assert_eq!(found.imports[0].alias.as_deref(), Some("FmtResult"));
    }

    #[test]
    fn a_glob_import_is_recorded_as_one() {
        let found = analyze("use super::*;");
        assert_eq!(found.imports[0].path, "super::*");
    }

    #[test]
    fn source_ranges_point_at_the_declaration() {
        let found = analyze("fn first() {}\n\nfn second() {}\n");
        assert_eq!(found.items[0].range.start().line, 1);
        assert_eq!(found.items[1].range.start().line, 3);
        assert_eq!(found.items[1].range.start().column, 1);
    }

    #[test]
    fn a_syntax_error_costs_the_items_around_it_nothing() {
        // A structural analyzer runs over files somebody is still editing. Refusing to
        // report anything for one bad line would make the common case the failing case.
        let source = "fn good() {}\nfn broken( {\nfn also_good() {}\n";
        let names = named(source, ItemKind::Function);
        assert!(names.contains(&"good".to_owned()), "{names:?}");
    }

    #[test]
    fn an_unknown_construct_is_stepped_over_rather_than_derailing_the_walk() {
        let source = "frobnicate Thing { whatever }\nfn after() {}";
        assert_eq!(named(source, ItemKind::Function), ["after"]);
    }

    #[test]
    fn an_empty_file_yields_nothing_and_still_carries_a_digest() {
        let found = analyze("");
        assert!(found.items.is_empty());
        assert!(found.imports.is_empty());
        assert_eq!(found.digest, crate::sync::digest_bytes(b""));
        assert_eq!(found.language, "rust");
    }

    #[test]
    fn the_digest_follows_the_source() {
        assert_ne!(analyze("fn a() {}").digest, analyze("fn b() {}").digest);
        assert_eq!(analyze("fn a() {}").digest, analyze("fn a() {}").digest);
    }

    #[test]
    fn the_declared_capability_matches_what_this_analyzer_does() {
        let declared = capability();
        assert_eq!(declared.language.as_str(), "rust");
        assert_eq!(
            declared.precision,
            crate::analysis::PrecisionClass::DeterministicSyntactic,
            "resolving nothing across files is exactly what syntactic means"
        );
        assert!(declared.extracts(FactKind::Call));
        assert!(declared.extracts(FactKind::Method));
        assert!(
            !declared.extracts(FactKind::Inheritance),
            "Rust has no inheritance, so claiming to extract it would be false"
        );
        assert!(
            !declared.extracts(FactKind::EntryPoint),
            "entry points come from configuration this analyzer does not read"
        );
    }

    #[test]
    fn a_realistic_file_yields_every_kind_of_item() {
        let source = r#"
//! A module doc comment.
use std::collections::BTreeMap;
use std::fmt::{self, Display};

pub const LIMIT: usize = 8;

/// A parser.
#[derive(Debug, Default)]
pub struct Parser<'a> {
    source: &'a str,
    at: usize,
}

pub enum Mode { Fast, Careful { retries: u8 } }

pub trait Read {
    fn read(&mut self) -> Option<u8>;
}

impl<'a> Parser<'a> {
    pub fn new(source: &'a str) -> Self {
        Self { source, at: 0 }
    }

    fn advance(&mut self) {
        self.at = self.at.saturating_add(1);
        helper(self.at);
    }
}

impl<'a> Display for Parser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

fn helper(at: usize) -> usize { at }

mod inner {
    pub fn nested() {}
}
"#;
        let found = analyze(source);
        assert_eq!(found.count(ItemKind::Struct), 1);
        assert_eq!(found.count(ItemKind::Enum), 1);
        assert_eq!(found.count(ItemKind::Trait), 1);
        assert_eq!(found.count(ItemKind::Implementation), 2);
        assert_eq!(found.count(ItemKind::Constant), 1);
        assert_eq!(found.count(ItemKind::Module), 1);
        assert_eq!(
            named(source, ItemKind::Method),
            ["read", "new", "advance", "fmt"]
        );
        assert_eq!(named(source, ItemKind::Function), ["helper", "nested"]);
        assert_eq!(found.imports.len(), 3);
        assert!(
            calls(source).contains(&"helper".to_owned()),
            "{:?}",
            calls(source)
        );
    }
}
