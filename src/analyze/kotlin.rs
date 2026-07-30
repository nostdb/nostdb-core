//! Reads Kotlin structure deterministically.
//!
//! # What "syntactic" means here, and what it therefore cannot claim
//!
//! This analyzer declares [`PrecisionClass::DeterministicSyntactic`], the same class the Rust analyzer
//! declares, and the limits are the point of the declaration rather than an apology for it. It reads
//! declarations and the names they mention. It does not resolve types, so it cannot know which
//! `process` a call named `process` reaches, and it does not read platform or dependency source, so a
//! name declared outside the project is a name it will not match.
//!
//! Resolution is [`crate::build`]'s job and it is deliberately conservative: a name two records share
//! stays unresolved rather than being guessed. That is why this analyzer reports what a reference was
//! *written as* — its final segment, its qualifier, and whether it was a call on a receiver — and
//! leaves the matching to something that can see the whole build.
//!
//! # Kotlin declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `package a.b` | the file's package, on the file and on no qualified name |
//! | `import a.b.C`, `import a.b.C as D` | an import, with its alias |
//! | `class`, `data class`, `sealed class`, `value class` | [`ItemKind::Struct`] |
//! | `interface`, `fun interface` | [`ItemKind::Trait`] |
//! | `object`, `companion object` | [`ItemKind::Struct`] |
//! | `enum class` | [`ItemKind::Enum`] |
//! | `annotation class` | [`ItemKind::Struct`] |
//! | `typealias` | [`ItemKind::TypeAlias`] |
//! | `fun` at file scope | [`ItemKind::Function`] |
//! | `fun` inside a type | [`ItemKind::Method`] |
//! | `val`/`var` at file scope | [`ItemKind::Constant`] |
//! | `val`/`var` inside a type | [`ItemKind::Field`] |
//! | `val`/`var` in a primary constructor | [`ItemKind::Field`] |
//! | `constructor(...)` | [`ItemKind::Method`] named `constructor` |
//!
//! A `val` inside a function body is **not** recorded. A local is not a declaration anything outside
//! the function can refer to, and recording every one would bury the structure that is queryable in
//! the structure that is not.
//!
//! `:` after a class name introduces a supertype list, and Kotlin does not distinguish a class from an
//! interface there. `implements` is therefore left empty and every supertype is reported as a
//! reference: claiming a supertype was an interface would be a claim this analyzer cannot check.

use super::kotlin_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{Annotation, FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads.
pub const LANGUAGE: &str = "kotlin";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// The name Kotlin gives an unnamed companion object.
const COMPANION: &str = "Companion";

/// What this analyzer declares.
///
/// `FactKind::Call` is declared and `InterfaceImplementation` is **not**. A supertype list does not
/// say which entries are interfaces, so declaring the fact would advertise coverage this cannot have.
#[must_use]
pub fn capability() -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(LANGUAGE).unwrap_or_else(|_| NonEmptyText::literal("kotlin")),
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
            FactKind::SourceRange,
            FactKind::ContentHash,
        ],
    }
}

/// Analyzes one Kotlin file.
///
/// Never fails. Source that does not parse yields whatever structure was readable before the
/// confusion, because a structural analyzer runs over files somebody is still editing and refusing to
/// report anything for one syntax error would make the common case the failing case.
#[must_use]
pub fn analyze(source: &str) -> FileAnalysis {
    let tokens = tokenize(source);
    let mut reader = Reader {
        tokens: &tokens,
        at: 0,
        package: None,
        imports: Vec::new(),
    };
    let items = reader.declarations(None);
    FileAnalysis {
        language: LANGUAGE.to_owned(),
        digest: crate::sync::digest_bytes(source.as_bytes()),
        package: reader.package,
        items,
        imports: reader.imports,
    }
}

/// Keywords that may precede a declaration and are not part of it.
///
/// Listed rather than skipped by shape, because a modifier and a declaration keyword are both plain
/// identifiers to the lexer. `data` is in here and so is `value`: `data class C` declares `C`, and a
/// reader that stopped at `data` would name the class `class`.
const MODIFIERS: [&str; 27] = [
    "abstract",
    "actual",
    "annotation",
    "companion",
    "const",
    "crossinline",
    "data",
    "enum",
    "expect",
    "external",
    "final",
    "infix",
    "inline",
    "inner",
    "internal",
    "lateinit",
    "noinline",
    "open",
    "operator",
    "override",
    "private",
    "protected",
    "public",
    "sealed",
    "suspend",
    "tailrec",
    "value",
];

struct Reader<'a> {
    tokens: &'a [Spanned],
    at: usize,
    package: Option<String>,
    imports: Vec<Import>,
}

impl Reader<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at).map(|held| &held.token)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Token> {
        self.tokens.get(self.at + ahead).map(|held| &held.token)
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
    ///
    /// `container` is the kind of type this is inside, which is what makes a `fun` a method rather
    /// than a function and a `val` a field rather than a constant. `None` is file scope.
    fn declarations(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        let mut items = Vec::new();
        while self.at < self.tokens.len() {
            if matches!(self.peek(), Some(Token::Close(Delimiter::Brace))) {
                self.advance();
                return items;
            }
            // Annotations sit before a declaration and are not one, so they are collected and carried
            // onto whatever declaration follows. Discarded, they took every framework fact with them.
            //
            // Kotlin allows a use-site target, `@get:JvmName("x")`, and a modifier may sit between an
            // annotation and its declaration — so this loop gathers annotations and modifiers together
            // until a declaration keyword arrives.
            let mut annotations = Vec::new();
            loop {
                if self.peek().is_some_and(|token| token.is_punct('@')) {
                    if let Some(found) = self.annotation() {
                        annotations.push(found);
                    }
                    continue;
                }
                break;
            }
            let modifiers = self.modifiers();
            // A second run, because `private @Inject val x` is legal and so is `@Inject private val x`.
            while self.peek().is_some_and(|token| token.is_punct('@')) {
                if let Some(found) = self.annotation() {
                    annotations.push(found);
                }
            }
            match self.peek().and_then(Token::keyword) {
                Some("package") => {
                    // The package a file joins, not a declaration in it — so it is recorded on the file
                    // and never on an item. Kept rather than dropped because an import names a
                    // declaration, and a Kotlin file name is not required to agree with anything declared
                    // in it, so this is the only thing an import can honestly be matched against.
                    //
                    // Read whatever follows even when a package was already seen. A second `package` line
                    // does not compile, and the first is the one that means anything.
                    self.advance();
                    let found = self.qualified_name();
                    if self.package.is_none() && !found.is_empty() {
                        self.package = Some(found);
                    }
                }
                Some("import") => self.import(),
                Some("class") | Some("interface") => {
                    if let Some(mut item) = self.type_declaration(&modifiers) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("object") => {
                    if let Some(mut item) = self.object_declaration(&modifiers) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("typealias") => {
                    if let Some(mut item) = self.type_alias() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("fun") => {
                    // `fun interface Handler` declares an interface. Read as a function it would
                    // declare something named `interface`, and every functional interface in a
                    // project would collide on that one name.
                    if self.peek_at(1).and_then(Token::keyword) == Some("interface") {
                        self.advance();
                        if let Some(mut item) = self.type_declaration(&modifiers) {
                            item.annotations = annotations;
                            items.push(item);
                        }
                    } else if let Some(mut item) = self.function(container) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("val") | Some("var") => {
                    if let Some(mut item) = self.property(container) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                Some("constructor") => {
                    if let Some(mut item) = self.secondary_constructor() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                // Anything else at this level is not a declaration. Advancing one token keeps the
                // reader moving over an expression, a stray brace, or source mid-edit.
                _ => {
                    self.advance();
                }
            }
        }
        items
    }

    /// Consumes any modifiers before a declaration and reports which were seen.
    fn modifiers(&mut self) -> Vec<String> {
        let mut seen = Vec::new();
        while let Some(word) = self.peek().and_then(Token::keyword) {
            // `enum` and `annotation` and `companion` are modifiers only when a declaration follows.
            // `enum class` is one; a bare `enum` used as a name is not.
            if !MODIFIERS.contains(&word) {
                return seen;
            }
            seen.push(word.to_owned());
            self.advance();
        }
        seen
    }

    /// One annotation, with its arguments exactly as written.
    ///
    /// A use-site target — `@get:JvmName(...)` — is consumed and the annotation's own name is what is
    /// recorded. A qualified name keeps only its last segment, because `@org.springframework.\
    /// web.bind.annotation.GetMapping` and `@GetMapping` are the same annotation and a framework
    /// analyzer should not have to know which spelling a file used.
    fn annotation(&mut self) -> Option<Annotation> {
        let start = self.position();
        self.advance();
        let mut name = self.advance().and_then(Token::name)?.to_owned();
        // A use-site target, which is a keyword followed by `:` before the real name.
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            name = self.advance().and_then(Token::name)?.to_owned();
        }
        while self.peek().is_some_and(|token| token.is_punct('.')) {
            self.advance();
            name = self.advance().and_then(Token::name)?.to_owned();
        }
        let arguments = match self.peek() {
            Some(Token::Open(Delimiter::Paren)) => Some(self.argument_text()),
            _ => None,
        };
        Some(Annotation {
            name,
            arguments,
            range: range(start, self.previous_position()),
        })
    }

    /// The text between a balanced pair of parentheses, reconstructed from the tokens inside it.
    ///
    /// Reconstructed rather than sliced out of the source, because this reader holds tokens and not the
    /// text. What that costs is exact spacing, and what it keeps is every name, string, and number in
    /// order — which is what a framework analyzer reads. A string literal is the one thing it cannot
    /// return, because the lexer reduces a literal to the fact that one was here; that is why
    /// `argument_strings` below exists and takes them from the source instead.
    fn argument_text(&mut self) -> String {
        let mut parts: Vec<String> = Vec::new();
        self.advance();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::Open(Delimiter::Paren)) => {
                    depth += 1;
                    parts.push("(".to_owned());
                    self.advance();
                }
                Some(Token::Close(Delimiter::Paren)) => {
                    depth -= 1;
                    if depth > 0 {
                        parts.push(")".to_owned());
                    }
                    self.advance();
                }
                Some(token) => {
                    parts.push(match token {
                        Token::Ident { name, .. } => name.clone(),
                        // Quoted, so a framework analyzer can tell a string from a name. `@GetMapping("/x")`
                        // and a hypothetical `@GetMapping(x)` are different arguments, and unquoting both
                        // to `/x` and `x` would lose which was which.
                        Token::Text(content) => format!("\"{content}\""),
                        Token::Literal => "<literal>".to_owned(),
                        Token::Open(delimiter) => delimiter.to_string()[..1].to_owned(),
                        Token::Close(delimiter) => delimiter.to_string()[1..].to_owned(),
                        Token::Punct(character) => character.to_string(),
                    });
                    self.advance();
                }
            }
        }
        parts.join(" ")
    }

    fn import(&mut self) {
        let start = self.position();
        self.advance();
        let path = self.qualified_name();
        let alias = match self.peek().and_then(Token::keyword) {
            Some("as") => {
                self.advance();
                self.advance().and_then(Token::name).map(str::to_owned)
            }
            _ => None,
        };
        if let Some(path) = NonEmptyText::new(path.as_str()).ok().map(|_| path) {
            self.imports.push(Import {
                path,
                alias,
                range: range(start, self.previous_position()),
            });
        }
    }

    /// A dotted name, including a trailing `.*`.
    fn qualified_name(&mut self) -> String {
        let mut segments = Vec::new();
        loop {
            match self.peek() {
                Some(token) if token.name().is_some() => {
                    if let Some(name) = token.name() {
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

    /// `class`, `data class`, `enum class`, `annotation class`, `interface`, `fun interface`.
    fn type_declaration(&mut self, modifiers: &[String]) -> Option<Item> {
        let start = self.position();
        let keyword = self.advance().and_then(Token::keyword)?.to_owned();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let kind = match keyword.as_str() {
            "interface" => ItemKind::Trait,
            _ if modifiers.iter().any(|held| held == "enum") => ItemKind::Enum,
            _ => ItemKind::Struct,
        };

        // Type parameters, then the primary constructor, then supertypes.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Bracket))) {
            self.skip_balanced(Delimiter::Bracket);
        }
        self.skip_type_parameters();
        let mut children = Vec::new();
        let mut references = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            children.extend(self.primary_constructor());
        }
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            references.extend(self.supertypes());
        }
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.advance();
            children.extend(self.declarations(Some(kind)));
        }
        Some(Item {
            kind,
            name,
            range: range(start, self.previous_position()),
            target: None,
            // A supertype list does not distinguish a class from an interface, so nothing here may
            // claim one. Every supertype is a reference instead.
            implements: None,
            references,
            annotations: Vec::new(),
            children,
        })
    }

    /// `object X`, `companion object`, `companion object X`.
    fn object_declaration(&mut self, modifiers: &[String]) -> Option<Item> {
        let start = self.position();
        self.advance();
        let companion = modifiers.iter().any(|held| held == "companion");
        let name = match self.peek().and_then(Token::name) {
            Some(name) => {
                let name = name.to_owned();
                self.advance();
                name
            }
            // `companion object` with no name is `Companion`, which is what Kotlin calls it and what a
            // reference to it is written as.
            None if companion => COMPANION.to_owned(),
            // An object expression, `object : Runnable { }`, declares nothing named.
            None => {
                self.skip_to_body_and_past_it();
                return None;
            }
        };
        let mut references = Vec::new();
        if self.peek().is_some_and(|token| token.is_punct(':')) {
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

    fn type_alias(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        self.skip_type_parameters();
        let mut references = Vec::new();
        if self.peek().is_some_and(|token| token.is_punct('=')) {
            self.advance();
            if let Some(reference) = self.type_reference() {
                references.push(reference);
            }
        }
        Some(Item {
            kind: ItemKind::TypeAlias,
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    /// A function. `container` decides whether it is a function or a method.
    fn function(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        self.advance();
        self.skip_type_parameters();
        let mut name = self.advance().and_then(Token::name)?.to_owned();
        // An extension function: `fun Receiver.name()`. The name is the last segment and the receiver
        // is a reference to a type this file does not declare.
        let mut references = Vec::new();
        while self.peek().is_some_and(|token| token.is_punct('.')) {
            self.advance();
            references.push(Reference {
                name: name.clone(),
                qualifier: None,
                is_method: false,
                range: range(start, self.previous_position()),
            });
            name = self.advance().and_then(Token::name)?.to_owned();
        }
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            references.extend(self.parameter_types());
        }
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            if let Some(reference) = self.type_reference() {
                references.push(reference);
            }
        }
        // A body is either a block or `= expression`. Both may contain calls; neither may contain a
        // declaration this analyzer records.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            references.extend(self.body_calls());
        } else if self.peek().is_some_and(|token| token.is_punct('=')) {
            self.advance();
            references.extend(self.expression_calls());
        }
        Some(Item {
            kind: match container {
                Some(_) => ItemKind::Method,
                None => ItemKind::Function,
            },
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    /// A `val` or `var` at file scope or in a type body.
    fn property(&mut self, container: Option<ItemKind>) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let mut references = Vec::new();
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            if let Some(reference) = self.type_reference() {
                references.push(reference);
            }
        }
        if self.peek().is_some_and(|token| token.is_punct('=')) {
            self.advance();
            references.extend(self.expression_calls());
        }
        // A getter or setter body.
        while matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            references.extend(self.body_calls());
        }
        Some(Item {
            kind: match container {
                Some(_) => ItemKind::Field,
                None => ItemKind::Constant,
            },
            name,
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    fn secondary_constructor(&mut self) -> Option<Item> {
        let start = self.position();
        self.advance();
        let mut references = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            references.extend(self.parameter_types());
        }
        // `: this(...)` or `: super(...)` before the body.
        if self.peek().is_some_and(|token| token.is_punct(':')) {
            self.advance();
            self.advance();
            if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                self.skip_balanced(Delimiter::Paren);
            }
        }
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            references.extend(self.body_calls());
        }
        Some(Item {
            kind: ItemKind::Method,
            name: "constructor".to_owned(),
            range: range(start, self.previous_position()),
            target: None,
            implements: None,
            references,
            annotations: Vec::new(),
            children: Vec::new(),
        })
    }

    /// The `val`/`var` parameters of a primary constructor, which are properties.
    ///
    /// A parameter written without `val` or `var` is a constructor argument and not a property, so it
    /// is not recorded. `class Server(val port: Int, timeout: Long)` declares one property.
    fn primary_constructor(&mut self) -> Vec<Item> {
        let mut properties = Vec::new();
        self.advance();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::Open(Delimiter::Paren)) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::Close(Delimiter::Paren)) => {
                    depth -= 1;
                    self.advance();
                }
                Some(token) if depth == 1 && matches!(token.keyword(), Some("val" | "var")) => {
                    let start = self.position();
                    self.advance();
                    if let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) {
                        self.advance();
                        let mut references = Vec::new();
                        if self.peek().is_some_and(|token| token.is_punct(':')) {
                            self.advance();
                            if let Some(reference) = self.type_reference() {
                                references.push(reference);
                            }
                        }
                        properties.push(Item {
                            kind: ItemKind::Field,
                            name,
                            range: range(start, self.previous_position()),
                            target: None,
                            implements: None,
                            references,
                            annotations: Vec::new(),
                            children: Vec::new(),
                        });
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
        properties
    }

    /// Every type named in a parameter list, and every call in a default value.
    fn parameter_types(&mut self) -> Vec<Reference> {
        let mut references = Vec::new();
        self.advance();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::Open(Delimiter::Paren)) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::Close(Delimiter::Paren)) => {
                    depth -= 1;
                    self.advance();
                }
                Some(token) if token.is_punct(':') => {
                    self.advance();
                    if let Some(reference) = self.type_reference() {
                        references.push(reference);
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
        references
    }

    /// The supertype list after `:`, as references.
    fn supertypes(&mut self) -> Vec<Reference> {
        let mut references = Vec::new();
        while let Some(reference) = self.type_reference() {
            references.push(reference);
            // A supertype may be constructed: `: Base(port)`.
            if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                self.skip_balanced(Delimiter::Paren);
            }
            // `by` delegation names the delegate expression, which is not a supertype.
            if self.peek().and_then(Token::keyword) == Some("by") {
                self.advance();
                self.advance();
                if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                    self.skip_balanced(Delimiter::Paren);
                }
            }
            if self.peek().is_some_and(|token| token.is_punct(',')) {
                self.advance();
                continue;
            }
            break;
        }
        references
    }

    /// One type, as a reference. Generic arguments and nullability are consumed.
    fn type_reference(&mut self) -> Option<Reference> {
        let start = self.position();
        let mut segments = Vec::new();
        while let Some(name) = self.peek().and_then(Token::name) {
            segments.push(name.to_owned());
            self.advance();
            if self.peek().is_some_and(|token| token.is_punct('.')) {
                self.advance();
                continue;
            }
            break;
        }
        if segments.is_empty() {
            return None;
        }
        self.skip_type_parameters();
        while self.peek().is_some_and(|token| token.is_punct('?')) {
            self.advance();
        }
        let name = segments.pop()?;
        let qualifier = (!segments.is_empty()).then(|| segments.join("."));
        Some(Reference {
            name,
            qualifier,
            is_method: false,
            range: range(start, self.previous_position()),
        })
    }

    /// Calls inside a brace-delimited body.
    fn body_calls(&mut self) -> Vec<Reference> {
        let mut references = Vec::new();
        self.advance();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.peek() {
                None => break,
                Some(Token::Open(Delimiter::Brace)) => {
                    depth += 1;
                    self.advance();
                }
                Some(Token::Close(Delimiter::Brace)) => {
                    depth -= 1;
                    self.advance();
                }
                _ => {
                    if let Some(reference) = self.call() {
                        references.push(reference);
                    } else {
                        self.advance();
                    }
                }
            }
        }
        references
    }

    /// Calls in an expression body, which ends at a newline this lexer does not report.
    ///
    /// Bounded by the next declaration keyword instead. Kotlin has no statement terminator, so an
    /// expression body's end is not visible in the token stream — reading to the next `fun`, `val`, or
    /// closing brace is what keeps this from consuming the rest of the type.
    fn expression_calls(&mut self) -> Vec<Reference> {
        let mut references = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(Token::Close(Delimiter::Brace)) => break,
                // An annotation begins the next declaration, so it ends this expression body. Without
                // this, `fun a() = 1` followed by `@Test fun b()` swallowed the `@Test` — the
                // annotation was consumed as part of the previous expression and vanished.
                Some(token) if token.is_punct('@') => break,
                Some(token)
                    if matches!(
                        token.keyword(),
                        Some(
                            "fun"
                                | "val"
                                | "var"
                                | "class"
                                | "interface"
                                | "object"
                                | "typealias"
                                | "constructor"
                        )
                    ) =>
                {
                    break;
                }
                Some(Token::Open(Delimiter::Brace)) => {
                    references.extend(self.body_calls());
                }
                _ => {
                    if let Some(reference) = self.call() {
                        references.push(reference);
                    } else {
                        self.advance();
                    }
                }
            }
        }
        references
    }

    /// A name immediately followed by `(`, which is a call at syntactic precision.
    ///
    /// It cannot tell a call from a constructor invocation, because Kotlin writes them the same way
    /// and telling them apart needs the declaration. Both are references to a name, which is what is
    /// reported.
    fn call(&mut self) -> Option<Reference> {
        let start = self.position();
        let mut segments = Vec::new();
        let mut is_method = false;
        let mut at = self.at;
        loop {
            let name = self.tokens.get(at).map(|held| &held.token)?.name()?;
            segments.push(name.to_owned());
            at += 1;
            let next = self.tokens.get(at).map(|held| &held.token);
            match next {
                Some(token) if token.is_punct('.') => {
                    is_method = true;
                    at += 1;
                }
                Some(token) if token.is_punct('?') => {
                    // A safe call, `a?.b()`, is a call on a receiver.
                    at += 1;
                    if self
                        .tokens
                        .get(at)
                        .map(|held| &held.token)
                        .is_some_and(|token| token.is_punct('.'))
                    {
                        is_method = true;
                        at += 1;
                        continue;
                    }
                    return None;
                }
                _ => break,
            }
        }
        if !matches!(
            self.tokens.get(at).map(|held| &held.token),
            Some(Token::Open(Delimiter::Paren))
        ) {
            return None;
        }
        self.at = at;
        self.skip_balanced(Delimiter::Paren);
        let name = segments.pop()?;
        let qualifier = (!segments.is_empty()).then(|| segments.join("."));
        Some(Reference {
            name,
            qualifier,
            is_method,
            range: range(start, self.previous_position()),
        })
    }

    /// `<...>` type parameters, which the lexer reports as punctuation.
    ///
    /// Angle-bracket depth is counted so `Map<String, List<Int>>` is consumed whole. `>>` is two
    /// tokens here, because the lexer emits punctuation one character at a time.
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
                // A `{` inside what looked like type parameters means it was a comparison, not a
                // parameter list. Stopping beats consuming a body.
                return;
            }
            self.advance();
        }
    }

    /// Consumes a balanced group starting at its opening delimiter.
    fn skip_balanced(&mut self, delimiter: Delimiter) {
        if !matches!(self.peek(), Some(Token::Open(found)) if *found == delimiter) {
            return;
        }
        self.advance();
        let mut depth = 1_u32;
        while depth > 0 {
            match self.advance() {
                None => return,
                Some(Token::Open(found)) if *found == delimiter => depth += 1,
                Some(Token::Close(found)) if *found == delimiter => depth -= 1,
                _ => {}
            }
        }
    }

    /// Skips to the next `{` and past its matching `}`, for a construct that declares nothing.
    fn skip_to_body_and_past_it(&mut self) {
        while let Some(token) = self.peek() {
            if matches!(token, Token::Open(Delimiter::Brace)) {
                self.skip_balanced(Delimiter::Brace);
                return;
            }
            if matches!(token, Token::Close(Delimiter::Brace)) {
                return;
            }
            self.advance();
        }
    }
}

/// A range from two positions, falling back rather than panicking.
///
/// A reader that ran past the end takes its end position from the last token, which can put the end
/// before the start. `ORIGIN` exists for exactly this: a structural analyzer over source somebody is
/// editing must not panic on a position it computed itself.
fn range(start: SourcePosition, end: SourcePosition) -> SourceRange {
    SourceRange::new(start, end)
        .or_else(|_| SourceRange::new(start, start))
        .unwrap_or(SourceRange::ORIGIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(source: &str) -> Vec<Item> {
        analyze(source).items
    }

    fn named(items: &[Item], kind: ItemKind) -> Vec<&str> {
        items
            .iter()
            .filter(|item| item.kind == kind)
            .map(|item| item.name.as_str())
            .collect()
    }

    /// Every item at every depth, as `kind:name`.
    fn flat(source: &str) -> Vec<String> {
        fn walk(items: &[Item], into: &mut Vec<String>) {
            for item in items {
                into.push(format!("{:?}:{}", item.kind, item.name));
                walk(&item.children, into);
            }
        }
        let mut found = Vec::new();
        walk(&items(source), &mut found);
        found
    }

    fn calls(source: &str) -> Vec<String> {
        fn walk(items: &[Item], into: &mut Vec<String>) {
            for item in items {
                for reference in &item.references {
                    into.push(match &reference.qualifier {
                        Some(qualifier) => format!("{qualifier}.{}", reference.name),
                        None => reference.name.clone(),
                    });
                }
                walk(&item.children, into);
            }
        }
        let mut found = Vec::new();
        walk(&items(source), &mut found);
        found
    }

    #[test]
    fn a_class_and_its_members_are_read() {
        let source = "\
package demo

class Server(val port: Int, timeout: Long) {
    val name: String = \"s\"
    fun start() {}
    private fun stop() {}
}
";
        assert_eq!(
            flat(source),
            [
                "Struct:Server",
                // A primary-constructor `val` is a property; a bare parameter is not.
                "Field:port",
                "Field:name",
                "Method:start",
                "Method:stop",
            ]
        );
    }

    #[test]
    fn a_modifier_is_not_mistaken_for_the_name() {
        // `data class C` declares `C`. A reader that stopped at the first keyword would name it
        // `class`, and every `data class` in a project would collide on one name.
        assert_eq!(
            named(&items("data class Point(val x: Int)"), ItemKind::Struct),
            ["Point"]
        );
        assert_eq!(
            named(&items("sealed class Shape"), ItemKind::Struct),
            ["Shape"]
        );
        assert_eq!(
            named(&items("value class Id(val v: Long)"), ItemKind::Struct),
            ["Id"]
        );
        assert_eq!(
            named(&items("annotation class Marker"), ItemKind::Struct),
            ["Marker"]
        );
        assert_eq!(
            named(&items("enum class Colour { RED }"), ItemKind::Enum),
            ["Colour"]
        );
        assert_eq!(
            named(&items("fun interface Handler"), ItemKind::Trait),
            ["Handler"]
        );
    }

    #[test]
    fn a_file_level_function_is_a_function_and_a_member_is_a_method() {
        assert_eq!(named(&items("fun main() {}"), ItemKind::Function), ["main"]);
        assert_eq!(
            flat("class A { fun m() {} }"),
            ["Struct:A", "Method:m"],
            "the same keyword inside a type is a method"
        );
    }

    #[test]
    fn a_file_level_property_is_a_constant_and_a_member_is_a_field() {
        assert_eq!(
            named(&items("val version = 1"), ItemKind::Constant),
            ["version"]
        );
        assert_eq!(
            flat("class A { var count = 0 }"),
            ["Struct:A", "Field:count"]
        );
    }

    #[test]
    fn a_local_inside_a_function_is_not_a_declaration() {
        // A local is not something anything outside the function can refer to, and recording every
        // one would bury the queryable structure in structure that is not.
        assert_eq!(flat("fun f() { val local = 1 }"), ["Function:f"]);
    }

    #[test]
    fn an_object_is_read_and_a_companion_takes_the_name_kotlin_gives_it() {
        assert_eq!(
            flat("object Registry { fun get() {} }"),
            ["Struct:Registry", "Method:get"]
        );
        assert_eq!(
            flat("class A { companion object { fun of() {} } }"),
            ["Struct:A", "Struct:Companion", "Method:of"]
        );
        assert_eq!(
            flat("class A { companion object Factory { } }"),
            ["Struct:A", "Struct:Factory"]
        );
    }

    #[test]
    fn an_object_expression_declares_nothing_and_does_not_swallow_what_follows() {
        let source = "\
fun f() {
    val r = object : Runnable { override fun run() {} }
}
class Kept
";
        assert_eq!(flat(source), ["Function:f", "Struct:Kept"]);
    }

    #[test]
    fn the_package_is_recorded_on_the_file_and_is_not_a_declaration() {
        // The module documentation used to claim this went onto every qualified name below it, and it never
        // did. It goes on the file, and `Payload` stays `Payload`: a qualified name is an identity, and
        // moving a package into one would retire and re-mint every record in every existing database.
        //
        // It is held at all because a Kotlin file name is free — this declaration is in `Models.kt` as far
        // as anything here knows — so the package is the only thing an import can be resolved against.
        let found = analyze("package com.demo.app.data\n\nclass Payload\n");
        assert_eq!(found.package.as_deref(), Some("com.demo.app.data"));
        assert_eq!(
            flat("package com.demo.app.data\n\nclass Payload\n"),
            ["Struct:Payload"]
        );
    }

    #[test]
    fn a_file_in_the_default_package_says_absent_rather_than_empty() {
        // Kotlin's default package is written by writing nothing, and absent is what the resolver reads to
        // fall back to matching paths. An empty string would claim a package named "".
        assert_eq!(analyze("class Payload\n").package, None);
    }

    #[test]
    fn an_import_is_recorded_with_its_alias() {
        let analysis = analyze("import a.b.C\nimport d.e.F as G\nimport h.*\n");
        let paths: Vec<(&str, Option<&str>)> = analysis
            .imports
            .iter()
            .map(|held| (held.path.as_str(), held.alias.as_deref()))
            .collect();
        assert_eq!(
            paths,
            [("a.b.C", None), ("d.e.F", Some("G")), ("h.*", None)]
        );
    }

    #[test]
    fn a_supertype_is_a_reference_and_never_claimed_as_an_interface() {
        let found = items("class Impl : Base(1), Runnable { }");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].implements, None,
            "a supertype list does not say which entries are interfaces"
        );
        let names: Vec<&str> = found[0]
            .references
            .iter()
            .map(|held| held.name.as_str())
            .collect();
        assert_eq!(names, ["Base", "Runnable"]);
    }

    #[test]
    fn a_call_is_recorded_from_a_body_and_from_an_expression_body() {
        assert_eq!(calls("fun f() { helper() }"), ["helper"]);
        assert_eq!(calls("fun f() = helper()"), ["helper"]);
        assert_eq!(calls("fun f() { a.b.c() }"), ["a.b.c"]);
        assert_eq!(calls("fun f() { x?.y() }"), ["x.y"]);
    }

    #[test]
    fn an_expression_body_stops_at_the_next_declaration() {
        // Kotlin has no statement terminator, so nothing in the token stream ends an expression body.
        // Reading past it would make `g` a call inside `f` and lose `g` as a declaration.
        assert_eq!(
            flat("class A {\n  fun f() = 1\n  fun g() = 2\n}"),
            ["Struct:A", "Method:f", "Method:g"]
        );
    }

    #[test]
    fn a_generic_signature_is_consumed_whole() {
        assert_eq!(
            flat("class Box<T>(val value: T) { fun <R> map(f: (T) -> R): Box<R> = Box(f(value)) }"),
            ["Struct:Box", "Field:value", "Method:map"]
        );
        assert_eq!(
            flat("val m: Map<String, List<Int>> = mapOf()"),
            ["Constant:m"],
            "nested angle brackets close as two tokens"
        );
    }

    /// Every annotation on an item, as `name(arguments)`.
    fn annotated(source: &str) -> Vec<String> {
        fn walk(items: &[Item], into: &mut Vec<String>) {
            for item in items {
                for annotation in &item.annotations {
                    into.push(match &annotation.arguments {
                        Some(arguments) => {
                            format!("{}:{}({arguments})", item.name, annotation.name)
                        }
                        None => format!("{}:{}", item.name, annotation.name),
                    });
                }
                walk(&item.children, into);
            }
        }
        let mut found = Vec::new();
        walk(&items(source), &mut found);
        found
    }

    #[test]
    fn an_annotation_is_kept_on_the_declaration_it_was_written_on() {
        // The reported failure was a Spring route returning nothing. This is where it was lost: the
        // annotation was skipped, so the route never reached the graph and no framework analyzer could
        // have recovered it.
        let source = "\
@RestController
class TempController {
    @GetMapping(\"/temp\")
    fun temp(): String = \"ok\"

    @Test
    fun plain() {}
}
";
        assert_eq!(
            annotated(source),
            [
                "TempController:RestController",
                // The route itself, which is the whole point: `<literal>` would tell a framework
                // analyzer that a string was there and not which one.
                "temp:GetMapping(\"/temp\")",
                "plain:Test",
            ]
        );
    }

    #[test]
    fn an_annotation_keeps_its_arguments_as_written() {
        // Unparsed on purpose. `@GetMapping("/x")` and `@RequestMapping(value = ["/x"], method = ...)`
        // mean the same thing to Spring and nothing to Kotlin, so normalising them here would be
        // guessing at a framework this analyzer does not know.
        let source = "@RequestMapping(value = [\"/api\"], method = [RequestMethod.GET])\nclass C";
        let found = items(source);
        let annotation = &found[0].annotations[0];
        assert_eq!(annotation.name, "RequestMapping");
        let arguments = annotation.arguments.clone().expect("arguments");
        assert!(arguments.contains("value"), "{arguments}");
        assert!(arguments.contains("RequestMethod"), "{arguments}");
        assert!(arguments.contains("GET"), "{arguments}");
    }

    #[test]
    fn no_arguments_and_empty_arguments_are_different() {
        // `@Test` took none and `@Test()` took none but was called. A framework may care which, and
        // collapsing them would decide that for it.
        assert_eq!(items("@Test\nfun a() {}")[0].annotations[0].arguments, None);
        assert_eq!(
            items("@Test()\nfun a() {}")[0].annotations[0]
                .arguments
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn a_qualified_annotation_keeps_only_its_own_name() {
        let source = "@org.springframework.web.bind.annotation.GetMapping(\"/x\")\nfun f() {}";
        assert_eq!(items(source)[0].annotations[0].name, "GetMapping");
    }

    #[test]
    fn a_use_site_target_is_consumed_and_the_annotation_is_kept() {
        assert_eq!(
            items("@get:JvmName(\"x\")\nval v = 1")[0].annotations[0].name,
            "JvmName"
        );
    }

    #[test]
    fn an_annotation_survives_a_modifier_on_either_side_of_it() {
        // Both orders are legal Kotlin, and a reader that gathered annotations only before modifiers
        // would silently drop half of them.
        for source in ["@Inject private val a = 1", "private @Inject val a = 1"] {
            let found = items(source);
            assert_eq!(
                found[0].annotations.first().map(|held| held.name.as_str()),
                Some("Inject"),
                "{source}"
            );
        }
    }

    #[test]
    fn an_annotation_and_its_arguments_are_not_declarations() {
        let source = "@Service(name = \"x\")\nclass Annotated {\n  @Test fun t() {}\n}";
        assert_eq!(flat(source), ["Struct:Annotated", "Method:t"]);
    }

    #[test]
    fn a_declaration_inside_a_comment_or_a_string_is_not_read() {
        assert_eq!(flat("/* class Commented */ class Real"), ["Struct:Real"]);
        assert_eq!(flat("val s = \"\"\"class Quoted\"\"\""), ["Constant:s"]);
        assert_eq!(
            flat("class A { val s = \"${'$'}{if (true) \"}\" else \"\"}\" }"),
            ["Struct:A", "Field:s"],
            "a brace inside a template's nested string does not close the class"
        );
    }

    #[test]
    fn an_extension_function_is_named_for_its_last_segment() {
        let found = items("fun String.shout(): String = uppercase()");
        assert_eq!(named(&found, ItemKind::Function), ["shout"]);
        assert!(
            found[0].references.iter().any(|held| held.name == "String"),
            "and its receiver is a reference: {:?}",
            found[0].references
        );
    }

    #[test]
    fn a_secondary_constructor_is_a_method() {
        assert_eq!(
            flat("class A(val x: Int) {\n  constructor() : this(0) {}\n}"),
            ["Struct:A", "Field:x", "Method:constructor"]
        );
    }

    #[test]
    fn a_typealias_is_read_with_its_target() {
        let found = items("typealias Handler = (Int) -> Unit");
        assert_eq!(named(&found, ItemKind::TypeAlias), ["Handler"]);
    }

    #[test]
    fn a_backtick_name_is_the_declaration_name() {
        assert_eq!(flat("fun `a test name`() {}"), ["Function:a test name"]);
        assert_eq!(
            flat("fun `class`() {}"),
            ["Function:class"],
            "and a quoted keyword does not begin a type"
        );
    }

    #[test]
    fn a_range_starts_and_ends_where_the_declaration_does() {
        let found = items("\nclass A {\n    fun f() {}\n}\n");
        assert_eq!(found[0].range.start().line, 2);
        assert_eq!(found[0].range.end().line, 4);
        assert_eq!(found[0].children[0].range.start().line, 3);
    }

    #[test]
    fn malformed_source_yields_what_was_readable_and_returns() {
        for source in [
            "class",
            "class A {",
            "fun f(",
            "val",
            "class A { fun",
            "}",
            "import",
            "typealias",
            "object",
            "fun f() { \"${",
        ] {
            let _ = analyze(source);
        }
        // And a truncated file still reports the declaration that was complete.
        assert_eq!(
            flat("class Whole {}\nclass Trunc"),
            ["Struct:Whole", "Struct:Trunc"]
        );
    }

    #[test]
    fn the_declared_capability_says_what_it_does_and_does_not_extract() {
        let declared = capability();
        assert_eq!(declared.language.as_str(), LANGUAGE);
        assert_eq!(declared.precision, PrecisionClass::DeterministicSyntactic);
        assert!(declared.extracts(FactKind::Call));
        assert!(
            !declared.extracts(FactKind::InterfaceImplementation),
            "a supertype list does not say which entries are interfaces, so this is not claimed"
        );
    }
}
