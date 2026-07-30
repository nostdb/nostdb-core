//! Reads Java structure, without resolving anything.
//!
//! # What this layer is for
//!
//! It says what the source declares. What those declarations *mean* to a framework is
//! [`super::framework`]'s question, and that split is why Spring costs nothing to reach from here: the
//! knowledge that `@GetMapping` is a route is written once, against [`super::FileAnalysis`], and Java
//! reaches it by producing the same annotations Kotlin does. Putting Spring knowledge in this file
//! would have been the second copy that layer exists to prevent.
//!
//! # Java declarations this reads
//!
//! | Written | Recorded as |
//! | --- | --- |
//! | `package a.b;` | the file's package, on the file and on no qualified name — see below |
//! | `import a.b.C;`, `import static a.b.C.d;`, `import a.b.*;` | an import |
//! | `class`, `record` | [`ItemKind::Struct`] |
//! | `interface`, `@interface` | [`ItemKind::Trait`] |
//! | `enum` | [`ItemKind::Enum`] |
//! | a method or constructor in a type | [`ItemKind::Method`] |
//! | a field in a type | [`ItemKind::Field`] |
//! | a nested type | a child of the type it is in |
//! | `extends`, `implements`, `permits` | references, not `implements` |
//! | a name applied in a body | a reference |
//! | annotations, with their arguments as written | on the declaration they precede |
//!
//! **No `Constant` is produced.** Kotlin records one for a `val` at file scope, and Java has no file
//! scope: every field belongs to a type. Recording a `static final` field as a Constant instead would
//! make the same declaration two different kinds depending on its modifiers, and nothing downstream
//! asks that question.
//!
//! # Why `extends` is a reference and not `implements`
//!
//! [`Item::implements`] exists for a language that distinguishes the thing being implemented from the
//! thing being extended at the syntax level. Java writes `class A extends B implements C`, which looks
//! like it does — but an `interface` also writes `extends` for what it inherits, and a superclass and an
//! interface are both just names here. At [`PrecisionClass::DeterministicSyntactic`] this analyzer
//! cannot tell which name is a class, so claiming one would be a guess. Every supertype is a reference,
//! which is what Kotlin's analyzer concluded from the same problem.
//!
//! # Why the package is recorded on the file and on nothing else
//!
//! The objection that kept it out stands: a qualified name is an identity, and putting the package on one
//! would retire and re-mint every record in every existing database. So it goes nowhere near an item. It is
//! recorded on the **file**, where it names no record and changes no identity.
//!
//! It is recorded at all because an import names a declaration, and the resolver had nothing else to match
//! one against but a file name. Java's file names are constrained enough for that to have worked here;
//! Kotlin's are not, and both languages are resolved by the same rule.

use super::java_lexer::{Delimiter, Spanned, Token, tokenize};
use super::{Annotation, FileAnalysis, Import, Item, ItemKind, Reference};
use crate::analysis::{AnalyzerCapability, FactKind, PrecisionClass};
use crate::evidence::{SourcePosition, SourceRange};
use crate::text::NonEmptyText;

/// The language this analyzer reads.
pub const LANGUAGE: &str = "java";

/// How precisely it reads.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// What this analyzer declares it extracts.
#[must_use]
pub fn capability() -> AnalyzerCapability {
    AnalyzerCapability {
        language: NonEmptyText::new(LANGUAGE).unwrap_or_else(|_| NonEmptyText::literal("java")),
        precision: PRECISION,
        facts: vec![
            FactKind::File,
            FactKind::Type,
            FactKind::Class,
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

/// Reads one Java file.
///
/// Never fails. Malformed input yields whatever declarations could be read, because a structural
/// analyzer runs over source somebody is editing and a file that does not compile is the ordinary case.
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

/// Words that precede a declaration without being one.
///
/// `sealed` and `non-sealed` are contextual — `sealed` is a valid identifier elsewhere — so they are
/// listed as modifiers and never as declaration keywords.
const MODIFIERS: [&str; 13] = [
    "abstract",
    "default",
    "final",
    "native",
    "private",
    "protected",
    "public",
    "sealed",
    "static",
    "strictfp",
    "synchronized",
    "transient",
    "volatile",
];

/// Words that begin a type declaration.
const TYPE_KEYWORDS: [&str; 4] = ["class", "enum", "interface", "record"];

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
    ///
    /// `container` is the kind of type this is inside, and `None` is file scope. It decides nothing
    /// about naming here — Java has no file-scope member — but it is what stops a stray closing brace
    /// in a malformed file from ending the whole file's parse.
    fn declarations(&mut self, container: Option<ItemKind>) -> Vec<Item> {
        let mut items = Vec::new();
        loop {
            let annotations = self.annotations();
            self.modifiers();
            // Annotations and modifiers may be all that is left, on a file being typed.
            let Some(token) = self.peek() else {
                return items;
            };
            if matches!(token, Token::Close(Delimiter::Brace)) {
                self.advance();
                // Inside a body this closes it. At file scope it is a stray brace in a file somebody is
                // partway through editing, and returning would hide every declaration after it.
                if container.is_some() {
                    return items;
                }
                continue;
            }
            // A static or instance initializer block, `static { }` or `{ }`. It declares nothing.
            if matches!(token, Token::Open(Delimiter::Brace)) {
                self.skip_balanced(Delimiter::Brace);
                continue;
            }
            match self.name_here() {
                Some("package") => {
                    // The package a file joins, not a declaration in it — so it is recorded on the file
                    // and never on an item, for the reason the module documentation gives. Kept rather
                    // than dropped because an import names a declaration, and the resolver had nothing
                    // else to match one against but a file name.
                    self.advance();
                    let found = self.qualified_name();
                    if self.package.is_none() && !found.is_empty() {
                        self.package = Some(found);
                    }
                    self.skip_statement_end();
                }
                Some("import") => self.import(),
                Some(name) if TYPE_KEYWORDS.contains(&name) => {
                    let keyword = name.to_owned();
                    if let Some(mut item) = self.type_declaration(&keyword) {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                // Only inside a type, because that is the only place Java puts a member.
                Some(_) if container.is_some() => {
                    if let Some(mut item) = self.member() {
                        item.annotations = annotations;
                        items.push(item);
                    }
                }
                // At file scope, anything that is not a package, an import, or a type is not something
                // this analyzer reads. Advancing keeps a malformed file from looping.
                _ => {
                    self.advance();
                }
            }
        }
    }

    /// `@Name`, `@Name(...)`, repeated.
    ///
    /// An annotation's arguments are kept **as written**. `@GetMapping("/x")` and
    /// `@RequestMapping(value = "/x", method = GET)` mean the same thing to Spring and nothing to Java,
    /// so normalizing them here would be guessing at a framework this layer does not know.
    fn annotations(&mut self) -> Vec<Annotation> {
        let mut found = Vec::new();
        while self.peek().is_some_and(|token| token.is_punct('@')) {
            // `@interface` is a declaration, not an annotation on one.
            if self.peek_at(1).and_then(Token::name) == Some("interface") {
                return found;
            }
            let start = self.position();
            self.advance();
            let Some(name) = self.peek().and_then(Token::name).map(str::to_owned) else {
                return found;
            };
            self.advance();
            // A qualified annotation, `@org.junit.Test`.
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
            if let Ok(name) = NonEmptyText::new(name.as_str()) {
                found.push(Annotation {
                    name: name.as_str().to_owned(),
                    arguments,
                    range: range(start, self.previous_position()),
                });
            }
        }
        found
    }

    /// Modifier words, consumed and returned.
    ///
    /// `non-sealed` is written with a hyphen, which the lexer reads as three tokens. The punctuation is
    /// consumed with it so the `sealed` that follows is not read as a declaration's name.
    fn modifiers(&mut self) -> Vec<String> {
        let mut found = Vec::new();
        loop {
            match self.name_here() {
                Some("non") if self.peek_at(1).is_some_and(|token| token.is_punct('-')) => {
                    self.advance();
                    self.advance();
                    if self.name_here() == Some("sealed") {
                        self.advance();
                        found.push("non-sealed".to_owned());
                    }
                }
                Some(name) if MODIFIERS.contains(&name) => {
                    found.push(name.to_owned());
                    self.advance();
                }
                _ => return found,
            }
        }
    }

    fn import(&mut self) {
        let start = self.position();
        self.advance();
        // `import static a.b.C.d;` names a member. The path is what is recorded either way, because
        // what an import resolves to is decided against the whole build rather than here.
        if self.name_here() == Some("static") {
            self.advance();
        }
        let path = self.qualified_name();
        self.skip_statement_end();
        if !path.is_empty() {
            self.imports.push(Import {
                path,
                // Java has no import alias. The field stays for the shared contract.
                alias: None,
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

    /// `class`, `interface`, `@interface`, `enum`, `record`.
    fn type_declaration(&mut self, keyword: &str) -> Option<Item> {
        let start = self.position();
        self.advance();
        let name = self.advance().and_then(Token::name)?.to_owned();
        let kind = match keyword {
            "interface" => ItemKind::Trait,
            "enum" => ItemKind::Enum,
            _ => ItemKind::Struct,
        };

        self.skip_type_parameters();
        let mut references = Vec::new();
        // A record's components are its parameters, not its body.
        if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
            self.skip_balanced(Delimiter::Paren);
        }
        // `extends`, `implements`, and `permits` all list names, and none of them says which name is a
        // class. Every one is a reference.
        while let Some("extends" | "implements" | "permits") = self.name_here() {
            self.advance();
            references.extend(self.supertypes());
        }
        let mut children = Vec::new();
        if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
            self.advance();
            if kind == ItemKind::Enum {
                children.extend(self.enum_constants());
            }
            children.extend(self.declarations(Some(kind)));
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

    /// An enum's constants, which come before its members and are separated by commas.
    ///
    /// Recorded as fields, because that is what they are: a named member of the enum's own type. The
    /// list ends at a `;` or at the closing brace.
    fn enum_constants(&mut self) -> Vec<Item> {
        let mut found = Vec::new();
        loop {
            // A constant may carry annotations of its own.
            self.annotations();
            let start = self.position();
            let Some(name) = self.name_here().map(str::to_owned) else {
                return found;
            };
            self.advance();
            // `RED("red")` and `RED { ... }` are both a constant with a body.
            if matches!(self.peek(), Some(Token::Open(Delimiter::Paren))) {
                self.skip_balanced(Delimiter::Paren);
            }
            if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
                self.skip_balanced(Delimiter::Brace);
            }
            found.push(Item {
                kind: ItemKind::Field,
                name,
                range: range(start, self.previous_position()),
                target: None,
                implements: None,
                references: Vec::new(),
                annotations: Vec::new(),
                children: Vec::new(),
            });
            match self.peek() {
                Some(token) if token.is_punct(',') => {
                    self.advance();
                }
                // The members begin after the semicolon.
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return found;
                }
                _ => return found,
            }
        }
    }

    /// One member of a type: a nested type, a method, a constructor, or a field.
    ///
    /// Java has no keyword introducing a method or a field, so the two are told apart by what follows
    /// the name: a `(` makes it a method, anything else a field. That is the whole rule, and it is the
    /// same one a reader uses.
    ///
    /// The modifiers are consumed by the caller and not passed in, because none of them changes what a
    /// member is. `static final` on a field leaves it a field — see the module note on `Constant`.
    fn member(&mut self) -> Option<Item> {
        let start = self.position();
        if let Some(keyword) = self.name_here()
            && TYPE_KEYWORDS.contains(&keyword)
        {
            let keyword = keyword.to_owned();
            return self.type_declaration(&keyword);
        }
        // A generic method's parameters come before its return type.
        self.skip_type_parameters();

        // Walk the type and the name together, because which token is the name is only known once a `(`
        // or a `=` or a `;` is reached. `Map<String, List<Integer>> field = ...` has three tokens of
        // type before the name.
        let mut last_name: Option<String> = None;
        loop {
            match self.peek() {
                Some(Token::Open(Delimiter::Paren)) => {
                    let name = last_name?;
                    self.skip_balanced(Delimiter::Paren);
                    // `throws A, B` before the body.
                    if self.name_here() == Some("throws") {
                        self.advance();
                        self.supertypes();
                    }
                    let mut references = Vec::new();
                    if matches!(self.peek(), Some(Token::Open(Delimiter::Brace))) {
                        references = self.body();
                    } else {
                        // An abstract or interface method has no body.
                        self.skip_statement_end();
                    }
                    return Some(Item {
                        kind: ItemKind::Method,
                        name,
                        range: range(start, self.previous_position()),
                        target: None,
                        implements: None,
                        references,
                        annotations: Vec::new(),
                        children: Vec::new(),
                    });
                }
                // A field, with or without an initializer.
                Some(token) if token.is_punct('=') || token.is_punct(';') => {
                    let name = last_name?;
                    let references = self.skip_to_statement_end();
                    return Some(Item {
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
                Some(Token::Open(Delimiter::Bracket)) => {
                    self.skip_balanced(Delimiter::Bracket);
                }
                Some(token) if token.is_punct('<') => {
                    self.skip_type_parameters();
                }
                Some(token) if token.name().is_some() => {
                    last_name = token.name().map(str::to_owned);
                    self.advance();
                }
                Some(Token::Close(Delimiter::Brace)) | None => return None,
                _ => {
                    self.advance();
                }
            }
        }
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
            // A qualified supertype keeps its final segment, which is what a reference names.
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

    /// A method body, returning the names applied in it.
    ///
    /// A name followed by `(` is a call. Nothing else is recorded: at syntactic precision a bare name
    /// could be a local, a field, a type, or a package segment, and recording all of them would make
    /// every reference count meaningless.
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
                    let name = token.name().map(str::to_owned);
                    self.advance();
                    // `a.b()` is a call to `b` on `a`; `b()` is a call to `b`.
                    let mut name = name;
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

    /// Consumes to the end of a statement, returning the calls made in it.
    fn skip_to_statement_end(&mut self) -> Vec<Reference> {
        let mut found = Vec::new();
        loop {
            match self.peek() {
                Some(token) if token.is_punct(';') => {
                    self.advance();
                    return found;
                }
                Some(Token::Open(Delimiter::Brace)) => {
                    // An array initializer or an anonymous class.
                    found.extend(self.body());
                }
                Some(Token::Close(Delimiter::Brace)) | None => return found,
                Some(token) if token.name().is_some() => {
                    let start = self.position();
                    let name = token.name().map(str::to_owned);
                    self.advance();
                    if matches!(self.peek(), Some(Token::Open(Delimiter::Paren)))
                        && let Some(name) = name
                    {
                        found.push(Reference {
                            name,
                            qualifier: None,
                            is_method: false,
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

    /// Consumes a `;` when one is next.
    fn skip_statement_end(&mut self) {
        if self.peek().is_some_and(|token| token.is_punct(';')) {
            self.advance();
        }
    }

    /// Consumes a balanced `<...>` when one is next.
    ///
    /// Counted rather than matched to the first `>`, because `Map<String, List<Integer>>` closes two at
    /// once and the lexer emits each `>` separately. A generic bound holding a `>>` shift operator
    /// cannot occur in a type, so counting is exact here.
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
            } else if matches!(
                token,
                Token::Open(Delimiter::Brace) | Token::Close(Delimiter::Brace)
            ) {
                // Not a type parameter list after all. Stopping beats consuming a body.
                return;
            }
            self.advance();
        }
    }

    /// Consumes a balanced pair, assuming the opening delimiter is next.
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
    ///
    /// A string keeps its content and every other token renders as itself, so an annotation's arguments
    /// read the way the source wrote them.
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

    fn kinds(source: &str) -> Vec<(ItemKind, String)> {
        analyze(source)
            .walk()
            .map(|item| (item.kind, item.name.clone()))
            .collect()
    }

    fn names(source: &str) -> Vec<String> {
        analyze(source)
            .walk()
            .map(|item| item.name.clone())
            .collect()
    }

    #[test]
    fn a_class_its_methods_and_its_fields_are_read() {
        let found = kinds(
            "package com.demo;\n\
             public class Service {\n\
               private final Repo repo;\n\
               public Service(Repo repo) { this.repo = repo; }\n\
               public String find(long id) { return repo.get(id); }\n\
             }\n",
        );
        assert_eq!(
            found,
            [
                (ItemKind::Struct, "Service".to_owned()),
                (ItemKind::Field, "repo".to_owned()),
                (ItemKind::Method, "Service".to_owned()),
                (ItemKind::Method, "find".to_owned()),
            ]
        );
    }

    #[test]
    fn an_interface_is_a_trait_and_an_enum_is_an_enum() {
        assert_eq!(
            kinds("interface Greeter { String greet(); }"),
            [
                (ItemKind::Trait, "Greeter".to_owned()),
                (ItemKind::Method, "greet".to_owned()),
            ]
        );
        assert_eq!(
            kinds("enum Colour { RED, GREEN; int code() { return 0; } }"),
            [
                (ItemKind::Enum, "Colour".to_owned()),
                (ItemKind::Field, "RED".to_owned()),
                (ItemKind::Field, "GREEN".to_owned()),
                (ItemKind::Method, "code".to_owned()),
            ]
        );
    }

    #[test]
    fn a_record_is_a_struct_and_its_components_are_not_fields() {
        // A component is a parameter of the declaration, not a member of its body. Recording one as a
        // field would put a declaration in the graph that the body does not contain.
        assert_eq!(
            kinds("public record Point(int x, int y) { }"),
            [(ItemKind::Struct, "Point".to_owned())]
        );
    }

    #[test]
    fn an_annotation_type_is_a_trait_and_not_an_annotation_on_something() {
        // `@interface` begins a declaration. Read as an annotation it would attach to whatever follows
        // and the type itself would vanish.
        assert_eq!(
            kinds("public @interface Marker { String value(); }"),
            [
                (ItemKind::Trait, "Marker".to_owned()),
                (ItemKind::Method, "value".to_owned()),
            ]
        );
    }

    #[test]
    fn imports_are_recorded_with_their_path_as_written() {
        let found = analyze(
            "package com.demo;\n\
             import java.util.List;\n\
             import static org.junit.Assert.assertEquals;\n\
             import com.demo.data.*;\n\
             class A { }\n",
        );
        assert_eq!(
            found
                .imports
                .iter()
                .map(|held| held.path.clone())
                .collect::<Vec<_>>(),
            [
                "java.util.List",
                "org.junit.Assert.assertEquals",
                "com.demo.data.*"
            ]
        );
    }

    #[test]
    fn the_package_is_recorded_on_the_file_and_is_not_a_declaration() {
        // Both halves matter. It is held, because an import names a declaration and the resolver has
        // nothing else to match one against. And it is on the file only: `A` stays `A`, because a qualified
        // name is an identity and moving the package into one would re-mint every record in every database.
        let found = analyze("package com.demo.app;\nclass A { }\n");
        assert_eq!(found.package.as_deref(), Some("com.demo.app"));
        assert_eq!(names("package com.demo.app;\nclass A { }\n"), ["A"]);
        assert!(found.imports.is_empty());
    }

    #[test]
    fn a_file_declaring_no_package_says_absent_rather_than_empty() {
        // Absent is what the resolver reads to fall back to matching paths, so an empty string in its place
        // would claim a package named "" and route the file's imports through a rule that cannot answer them.
        let found = analyze("class A { }\n");
        assert_eq!(found.package, None);
    }

    #[test]
    fn annotations_keep_their_arguments_as_written() {
        // The whole reason Java reaches Spring for free: the framework layer reads these, and it already
        // knows what they mean.
        let found = analyze(
            "@RestController\n\
             class Controller {\n\
               @GetMapping(\"/api/x\")\n\
               public String read() { return \"\"; }\n\
             }\n",
        );
        let controller = &found.items[0];
        assert_eq!(
            controller
                .annotations
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["RestController"]
        );
        let method = &controller.children[0];
        assert_eq!(method.annotations[0].name, "GetMapping");
        assert_eq!(
            method.annotations[0].arguments.as_deref(),
            Some("\"/api/x\"")
        );
    }

    #[test]
    fn a_qualified_annotation_keeps_its_final_segment() {
        let found = analyze("class A { @org.junit.Test void t() { } }");
        assert_eq!(found.items[0].children[0].annotations[0].name, "Test");
    }

    #[test]
    fn every_supertype_is_a_reference_and_nothing_claims_to_be_implemented() {
        // Java writes `extends` and `implements` separately, but an interface also writes `extends` for
        // what it inherits, and at syntactic precision neither says which name is a class.
        let found = analyze("class A extends B implements C, D { }");
        let item = &found.items[0];
        assert!(item.implements.is_none());
        assert_eq!(
            item.references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["B", "C", "D"]
        );
    }

    #[test]
    fn a_call_in_a_body_is_a_reference_and_a_bare_name_is_not() {
        let found = analyze("class A { void run() { int x = 1; helper(); other.thing(); } }");
        let method = &found.items[0].children[0];
        let referenced: Vec<String> = method
            .references
            .iter()
            .map(|held| held.name.clone())
            .collect();
        assert_eq!(referenced, ["helper", "thing"]);
        assert!(!method.references[0].is_method, "an unqualified call");
        assert!(method.references[1].is_method, "a call on a receiver");
    }

    #[test]
    fn a_generic_return_type_does_not_hide_the_method_name() {
        // The name is only knowable once a `(` is reached, and `Map<String, List<Integer>>` closes two
        // angle brackets at once.
        assert_eq!(
            kinds("class A { public Map<String, List<Integer>> grouped() { return null; } }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "grouped".to_owned()),
            ]
        );
    }

    #[test]
    fn a_generic_method_declares_its_parameters_before_its_return_type() {
        assert_eq!(
            kinds("class A { public <T> T pick(T a) { return a; } }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "pick".to_owned()),
            ]
        );
    }

    #[test]
    fn an_initializer_block_declares_nothing() {
        assert_eq!(
            kinds("class A { static { load(); } { also(); } int f; }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Field, "f".to_owned()),
            ]
        );
    }

    #[test]
    fn a_nested_type_is_a_child() {
        let found = analyze("class Outer { static class Inner { void m() { } } }");
        let outer = &found.items[0];
        assert_eq!(outer.name, "Outer");
        assert_eq!(outer.children[0].name, "Inner");
        assert_eq!(outer.children[0].children[0].name, "m");
    }

    #[test]
    fn a_throws_clause_does_not_become_a_declaration() {
        assert_eq!(
            kinds("class A { void risky() throws IOException, SQLException { } }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "risky".to_owned()),
            ]
        );
    }

    #[test]
    fn an_abstract_method_without_a_body_is_still_a_method() {
        assert_eq!(
            kinds("abstract class A { public abstract int size(); int n; }"),
            [
                (ItemKind::Struct, "A".to_owned()),
                (ItemKind::Method, "size".to_owned()),
                (ItemKind::Field, "n".to_owned()),
            ]
        );
    }

    #[test]
    fn a_sealed_hierarchy_reads_its_permits_list_as_references() {
        let found = analyze("public sealed interface Shape permits Circle, Square { }");
        assert_eq!(found.items[0].kind, ItemKind::Trait);
        assert_eq!(
            found.items[0]
                .references
                .iter()
                .map(|held| held.name.clone())
                .collect::<Vec<_>>(),
            ["Circle", "Square"]
        );
        // `non-sealed` is three tokens and must not leave `sealed` reading as a name.
        assert_eq!(
            kinds("non-sealed class B extends A { }"),
            [(ItemKind::Struct, "B".to_owned())]
        );
    }

    #[test]
    fn no_constant_is_produced_because_java_has_no_file_scope() {
        let found = analyze("class A { public static final int MAX = 10; }");
        assert_eq!(found.items[0].children[0].kind, ItemKind::Field);
        assert!(
            found.walk().all(|item| item.kind != ItemKind::Constant),
            "a static final field is a field, not a Constant"
        );
    }

    #[test]
    fn malformed_source_yields_what_could_be_read_and_stops() {
        // The ordinary case: a file somebody is midway through typing.
        assert_eq!(names("class A { void m() { "), ["A", "m"]);
        assert_eq!(names("class A {"), ["A"]);
        assert!(names("class").is_empty());
        assert!(names("").is_empty());
        // A stray closing brace at file scope must not end the parse of what follows.
        assert_eq!(names("} class A { }"), ["A"]);
    }

    #[test]
    fn a_declaration_carries_the_range_it_was_written_at() {
        let found = analyze("class A {\n  void m() { }\n}\n");
        assert_eq!(found.items[0].range.start().line, 1);
        let method = &found.items[0].children[0];
        assert_eq!(method.range.start().line, 2);
    }

    #[test]
    fn the_capability_declares_only_what_this_analyzer_produces() {
        let declared = capability();
        assert_eq!(declared.language.as_str(), "java");
        assert_eq!(declared.precision, PRECISION);
        // Every one of these has a test above that produces it.
        for fact in [
            FactKind::Method,
            FactKind::Field,
            FactKind::ImportExport,
            FactKind::Call,
            FactKind::Inheritance,
        ] {
            assert!(declared.extracts(fact), "{fact} is declared and produced");
        }
        // Declared by neither Kotlin nor Rust and not produced here either. `ImportExport` was declared
        // by both and produced by neither until the import relation landed, which is the defect this
        // assertion exists to keep out of a new analyzer.
        assert!(!declared.extracts(FactKind::Package));
        assert!(!declared.extracts(FactKind::EntryPoint));
    }
}
