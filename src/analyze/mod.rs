//! Deterministic structural analysis.
//!
//! An analyzer reads source and reports its shape. It resolves nothing across files, calls
//! nothing external, and spends no AI tokens, which root PRD section 29.1 requires of
//! structural extraction over supported source.
//!
//! # Precision is declared, not assumed
//!
//! Every analyzer here is [`PrecisionClass::DeterministicSyntactic`]: it reads syntax
//! without resolving names. A call to `parse` is recorded as a call to something named
//! `parse`, not as a call to a particular function, because deciding which `parse` is
//! meant needs a name resolver this does not have.
//!
//! That is an honest claim rather than a shortfall, and section 17.3 requires it to travel
//! with the facts. A caller must be able to tell a resolved fact from a syntactic one, and
//! presenting the second as the first is the specific thing the contract forbids.

pub mod c;
pub mod c_lexer;
pub mod framework;
pub mod go;
pub mod go_lexer;
pub mod java;
pub mod java_lexer;
pub mod kotlin;
pub mod kotlin_lexer;
pub mod python;
pub mod python_lexer;
pub mod rust;
pub mod rust_lexer;
pub mod typescript;
pub mod typescript_lexer;

use crate::analysis::{AnalyzerCapability, CapabilityRegistry, PrecisionClass};
use crate::evidence::{ContentDigest, SourcePosition, SourceRange};
use std::fmt;

/// What kind of thing an extracted item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    /// A module of the analyzed language.
    Module,
    /// A struct, record, or equivalent.
    Struct,
    /// An enumeration.
    Enum,
    /// A union.
    Union,
    /// An interface or trait.
    Trait,
    /// A type alias.
    TypeAlias,
    /// A free function.
    Function,
    /// A function belonging to a type or trait.
    Method,
    /// A field of a struct, union, or enum variant.
    Field,
    /// A constant or static.
    Constant,
    /// An implementation block, which associates methods with a type.
    Implementation,
}

impl ItemKind {
    /// Reports whether this kind can hold other items.
    #[must_use]
    pub const fn can_contain(self) -> bool {
        matches!(
            self,
            Self::Module
                | Self::Trait
                | Self::Implementation
                | Self::Struct
                | Self::Enum
                | Self::Union
        )
    }
}

impl fmt::Display for ItemKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Module => "module",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Union => "union",
            Self::Trait => "trait",
            Self::TypeAlias => "type",
            Self::Function => "function",
            Self::Method => "method",
            Self::Field => "field",
            Self::Constant => "constant",
            Self::Implementation => "impl",
        })
    }
}

/// A reference to something named, which this analyzer did not resolve.
///
/// The name and its qualifier are recorded exactly as written. Turning either into a
/// target is cross-file work that happens after every file is analyzed, and a reference
/// that resolves to nothing becomes a Placeholder rather than a null endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The final segment, which is the name being referred to.
    pub name: String,
    /// Everything before it, when the reference was qualified.
    pub qualifier: Option<String>,
    /// Whether it was written as a method call on a receiver.
    pub is_method: bool,
    /// Where it appears.
    pub range: SourceRange,
}

/// One extracted item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// What it is.
    pub kind: ItemKind,
    /// Its name.
    pub name: String,
    /// Where its declaration begins and ends.
    pub range: SourceRange,
    /// For an implementation, the type it is for.
    pub target: Option<String>,
    /// For an implementation, the trait it implements.
    pub implements: Option<String>,
    /// Names this item refers to, unresolved.
    pub references: Vec<Reference>,
    /// Annotations or attributes written on it, in source order.
    ///
    /// Kept rather than skipped because this is where a framework's meaning lives. A route, an
    /// injected dependency, a scheduled job, a serialized field — none of them are facts about the
    /// language, and all of them are written as annotations on a declaration the language does
    /// describe. A language analyzer that discarded them left every framework fact unrecoverable, and
    /// the only sign of it was a query returning nothing.
    pub annotations: Vec<Annotation>,
    /// Items declared inside it.
    pub children: Vec<Item>,
}

/// One annotation or attribute written on a declaration.
///
/// The arguments are kept **as written**, unparsed. `@GetMapping("/api/x")` and
/// `@RequestMapping(value = ["/api/x"], method = [RequestMethod.GET])` mean the same thing to Spring
/// and nothing to Kotlin, so which is which is a framework analyzer's question rather than a language
/// analyzer's — and a language analyzer that tried to normalise them would be guessing at a framework
/// it does not know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation {
    /// The annotation's name, without the sigil and without its qualifier.
    pub name: String,
    /// Everything between the parentheses, exactly as written, or `None` when there were none.
    ///
    /// `None` and `Some("")` are different: `@Test` took no arguments and `@Test()` took none but was
    /// called, and a framework may care which.
    pub arguments: Option<String>,
    /// Where it appears.
    pub range: SourceRange,
}

impl Item {
    /// A named item of one kind, with nothing else set.
    #[must_use]
    pub fn new(kind: ItemKind, name: impl Into<String>, range: SourceRange) -> Self {
        Self {
            kind,
            name: name.into(),
            range,
            target: None,
            implements: None,
            references: Vec::new(),
            annotations: Vec::new(),
            children: Vec::new(),
        }
    }

    /// This item and every item beneath it, depth first.
    pub fn walk(&self) -> impl Iterator<Item = &Self> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            let next = stack.pop()?;
            stack.extend(next.children.iter().rev());
            Some(next)
        })
    }
}

/// Something one file brings in from elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// The path exactly as written.
    pub path: String,
    /// The name it is bound to, when renamed.
    pub alias: Option<String>,
    /// Where it appears.
    pub range: SourceRange,
}

/// What one file yielded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileAnalysis {
    /// The language that was read.
    pub language: String,
    /// The digest of the bytes that were read, which is half of the parse cache key.
    pub digest: ContentDigest,
    /// The package the file declares, where its language has one and it wrote one.
    ///
    /// Held because an import names a **declaration**, and without this the only thing left to match one
    /// against is a file name. That is sound in Java, whose file names are constrained to agree with the
    /// class in them, and unsound in Kotlin, whose are not: `class Payload` may be declared in `Models.kt`,
    /// and matching by path then either misses it or attaches the import to whatever `Payload.kt` happens
    /// to declare.
    ///
    /// A file-level fact, deliberately. It is not joined onto any item's [`Item::name`] or qualified name,
    /// because a qualified name is an identity and moving the package into one would retire and re-mint
    /// every record in every existing database.
    ///
    /// `None` where the language declares no package, and also where it has the concept and the file wrote
    /// nothing — Kotlin's default package is absent rather than empty, and absent is what a resolver needs
    /// to know to fall back.
    pub package: Option<String>,
    /// Top-level items, in source order.
    pub items: Vec<Item>,
    /// What the file brings in.
    pub imports: Vec<Import>,
}

impl FileAnalysis {
    /// Every item at every depth, depth first.
    pub fn walk(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().flat_map(Item::walk)
    }

    /// How many items of one kind were found, at every depth.
    #[must_use]
    pub fn count(&self, kind: ItemKind) -> usize {
        self.walk().filter(|item| item.kind == kind).count()
    }
}

/// A position a token starts at: line, column, and byte offset.
pub type At = (u32, u32, u64);

/// Builds a range from two positions, falling back rather than panicking.
///
/// A position this analyzer computes is always valid, so the fallback is unreachable in
/// practice. It exists because a library must not panic for an ordinary error, and a
/// structural analyzer runs over source somebody is still editing.
#[must_use]
pub fn range(start: At, end: At) -> SourceRange {
    let position = |(line, column, offset): At| SourcePosition {
        line: line.max(1),
        column: column.max(1),
        offset,
    };
    let (start, end) = if start.2 <= end.2 {
        (start, end)
    } else {
        (end, start)
    };
    SourceRange::new(position(start), position(end)).unwrap_or(SourceRange::ORIGIN)
}

/// A registry holding every analyzer this build ships.
///
/// # Errors
///
/// Returns whatever [`CapabilityRegistry::register`] reports, which can only happen if two
/// analyzers here declared the same language.
pub fn builtin_registry() -> Result<CapabilityRegistry, crate::analysis::CapabilityError> {
    let mut registry = CapabilityRegistry::new();
    registry.register(c::capability_for(c::LANGUAGE))?;
    registry.register(c::capability_for(c::CPP))?;
    registry.register(c::capability_for(c::OBJCPP))?;
    registry.register(go::capability())?;
    registry.register(java::capability())?;
    registry.register(kotlin::capability())?;
    registry.register(python::capability())?;
    registry.register(rust::capability())?;
    registry.register(typescript::capability_for(typescript::LANGUAGE))?;
    registry.register(typescript::capability_for(typescript::JAVASCRIPT))?;
    Ok(registry)
}

/// Analyzes one file, when this build has an analyzer for its language.
///
/// Returns `None` for a language nothing here reads, which is an answer rather than a
/// failure: unsupported text stays eligible for AI analysis.
#[must_use]
pub fn analyze(language: &str, source: &str) -> Option<FileAnalysis> {
    match language {
        "c" | "cpp" | "objcpp" => Some(c::analyze_as(language, source)),
        "go" => Some(go::analyze(source)),
        "java" => Some(java::analyze(source)),
        "kotlin" => Some(kotlin::analyze(source)),
        "python" => Some(python::analyze(source)),
        "rust" => Some(rust::analyze(source)),
        "typescript" | "javascript" => Some(typescript::analyze_as(language, source)),
        _ => None,
    }
}

/// Reports whether this build reads a language deterministically.
#[must_use]
pub fn is_supported(language: &str) -> bool {
    builtin_registry()
        .map(|registry| registry.precision(language).is_deterministic())
        .unwrap_or(false)
}

/// The precision every analyzer here declares.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// Reports whether a capability is one this module could have produced.
#[must_use]
pub fn declares_syntactic(capability: &AnalyzerCapability) -> bool {
    capability.precision == PRECISION
}
