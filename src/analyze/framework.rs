//! Framework analysis: what a language's declarations mean to a framework.
//!
//! # Why this is a layer rather than more of each language analyzer
//!
//! A route is not a language fact. `@GetMapping` means nothing to Kotlin — it is an annotation like any
//! other — and it means something specific to Spring. Putting Spring knowledge into the Kotlin analyzer
//! would make a Spring change a Kotlin change, and the same framework reached from Java would need the
//! knowledge written a second time.
//!
//! So a framework analyzer consumes what a language analyzer produced. The language layer says what the
//! source declares; this layer says what those declarations mean to a framework. Each declares its own
//! capability.
//!
//! A framework analyzer still names a version, unlike a language analyzer, which declares none: its
//! evidence is what tells a reader that a route was found by `spring/1` rather than by a later reader with
//! wider coverage, and a framework's own precision is its own.
//!
//! # What happens when no analyzer covers a framework
//!
//! `docs/PRD.md` section 17.3 makes unsupported text eligible for AI analysis with an explicit
//! capability diagnostic, and the same rule applies here. A file carrying annotations that no registered
//! analyzer interprets is reported — by the **annotation names**, not by a framework name.
//!
//! That distinction is deliberate. Naming the framework would require a list of frameworks this build
//! knows of but cannot read, which is a closed allowlist by another route and exactly what section 4
//! forbids. What this build can say honestly is which annotations it saw and did not interpret, which is
//! evidence rather than a guess — and it is what makes the AI fallback well posed: those are the units
//! worth enriching, and the diagnostic names why.

use super::{Annotation, FileAnalysis, Item};
use crate::analysis::{FactKind, PrecisionClass};
use crate::evidence::SourceRange;
use crate::text::NonEmptyText;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub mod react;
pub mod spring;

/// What one framework analyzer declares.
///
/// The same shape as [`crate::analysis::AnalyzerCapability`] with a framework in place of a language,
/// and separate from it on purpose: a registry that held both would let a caller ask "what is the
/// precision for `kotlin`" and get an answer that mixed a language analyzer's with a framework's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameworkCapability {
    /// The framework, as a free string. There is no closed list.
    pub framework: NonEmptyText,
    /// How precisely this analyzer works.
    pub precision: PrecisionClass,
    /// What it extracts.
    pub facts: Vec<FactKind>,
    /// Analyzer version, which is part of its identity.
    pub version: NonEmptyText,
}

/// One entry point a framework analyzer found.
///
/// `docs/PRD.md` section 17.4 lists "configuration-defined entry points" among what a deterministic
/// analyzer should extract, and [`FactKind::EntryPoint`] has carried that name since. This is the first
/// thing to produce one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The HTTP method, upper-case, or `ANY` when the framework's declaration names none.
    pub method: String,
    /// The path, exactly as the source declares it.
    ///
    /// Not normalised, and not resolved. A path built by interpolation stays as written: a route this
    /// build cannot evaluate is one it must not guess at, and reporting `${base}/x` says what the source
    /// says while reporting `/x` would be a claim nobody made.
    pub path: String,
    /// The declaration it is written on, by name.
    pub handler: String,
    /// Where the declaration is.
    pub range: SourceRange,
}

/// One user-interface component a framework analyzer found.
///
/// Separate from [`Endpoint`] because the two are reached differently: an entry point is reached by an HTTP
/// request from outside the program, and a component is rendered by something else inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// The declaration's name, which is also the component's.
    pub name: String,
    /// How the analyzer recognised it, which is what a reader needs to judge the fact.
    ///
    /// Carried per component rather than taken from the analyzer's declared precision, because one
    /// analyzer may know some of them exactly and others by convention. A class extending `Component` says
    /// what it is; a capitalised function is a convention that a helper called `Wrapper` also satisfies.
    pub recognised_by: Recognition,
    /// Where the declaration is.
    pub range: SourceRange,
}

/// How certainly a component was recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    /// The source states it: a supertype, a decorator, or a call the framework defines.
    Declared,
    /// A naming or shape convention the framework's community follows, which a non-component may satisfy.
    Convention,
}

impl fmt::Display for Recognition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Declared => "declared",
            Self::Convention => "convention",
        })
    }
}

/// What framework analysis found in one file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameworkAnalysis {
    /// The frameworks whose analyzers recognised this file, in name order.
    pub frameworks: BTreeSet<String>,
    /// Entry points, in source order.
    pub endpoints: Vec<Endpoint>,
    /// User-interface components, in source order.
    pub components: Vec<Component>,
    /// Annotations no registered analyzer interpreted, by name, in name order.
    ///
    /// The capability diagnostic's evidence. An annotation here is not an error: most annotations mean
    /// nothing to any framework, and a file full of `@Deprecated` is not a file anything failed on.
    /// What it supports is the honest statement that this build saw something it did not read, which is
    /// what makes a unit worth sending to a model rather than a unit nobody mentioned.
    pub uninterpreted: BTreeSet<String>,
}

impl FrameworkAnalysis {
    /// Reports whether anything at all was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frameworks.is_empty()
            && self.endpoints.is_empty()
            && self.components.is_empty()
            && self.uninterpreted.is_empty()
    }
}

/// A framework analyzer.
trait Framework {
    /// What it declares.
    fn capability(&self) -> FrameworkCapability;

    /// Whether this file uses the framework.
    ///
    /// Decided from the file rather than from the project, because a repository may use a framework in
    /// one module and not another, and claiming a framework for a file that does not use it would put
    /// its declarations under a heading nobody chose.
    fn recognises(&self, analysis: &FileAnalysis) -> bool;

    /// Every annotation name this analyzer interprets.
    ///
    /// Used to decide what went uninterpreted. Declared rather than inferred from what it happened to
    /// read: an analyzer that recognised a file and then found nothing in it would otherwise report
    /// every annotation as uninterpreted, including its own.
    fn interprets(&self) -> &'static [&'static str];

    /// The entry points in one file.
    fn endpoints(&self, analysis: &FileAnalysis) -> Vec<Endpoint>;

    /// The user-interface components in one file.
    ///
    /// Defaulted to none, because most frameworks have no such concept and an analyzer should not have to
    /// say so. A route holder is not a component and a component is not an entry point: one is reached by
    /// an HTTP request, the other is rendered by something else in the same program.
    fn components(&self, _analysis: &FileAnalysis) -> Vec<Component> {
        Vec::new()
    }
}

/// Every framework analyzer this build ships.
fn analyzers() -> Vec<Box<dyn Framework>> {
    vec![Box::new(react::React), Box::new(spring::Spring)]
}

/// What every framework analyzer this build ships declares, by framework name.
#[must_use]
pub fn capabilities() -> BTreeMap<String, FrameworkCapability> {
    analyzers()
        .into_iter()
        .map(|analyzer| {
            let declared = analyzer.capability();
            (declared.framework.as_str().to_owned(), declared)
        })
        .collect()
}

/// Analyzes one file's declarations for every framework that recognises it.
///
/// Never fails. A framework analyzer reads what a language analyzer already produced, so there is no
/// source left to be malformed — the worst case is a declaration it does not recognise, which is the
/// ordinary case and is reported as such.
#[must_use]
pub fn analyze(analysis: &FileAnalysis) -> FrameworkAnalysis {
    let mut found = FrameworkAnalysis::default();
    let mut interpreted: BTreeSet<&str> = BTreeSet::new();

    for analyzer in analyzers() {
        if !analyzer.recognises(analysis) {
            continue;
        }
        found
            .frameworks
            .insert(analyzer.capability().framework.as_str().to_owned());
        interpreted.extend(analyzer.interprets().iter().copied());
        found.endpoints.extend(analyzer.endpoints(analysis));
        found.components.extend(analyzer.components(analysis));
    }

    // Every annotation in the file, minus what a recognising analyzer says it interprets.
    for annotation in every_annotation(&analysis.items) {
        if !interpreted.contains(annotation.name.as_str()) {
            found.uninterpreted.insert(annotation.name.clone());
        }
    }
    found
}

/// Every annotation on every item at every depth.
fn every_annotation(items: &[Item]) -> Vec<&Annotation> {
    items
        .iter()
        .flat_map(Item::walk)
        .flat_map(|item| item.annotations.iter())
        .collect()
}

/// The first string argument in an annotation's argument text, when there is one.
///
/// The argument text is what the language analyzer recorded verbatim, with string literals quoted. So
/// `"/api/x"` yields `/api/x`, and `value = [ "/api/x" ]` yields the same — which is why this reads the
/// first quoted run rather than trying to parse an argument list. Kotlin, Java, and every other language
/// that carries annotations writes that list differently, and a framework's own meaning does not depend
/// on which.
#[must_use]
pub fn first_string(arguments: &str) -> Option<String> {
    let mut characters = arguments.chars();
    while let Some(character) = characters.next() {
        if character != '"' {
            continue;
        }
        let mut content = String::new();
        for inside in characters.by_ref() {
            if inside == '"' {
                return Some(content);
            }
            content.push(inside);
        }
        return Some(content);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::ItemKind;

    fn annotated(name: &str, arguments: Option<&str>) -> Annotation {
        Annotation {
            name: name.to_owned(),
            arguments: arguments.map(str::to_owned),
            range: SourceRange::ORIGIN,
        }
    }

    fn file(items: Vec<Item>, imports: Vec<&str>) -> FileAnalysis {
        FileAnalysis {
            language: "kotlin".to_owned(),
            digest: crate::sync::digest_bytes(b""),
            // A framework analyzer reads declarations and annotations. It is handed no path and asks for no
            // package, so what these tests set here would change nothing.
            package: None,
            items,
            imports: imports
                .into_iter()
                .map(|path| crate::analyze::Import {
                    path: path.to_owned(),
                    alias: None,
                    range: SourceRange::ORIGIN,
                })
                .collect(),
        }
    }

    fn item(kind: ItemKind, name: &str, annotations: Vec<Annotation>) -> Item {
        let mut held = Item::new(kind, name, SourceRange::ORIGIN);
        held.annotations = annotations;
        held
    }

    #[test]
    fn a_file_no_analyzer_recognises_reports_its_annotations_as_uninterpreted() {
        // Not as a framework. Naming one would need a list of frameworks this build knows of and cannot
        // read, which is a closed allowlist by another route.
        let found = analyze(&file(
            vec![item(
                ItemKind::Struct,
                "Widget",
                vec![annotated("Entity", None), annotated("Table", Some("\"t\""))],
            )],
            vec!["javax.persistence.Entity"],
        ));
        assert!(found.frameworks.is_empty());
        assert!(found.endpoints.is_empty());
        assert_eq!(
            found
                .uninterpreted
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["Entity", "Table"]
        );
    }

    #[test]
    fn a_file_with_no_annotations_reports_nothing_at_all() {
        let found = analyze(&file(
            vec![item(ItemKind::Function, "main", Vec::new())],
            Vec::new(),
        ));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_annotation_a_recognising_analyzer_interprets_is_not_uninterpreted() {
        let found = analyze(&file(
            vec![item(
                ItemKind::Struct,
                "Controller",
                vec![
                    annotated("RestController", None),
                    annotated("Deprecated", None),
                ],
            )],
            vec!["org.springframework.web.bind.annotation.RestController"],
        ));
        assert!(found.frameworks.contains("spring"));
        // `RestController` is interpreted; `Deprecated` is not, and saying so is honest rather than an
        // error — most annotations mean nothing to any framework.
        assert_eq!(
            found
                .uninterpreted
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["Deprecated"]
        );
    }

    #[test]
    fn the_first_string_is_read_out_of_an_argument_list_however_it_was_written() {
        assert_eq!(first_string("\"/api/x\"").as_deref(), Some("/api/x"));
        assert_eq!(
            first_string("value = [ \"/api/x\" ] , method = [ RequestMethod . GET ]").as_deref(),
            Some("/api/x")
        );
        assert_eq!(first_string("").as_deref(), None);
        assert_eq!(first_string("RequestMethod . GET").as_deref(), None);
        // An unterminated quote yields what there was rather than nothing, because a file being edited
        // is the common case and refusing it would lose the route that is there.
        assert_eq!(first_string("\"/api").as_deref(), Some("/api"));
    }

    #[test]
    fn every_shipped_analyzer_declares_a_framework_and_a_version() {
        let declared = capabilities();
        assert!(
            !declared.is_empty(),
            "this build ships no framework analyzer"
        );
        for (name, capability) in &declared {
            assert_eq!(capability.framework.as_str(), name);
            assert!(!capability.version.as_str().is_empty());
            assert!(
                !capability.facts.is_empty(),
                "{name} declares no fact, so nothing knows what it is for"
            );
        }
    }
}
