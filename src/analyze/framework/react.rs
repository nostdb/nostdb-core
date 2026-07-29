//! React's components, read from the declarations a language analyzer recorded.
//!
//! # Why this analyzer is `Heuristic` and Spring's is not
//!
//! A Spring route is written down: `@GetMapping("/x")` says what it is and where it goes, and reading it
//! resolves nothing. A React component is mostly a **convention** — a function whose name is capitalised
//! and which returns markup. Nothing in the language says so, and `Wrapper`, `Fragment`, and `Layout` are
//! all names a helper might have.
//!
//! So the capability declares [`PrecisionClass::Heuristic`]: "pattern-based, so a fact may be wrong in ways
//! the analyzer cannot detect". That is the honest class, and root `docs/PRD.md` section 17.3 requires it to
//! travel with the facts rather than being implied away.
//!
//! Two cases are better than that, and each component says which it was:
//!
//! - a class extending `Component` or `PureComponent` is **declared**: the source states it;
//! - a capitalised function or arrow binding is **convention**.
//!
//! Recognition is carried per component rather than taken from the analyzer's class, because one analyzer
//! knowing some facts exactly and others by convention is the ordinary case, and collapsing them would make
//! the exact ones look like guesses.
//!
//! # What it deliberately does not do
//!
//! It does not read a `.vue`, `.svelte`, or `.astro` single-file component. Those are their own grammars
//! with a template section this build has no reader for, so a project using them gets no components and an
//! honest capability report rather than a partial list that looks complete.
//!
//! It does not decide that a function returns markup. JSX is read as punctuation by
//! [`crate::analyze::typescript_lexer`], for reasons that file documents, so "returns an element" is not a
//! fact available here. Claiming it from a `<` in a body would misread a comparison.

use super::{Component, Endpoint, Framework, FrameworkCapability, Recognition};
use crate::analysis::{FactKind, PrecisionClass};
use crate::analyze::{FileAnalysis, Item, ItemKind};
use crate::text::NonEmptyText;

/// The framework this analyzer reads.
pub const FRAMEWORK: &str = "react";

/// This analyzer's version, which is part of its identity.
pub const VERSION: &str = "1";

/// How precisely it reads.
///
/// `Heuristic`, unlike every other analyzer in this module. A capitalised function is a convention rather
/// than a declaration, and a reader has to be told that before trusting a count of components.
pub const PRECISION: PrecisionClass = PrecisionClass::Heuristic;

/// The module specifiers that identify the framework.
const IMPORT_PREFIXES: [&str; 3] = ["react", "react-dom", "next/"];

/// The base classes a class component extends.
const BASES: [&str; 2] = ["Component", "PureComponent"];

pub(super) struct React;

impl Framework for React {
    fn capability(&self) -> FrameworkCapability {
        FrameworkCapability {
            framework: NonEmptyText::new(FRAMEWORK)
                .unwrap_or_else(|_| NonEmptyText::literal("react")),
            precision: PRECISION,
            // `Class` and `Declaration`. It finds components and nothing else — no routes, no data
            // fetching, no state — and declaring `EntryPoint` would claim the thing Spring produces.
            facts: vec![
                FactKind::Class,
                FactKind::Declaration,
                FactKind::SourceRange,
            ],
            version: NonEmptyText::new(VERSION).unwrap_or_else(|_| NonEmptyText::literal("1")),
        }
    }

    /// Recognised by an import of the framework.
    ///
    /// The import only, unlike Spring's, which also accepts a route annotation. There is no annotation here
    /// to accept: without the import, the signal would be "this file declares a capitalised function",
    /// which every file in every language does.
    fn recognises(&self, analysis: &FileAnalysis) -> bool {
        analysis.imports.iter().any(|held| {
            IMPORT_PREFIXES
                .iter()
                .any(|prefix| held.path == *prefix || held.path.starts_with(prefix))
        })
    }

    /// None. React's meaning is not written in annotations, so nothing here is claimed as interpreted.
    ///
    /// A decorator in a React file is therefore reported uninterpreted, which is correct: this analyzer did
    /// not read it, and something else — a state library, a compiler plugin — put it there.
    fn interprets(&self) -> &'static [&'static str] {
        &[]
    }

    fn endpoints(&self, _analysis: &FileAnalysis) -> Vec<Endpoint> {
        Vec::new()
    }

    fn components(&self, analysis: &FileAnalysis) -> Vec<Component> {
        let mut found = Vec::new();
        for item in &analysis.items {
            let Some(recognised_by) = recognition_of(item) else {
                continue;
            };
            found.push(Component {
                name: item.name.clone(),
                recognised_by,
                range: item.range,
            });
        }
        found
    }
}

/// How a declaration is recognised as a component, when it is one.
///
/// Only a file-scope declaration is considered. A method inside a class is not a component, and a
/// capitalised name nested inside a function is a local helper.
fn recognition_of(item: &Item) -> Option<Recognition> {
    match item.kind {
        // `class Card extends React.Component` states what it is.
        ItemKind::Struct
            if item
                .references
                .iter()
                .any(|held| BASES.contains(&held.name.as_str())) =>
        {
            Some(Recognition::Declared)
        }
        // A capitalised function, or a capitalised binding holding one. The convention, and no more.
        ItemKind::Function | ItemKind::Constant if is_capitalised(&item.name) => {
            Some(Recognition::Convention)
        }
        _ => None,
    }
}

/// Reports whether a name follows the capitalised convention a component is written with.
///
/// The first character being upper-case is the whole rule, and it is also the rule JSX itself uses to tell a
/// component from an HTML tag — `<Card />` is a component and `<div />` is not. So this is the convention the
/// framework enforces rather than one this analyzer invented, which is why it is worth reading at all.
///
/// A name of `SCREAMING_CASE` is excluded: it is a constant by every convention in the language, and
/// `MAX_RETRIES` is not a component.
fn is_capitalised(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_uppercase() && characters.any(char::is_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::typescript;

    fn components(source: &str) -> Vec<(String, Recognition)> {
        let analysis = typescript::analyze_as(typescript::LANGUAGE, source);
        super::super::analyze(&analysis)
            .components
            .into_iter()
            .map(|held| (held.name, held.recognised_by))
            .collect()
    }

    #[test]
    fn a_capitalised_function_in_a_react_file_is_a_component_by_convention() {
        assert_eq!(
            components(
                "import React from \"react\";\n\
                 export function Card() { return null; }\n\
                 export const Panel = () => null;\n"
            ),
            [
                ("Card".to_owned(), Recognition::Convention),
                ("Panel".to_owned(), Recognition::Convention),
            ]
        );
    }

    #[test]
    fn a_class_extending_component_is_declared_rather_than_conventional() {
        // The source states it, so the fact is not a guess even though the analyzer's class is heuristic.
        assert_eq!(
            components(
                "import React from \"react\";\n\
                 export class Widget extends React.Component { render() { return null; } }\n"
            ),
            [("Widget".to_owned(), Recognition::Declared)]
        );
    }

    #[test]
    fn a_lowercase_declaration_is_not_a_component() {
        // The convention JSX itself enforces: `<Card />` is a component and `<div />` is a tag.
        assert!(
            components(
                "import React from \"react\";\n\
                 export function helper() { return 1; }\n\
                 const value = 2;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_screaming_case_constant_is_not_a_component() {
        assert!(
            components("import React from \"react\";\nexport const MAX_RETRIES = 3;\n").is_empty()
        );
    }

    #[test]
    fn a_file_that_does_not_import_react_yields_nothing() {
        // Without the import the signal would be "this file declares a capitalised function", which every
        // file in every language does.
        assert!(components("export function Card() { return null; }\n").is_empty());
    }

    #[test]
    fn a_framework_adjacent_import_still_recognises_the_file() {
        assert_eq!(
            components("import { useState } from \"react-dom\";\nexport function Card() {}\n"),
            [("Card".to_owned(), Recognition::Convention)]
        );
        assert_eq!(
            components("import Head from \"next/head\";\nexport function Page() {}\n"),
            [("Page".to_owned(), Recognition::Convention)]
        );
    }

    #[test]
    fn a_method_or_a_nested_declaration_is_not_a_component() {
        // Only a file-scope declaration is considered: a capitalised name inside a function is a helper.
        assert_eq!(
            components(
                "import React from \"react\";\n\
                 export class Holder extends Base {\n\
                 \x20 Render() { return null; }\n\
                 }\n"
            ),
            [],
            "neither the class, which extends something else, nor its method"
        );
    }

    #[test]
    fn the_declared_capability_says_what_it_extracts_and_what_it_does_not() {
        let declared = React.capability();
        assert_eq!(declared.framework.as_str(), "react");
        assert_eq!(
            declared.precision,
            PrecisionClass::Heuristic,
            "a convention is not a declaration, and a reader has to be told"
        );
        assert!(declared.facts.contains(&FactKind::Class));
        // Spring produces entry points; this produces none, and claiming one would advertise routes it
        // never reads.
        assert!(!declared.facts.contains(&FactKind::EntryPoint));
    }

    #[test]
    fn a_decorator_in_a_react_file_is_reported_uninterpreted() {
        // Nothing here interprets an annotation, so one is honestly reported as unread — something else put
        // it there.
        let analysis = typescript::analyze_as(
            typescript::LANGUAGE,
            "import React from \"react\";\n@observer\nexport class Store extends React.Component {}\n",
        );
        let found = super::super::analyze(&analysis);
        assert!(found.frameworks.contains("react"));
        assert!(found.uninterpreted.contains("observer"), "{found:?}");
    }
}
