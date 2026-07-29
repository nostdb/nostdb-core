//! Spring's HTTP routes, read from the annotations a language analyzer recorded.
//!
//! # What it reads
//!
//! A class annotated `@RestController` or `@Controller` is a route holder. `@RequestMapping` on the class
//! contributes a prefix; `@GetMapping`, `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`,
//! and `@RequestMapping` on a method each contribute a route.
//!
//! # What it deliberately does not do
//!
//! It does not evaluate a path. `@GetMapping("${api.base}/x")` is recorded as written, because a route
//! this build cannot evaluate is one it must not guess at — the value lives in a properties file, a
//! profile, or an environment variable, and substituting a guess would put a path in the graph that
//! nobody wrote.
//!
//! It does not read `@RequestMapping(method = [...])` to split one declaration into several routes. The
//! method list is recorded as `ANY` when no dedicated mapping annotation names one, because a
//! `DeterministicSyntactic` analyzer reading an argument list would be parsing an expression language it
//! has no grammar for.
//!
//! It does not find routes declared in a router bean, an XML file, or a functional `RouterFunction`.
//! Those are configuration this analyzer does not read, and a project using them gets zero endpoints and
//! an honest capability report rather than a partial list that looks complete.

use super::{Endpoint, Framework, FrameworkCapability, first_string};
use crate::analysis::{FactKind, PrecisionClass};
use crate::analyze::{FileAnalysis, Item, ItemKind};
use crate::text::NonEmptyText;

/// The framework this analyzer reads.
pub const FRAMEWORK: &str = "spring";

/// This analyzer's version, which is part of its identity.
pub const VERSION: &str = "1";

/// How precisely it reads.
///
/// `DeterministicSyntactic`, the same class the language analyzers declare, and for the same reason: it
/// reads what is written and resolves nothing. A path holding a property placeholder is reported as
/// written, and a route declared anywhere other than an annotation is not found at all.
pub const PRECISION: PrecisionClass = PrecisionClass::DeterministicSyntactic;

/// The annotations that mark a class as holding routes.
const HOLDERS: [&str; 2] = ["RestController", "Controller"];

/// Each mapping annotation and the HTTP method it names.
const MAPPINGS: [(&str, &str); 6] = [
    ("GetMapping", "GET"),
    ("PostMapping", "POST"),
    ("PutMapping", "PUT"),
    ("PatchMapping", "PATCH"),
    ("DeleteMapping", "DELETE"),
    // No method of its own. `method = [...]` would name one and reading that list means parsing an
    // expression language this analyzer has no grammar for, so it reports `ANY` rather than guess.
    ("RequestMapping", "ANY"),
];

/// The import prefix that identifies the framework.
const IMPORT_PREFIX: &str = "org.springframework.";

pub(super) struct Spring;

impl Framework for Spring {
    fn capability(&self) -> FrameworkCapability {
        FrameworkCapability {
            framework: NonEmptyText::new(FRAMEWORK)
                .unwrap_or_else(|_| NonEmptyText::literal("spring")),
            precision: PRECISION,
            // `EntryPoint` alone. This analyzer finds routes and nothing else — it does not read
            // injection, transactions, scheduling, or persistence, and declaring facts it does not
            // extract would advertise coverage it has not got.
            facts: vec![FactKind::EntryPoint, FactKind::SourceRange],
            version: NonEmptyText::new(VERSION).unwrap_or_else(|_| NonEmptyText::literal("1")),
        }
    }

    /// Recognised by an import of the framework, or by a route-holding annotation.
    ///
    /// Either, not both. A file may hold a fully qualified `@org.springframework...GetMapping` and no
    /// import, and a file in a project with a wildcard import may carry the annotation with no matching
    /// import line — so requiring both would miss real controllers, and requiring only the import would
    /// claim the framework for every file that mentions it.
    fn recognises(&self, analysis: &FileAnalysis) -> bool {
        if analysis
            .imports
            .iter()
            .any(|held| held.path.starts_with(IMPORT_PREFIX))
        {
            return true;
        }
        analysis.items.iter().flat_map(Item::walk).any(|item| {
            item.annotations
                .iter()
                .any(|held| is_holder(&held.name) || method_for(&held.name).is_some())
        })
    }

    fn interprets(&self) -> &'static [&'static str] {
        const NAMES: [&str; 8] = [
            "RestController",
            "Controller",
            "RequestMapping",
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "PatchMapping",
            "DeleteMapping",
        ];
        &NAMES
    }

    fn endpoints(&self, analysis: &FileAnalysis) -> Vec<Endpoint> {
        let mut found = Vec::new();
        for item in analysis.items.iter().flat_map(Item::walk) {
            if !matches!(item.kind, ItemKind::Struct) {
                continue;
            }
            if !item.annotations.iter().any(|held| is_holder(&held.name)) {
                continue;
            }
            // A class-level `@RequestMapping` is a prefix rather than a route of its own. Emitting it as
            // a route would report an endpoint at the prefix that the application does not serve.
            let prefix = item
                .annotations
                .iter()
                .find(|held| held.name == "RequestMapping")
                .and_then(|held| held.arguments.as_deref())
                .and_then(first_string)
                .unwrap_or_default();

            for member in &item.children {
                if !matches!(member.kind, ItemKind::Method | ItemKind::Function) {
                    continue;
                }
                for annotation in &member.annotations {
                    let Some(method) = method_for(&annotation.name) else {
                        continue;
                    };
                    let own = annotation
                        .arguments
                        .as_deref()
                        .and_then(first_string)
                        .unwrap_or_default();
                    found.push(Endpoint {
                        method: method.to_owned(),
                        path: join(&prefix, &own),
                        handler: member.name.clone(),
                        range: member.range,
                    });
                }
            }
        }
        found
    }
}

fn is_holder(name: &str) -> bool {
    HOLDERS.contains(&name)
}

fn method_for(name: &str) -> Option<&'static str> {
    MAPPINGS
        .iter()
        .find(|(annotation, _)| *annotation == name)
        .map(|(_, method)| *method)
}

/// Joins a class prefix and a method path the way Spring does.
///
/// One `/` between them, and a leading `/` on the result. A prefix of `/api` with a method path of `/x`
/// is `/api/x` and not `/api//x`, and a method with no path of its own serves the prefix itself.
///
/// A path holding a property placeholder is joined unevaluated, so `${base}` stays visible. That is the
/// point: the route in the graph is the route in the source.
fn join(prefix: &str, own: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let own = own.trim_start_matches('/');
    match (prefix.is_empty(), own.is_empty()) {
        (true, true) => "/".to_owned(),
        (true, false) => format!("/{own}"),
        (false, true) => match prefix.starts_with('/') {
            true => prefix.to_owned(),
            false => format!("/{prefix}"),
        },
        (false, false) => match prefix.starts_with('/') {
            true => format!("{prefix}/{own}"),
            false => format!("/{prefix}/{own}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::kotlin;

    fn endpoints(source: &str) -> Vec<(String, String, String)> {
        let analysis = kotlin::analyze(source);
        super::super::analyze(&analysis)
            .endpoints
            .into_iter()
            .map(|held| (held.method, held.path, held.handler))
            .collect()
    }

    fn endpoints_in_java(source: &str) -> Vec<(String, String, String)> {
        let analysis = crate::analyze::java::analyze(source);
        super::super::analyze(&analysis)
            .endpoints
            .into_iter()
            .map(|held| (held.method, held.path, held.handler))
            .collect()
    }

    #[test]
    fn the_same_framework_knowledge_serves_java_without_being_written_twice() {
        // The layer's whole claim, now testable in both directions. Nothing in this file mentions Java:
        // it reads `FileAnalysis`, and a Java analyzer producing the same annotations reaches it. Spring
        // is predominantly Java, so a Kotlin-only reading covered the smaller half of its own ecosystem.
        assert_eq!(
            endpoints_in_java(
                "package com.demo;\n\
                 @RestController\n\
                 @RequestMapping(\"/api\")\n\
                 public class UserController {\n\
                   @GetMapping(\"/users/{id}\")\n\
                   public String find(@PathVariable long id) { return \"\"; }\n\
                   @PostMapping(\"/users\")\n\
                   public void create(@RequestBody User user) { }\n\
                 }\n"
            ),
            [
                (
                    "GET".to_owned(),
                    "/api/users/{id}".to_owned(),
                    "find".to_owned()
                ),
                (
                    "POST".to_owned(),
                    "/api/users".to_owned(),
                    "create".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_java_class_without_a_spring_annotation_yields_nothing() {
        assert!(
            endpoints_in_java("package com.demo;\npublic class Plain { public void run() { } }")
                .is_empty()
        );
    }

    #[test]
    fn a_controller_yields_one_endpoint_per_mapping() {
        // The reported case, end to end from Kotlin source.
        let source = "\
package com.meerdog.api.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TempController {
    @GetMapping(\"/temp\")
    fun temp(): String = \"ok\"

    @GetMapping(\"/api/auth/callback/google\")
    fun googleCallback(): String = \"ok\"
}
";
        assert_eq!(
            endpoints(source),
            [
                ("GET".to_owned(), "/temp".to_owned(), "temp".to_owned()),
                (
                    "GET".to_owned(),
                    "/api/auth/callback/google".to_owned(),
                    "googleCallback".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_class_level_request_mapping_is_a_prefix_and_not_a_route() {
        let source = "\
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(\"/api/auth\")
class AuthController {
    @GetMapping(\"/google\")
    fun google(): String = \"\"

    @PostMapping
    fun callback(): String = \"\"
}
";
        assert_eq!(
            endpoints(source),
            [
                (
                    "GET".to_owned(),
                    "/api/auth/google".to_owned(),
                    "google".to_owned()
                ),
                // No path of its own, so it serves the prefix. The prefix is not itself an endpoint.
                (
                    "POST".to_owned(),
                    "/api/auth".to_owned(),
                    "callback".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn every_mapping_annotation_names_its_method() {
        for (annotation, method) in MAPPINGS {
            let source = format!(
                "import org.springframework.web.bind.annotation.RestController\n\
                 @RestController\nclass C {{\n    @{annotation}(\"/x\")\n    fun f() {{}}\n}}\n"
            );
            assert_eq!(
                endpoints(&source),
                [(method.to_owned(), "/x".to_owned(), "f".to_owned())],
                "{annotation}"
            );
        }
    }

    #[test]
    fn a_class_that_is_not_a_controller_yields_nothing() {
        // A mapping annotation outside a route holder is not a route. Spring does not serve it, and
        // reporting it would put an endpoint in the graph the application does not answer.
        let source = "\
import org.springframework.stereotype.Service

@Service
class NotAController {
    @GetMapping(\"/x\")
    fun f() {}
}
";
        assert!(endpoints(source).is_empty(), "{:?}", endpoints(source));
    }

    #[test]
    fn a_path_with_a_placeholder_is_reported_as_written() {
        // The value lives in a properties file this analyzer does not read. Substituting a guess would
        // put a path in the graph nobody wrote.
        let source = "\
import org.springframework.web.bind.annotation.RestController

@RestController
class C {
    @GetMapping(\"\\${api.base}/x\")
    fun f() {}
}
";
        let found = endpoints(source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].1.contains("api.base"), "{:?}", found[0].1);
    }

    #[test]
    fn a_request_mapping_with_no_dedicated_method_reports_any() {
        let source = "\
import org.springframework.web.bind.annotation.RestController

@RestController
class C {
    @RequestMapping(value = [\"/x\"], method = [RequestMethod.GET])
    fun f() {}
}
";
        // `ANY` rather than `GET`. Reading the method list means parsing an expression language this
        // analyzer has no grammar for, and reporting `GET` from a list it did not parse would be a claim
        // it cannot support.
        assert_eq!(
            endpoints(source),
            [("ANY".to_owned(), "/x".to_owned(), "f".to_owned())]
        );
    }

    #[test]
    fn a_controller_with_no_mapping_is_recognised_and_yields_nothing() {
        let source = "\
import org.springframework.web.bind.annotation.RestController

@RestController
class Empty
";
        let found = super::super::analyze(&kotlin::analyze(source));
        assert!(found.frameworks.contains("spring"), "recognised");
        assert!(found.endpoints.is_empty(), "and honest about finding none");
    }

    #[test]
    fn a_fully_qualified_annotation_with_no_import_is_still_recognised() {
        let source = "\
@org.springframework.web.bind.annotation.RestController
class C {
    @org.springframework.web.bind.annotation.GetMapping(\"/x\")
    fun f() {}
}
";
        assert_eq!(
            endpoints(source),
            [("GET".to_owned(), "/x".to_owned(), "f".to_owned())],
            "the language analyzer keeps the last segment, so the qualifier does not hide it"
        );
    }

    #[test]
    fn the_declared_capability_says_what_it_extracts_and_what_it_does_not() {
        let declared = Spring.capability();
        assert_eq!(declared.framework.as_str(), FRAMEWORK);
        assert_eq!(declared.version.as_str(), VERSION);
        assert_eq!(declared.precision, PrecisionClass::DeterministicSyntactic);
        assert!(declared.facts.contains(&FactKind::EntryPoint));
        // Not claimed: this analyzer reads routes and nothing else.
        for absent in [FactKind::Call, FactKind::PackageDependency, FactKind::Field] {
            assert!(
                !declared.facts.contains(&absent),
                "{absent} is not extracted"
            );
        }
    }

    #[test]
    fn a_prefix_and_a_path_join_the_way_spring_joins_them() {
        assert_eq!(join("/api", "/x"), "/api/x");
        assert_eq!(join("/api/", "x"), "/api/x");
        assert_eq!(join("api", "x"), "/api/x", "a leading slash is added");
        assert_eq!(join("", "/x"), "/x");
        assert_eq!(
            join("/api", ""),
            "/api",
            "no path of its own serves the prefix"
        );
        assert_eq!(join("", ""), "/", "a controller at the root");
    }
}
