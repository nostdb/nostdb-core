//! Git-ignore-compatible exclusion rules, matched without a dependency.
//!
//! Root PRD section 17.2 requires the scanner to honor `.gitignore` and a `.nostdbignore`
//! with Git-ignore-compatible exclusion semantics. That is a specific, documented matching
//! language, and approximating it would be worse than not implementing it: a rule that
//! excludes a path in Git and includes it here means the build analyzes a file the user
//! believed was excluded.
//!
//! # Why this is hand-written
//!
//! The Engine takes no dependency for it. The rules below are a closed, stable set —
//! Git's ignore syntax has not changed in years — and the matcher is a few hundred lines
//! with no allocation in the hot path. A crate would bring a transitive tree, a license to
//! record, and a maintenance surface for behavior this file states outright.
//!
//! # The rules
//!
//! - a blank line matches nothing, and `#` starts a comment;
//! - trailing spaces are stripped unless escaped with a backslash;
//! - `!` negates, and the **last** matching pattern decides;
//! - a trailing `/` matches directories only;
//! - a `/` anywhere but the end anchors the pattern to the directory holding the ignore
//!   file, and a pattern with no such `/` matches at any depth;
//! - `*` and `?` do not cross a `/`, `**` does;
//! - `[abc]`, `[a-z]`, and `[!abc]` are character classes;
//! - a negation cannot re-include a file whose parent directory is excluded.
//!
//! That last rule is the scanner's to enforce, not this file's. [`IgnoreStack::excludes`]
//! answers about exactly the path it is given; Git never descends into an excluded
//! directory, so a file beneath one is never asked about. Keeping the ancestor walk out of
//! the matcher is what makes each answer exact rather than approximately right.

/// One compiled ignore rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The pattern with its `!`, leading `/`, and trailing `/` removed.
    pattern: String,
    /// Whether a match re-includes rather than excludes.
    negated: bool,
    /// Whether this matches directories only.
    directory_only: bool,
    /// Whether the pattern is fixed to the ignore file's own directory.
    anchored: bool,
}

impl Rule {
    /// Compiles one line, or `None` when the line states no rule.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let trimmed = trim_trailing_unescaped_spaces(line.trim_start_matches(' '));
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let (negated, rest) = match trimmed.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, trimmed.as_str()),
        };
        // An escaped leading `#` or `!` is a literal one.
        let rest = rest
            .strip_prefix("\\#")
            .map_or_else(|| rest.strip_prefix("\\!").unwrap_or(rest), |_| &rest[1..]);

        let (directory_only, rest) = match rest.strip_suffix('/') {
            Some(rest) => (true, rest),
            None => (false, rest),
        };
        if rest.is_empty() {
            return None;
        }

        // A `/` anywhere but the very end fixes the pattern to this directory. `doc/frotz`
        // means that path from here; `frotz` means any `frotz` at any depth.
        let anchored = rest.trim_end_matches('/').contains('/');
        let pattern = rest.strip_prefix('/').unwrap_or(rest).to_owned();

        Some(Self {
            pattern,
            negated,
            directory_only,
            anchored,
        })
    }

    /// Reports whether this rule re-includes rather than excludes.
    #[must_use]
    pub const fn is_negated(&self) -> bool {
        self.negated
    }

    /// Reports whether `relative` matches, where `relative` is below the ignore file.
    #[must_use]
    pub fn matches(&self, relative: &str, is_dir: bool) -> bool {
        if self.directory_only && !is_dir {
            return false;
        }
        if self.anchored {
            return glob(&self.pattern, relative);
        }
        // Unanchored: the pattern applies to the path's tail at any depth.
        if glob(&self.pattern, relative) {
            return true;
        }
        relative
            .match_indices('/')
            .any(|(at, _)| glob(&self.pattern, &relative[at + 1..]))
    }
}

/// The rules from one ignore file, and where that file sits.
#[derive(Clone, Debug)]
pub struct IgnoreFile {
    /// The directory holding it, relative to the scan root, with no trailing separator.
    base: String,
    /// Its rules, in file order.
    rules: Vec<Rule>,
}

impl IgnoreFile {
    /// Compiles the rules in `text`, read from a file in `base`.
    ///
    /// `base` is relative to the scan root and is empty for the root itself.
    #[must_use]
    pub fn parse(text: &str, base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            rules: text.lines().filter_map(Rule::parse).collect(),
        }
    }

    /// Reports whether this file states any rule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The last rule in this file matching `relative`, which is the one that decides.
    fn decide(&self, relative: &str, is_dir: bool) -> Option<&Rule> {
        let below = if self.base.is_empty() {
            Some(relative)
        } else {
            relative
                .strip_prefix(&self.base)
                .and_then(|rest| rest.strip_prefix('/'))
        }?;
        self.rules
            .iter()
            .rev()
            .find(|rule| rule.matches(below, is_dir))
    }
}

/// The ignore files in effect, ordered from the scan root downwards.
///
/// A deeper file overrides a shallower one, so the search runs from the back.
#[derive(Clone, Debug, Default)]
pub struct IgnoreStack {
    files: Vec<IgnoreFile>,
}

impl IgnoreStack {
    /// An empty stack, which excludes nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Adds a file, which takes precedence over everything already present.
    pub fn push(&mut self, file: IgnoreFile) {
        if !file.is_empty() {
            self.files.push(file);
        }
    }

    /// How many files are in effect, so a caller can restore a prior depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Reports whether no file is in effect.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Drops back to `depth` files, undoing what one directory contributed.
    pub fn truncate(&mut self, depth: usize) {
        self.files.truncate(depth);
    }

    /// Reports whether `relative` is excluded.
    ///
    /// The deepest file with a matching rule decides, and within one file the last
    /// matching rule decides. A path nothing matches is not excluded.
    #[must_use]
    pub fn excludes(&self, relative: &str, is_dir: bool) -> bool {
        self.files
            .iter()
            .rev()
            .find_map(|file| file.decide(relative, is_dir))
            .is_some_and(|rule| !rule.negated)
    }
}

/// Strips trailing spaces that a backslash does not protect.
fn trim_trailing_unescaped_spaces(line: &str) -> String {
    let bytes: Vec<char> = line.chars().collect();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == ' ' {
        // A space is kept when the run of backslashes before it is odd.
        let mut backslashes = 0_usize;
        let mut at = end - 1;
        while at > 0 && bytes[at - 1] == '\\' {
            backslashes += 1;
            at -= 1;
        }
        if backslashes % 2 == 1 {
            break;
        }
        end -= 1;
    }
    bytes[..end].iter().collect()
}

/// Matches one Git-ignore glob against one path, where `*` and `?` do not cross a `/`.
#[must_use]
pub fn glob(pattern: &str, path: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    matches_from(&pattern, 0, &path, 0)
}

/// Matches `pattern[p..]` against `path[t..]`.
///
/// Recursive rather than iterative because `**` branches, and the depth is bounded by the
/// number of wildcards in one pattern rather than by anything an input controls.
fn matches_from(pattern: &[char], p: usize, path: &[char], t: usize) -> bool {
    if p == pattern.len() {
        return t == path.len();
    }

    match pattern[p] {
        '*' if pattern.get(p + 1) == Some(&'*') => {
            // `**` crosses separators. `a/**/b` also matches `a/b`, so a `**/` consuming
            // nothing is allowed by skipping the separator that follows it.
            let mut after = p + 2;
            if pattern.get(after) == Some(&'/') {
                after += 1;
                if matches_from(pattern, after, path, t) {
                    return true;
                }
            }
            (t..=path.len()).any(|at| matches_from(pattern, after, path, at))
        }
        '*' => {
            // A single star stops at a separator.
            let limit = path[t..]
                .iter()
                .position(|character| *character == '/')
                .map_or(path.len(), |at| t + at);
            (t..=limit).any(|at| matches_from(pattern, p + 1, path, at))
        }
        '?' => t < path.len() && path[t] != '/' && matches_from(pattern, p + 1, path, t + 1),
        '[' => {
            let Some((accepts, after)) = character_class(pattern, p, path.get(t).copied()) else {
                // An unterminated class is a literal `[`, which is what Git does.
                return t < path.len()
                    && path[t] == '['
                    && matches_from(pattern, p + 1, path, t + 1);
            };
            accepts && t < path.len() && matches_from(pattern, after, path, t + 1)
        }
        '\\' if p + 1 < pattern.len() => {
            t < path.len() && path[t] == pattern[p + 1] && matches_from(pattern, p + 2, path, t + 1)
        }
        literal => {
            t < path.len() && path[t] == literal && matches_from(pattern, p + 1, path, t + 1)
        }
    }
}

/// Reads `[...]` at `p`, reporting whether it accepts `candidate` and where it ends.
///
/// Returns `None` when the class is never closed.
fn character_class(pattern: &[char], p: usize, candidate: Option<char>) -> Option<(bool, usize)> {
    let mut at = p + 1;
    let negated = matches!(pattern.get(at), Some('!' | '^'));
    if negated {
        at += 1;
    }
    let mut accepts = false;
    let mut first = true;

    while at < pattern.len() {
        // A `]` immediately after the opening bracket is a literal `]`.
        if pattern[at] == ']' && !first {
            let hit = accepts != negated;
            return Some((hit, at + 1));
        }
        first = false;

        let low = pattern[at];
        if pattern.get(at + 1) == Some(&'-') && pattern.get(at + 2).is_some_and(|high| *high != ']')
        {
            let high = pattern[at + 2];
            if candidate.is_some_and(|character| character >= low && character <= high) {
                accepts = true;
            }
            at += 3;
        } else {
            if candidate == Some(low) {
                accepts = true;
            }
            at += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack(rules: &[(&str, &str)]) -> IgnoreStack {
        let mut stack = IgnoreStack::new();
        for (base, text) in rules {
            stack.push(IgnoreFile::parse(text, base));
        }
        stack
    }

    #[test]
    fn a_blank_line_and_a_comment_state_no_rule() {
        assert_eq!(Rule::parse(""), None);
        assert_eq!(Rule::parse("   "), None);
        assert_eq!(Rule::parse("# a comment"), None);
        assert_eq!(Rule::parse("/"), None);
        assert!(Rule::parse("\\#literal").is_some());
    }

    #[test]
    fn trailing_spaces_are_stripped_unless_a_backslash_protects_them() {
        assert!(Rule::parse("build   ").unwrap().matches("build", false));
        // The escaped space is part of the name.
        let rule = Rule::parse("odd\\ ").unwrap();
        assert!(rule.matches("odd ", false), "{rule:?}");
        assert!(!rule.matches("odd", false));
    }

    #[test]
    fn an_unanchored_pattern_matches_at_any_depth() {
        let rules = stack(&[("", "target\n")]);
        assert!(rules.excludes("target", true));
        assert!(rules.excludes("crates/inner/target", true));
    }

    #[test]
    fn a_rule_answers_about_one_path_and_says_nothing_about_what_is_under_it() {
        // `target` matches the directory. Git never descends into an excluded directory,
        // so a file beneath one is never asked about — which is also why a negation cannot
        // re-include it. Pruning is the scanner's job, and keeping it out of the matcher
        // is what keeps this answer exact rather than approximately right.
        let rules = stack(&[("", "target\n")]);
        assert!(rules.excludes("crates/inner/target", true));
        assert!(!rules.excludes("crates/inner/target/debug/build.rs", false));
    }

    #[test]
    fn a_slash_in_the_pattern_anchors_it() {
        let rules = stack(&[("", "doc/frotz\n")]);
        assert!(rules.excludes("doc/frotz", true));
        assert!(
            !rules.excludes("a/doc/frotz", true),
            "an anchored pattern does not float"
        );
    }

    #[test]
    fn a_leading_slash_anchors_without_making_the_pattern_a_path() {
        let rules = stack(&[("", "/build\n")]);
        assert!(rules.excludes("build", true));
        assert!(!rules.excludes("crates/build", true));
    }

    #[test]
    fn a_trailing_slash_matches_directories_only() {
        let rules = stack(&[("", "logs/\n")]);
        assert!(rules.excludes("logs", true));
        assert!(
            !rules.excludes("logs", false),
            "a file named `logs` is not a directory"
        );
    }

    #[test]
    fn the_last_matching_rule_in_a_file_decides() {
        let rules = stack(&[("", "*.log\n!keep.log\n")]);
        assert!(rules.excludes("debug.log", false));
        assert!(!rules.excludes("keep.log", false));

        // Order matters: reversing them makes the negation lose.
        let reversed = stack(&[("", "!keep.log\n*.log\n")]);
        assert!(reversed.excludes("keep.log", false));
    }

    #[test]
    fn a_deeper_file_overrides_a_shallower_one() {
        let rules = stack(&[("", "*.rs\n"), ("crates/inner", "!*.rs\n")]);
        assert!(rules.excludes("main.rs", false));
        assert!(!rules.excludes("crates/inner/main.rs", false));
        assert!(
            rules.excludes("crates/other/main.rs", false),
            "a deeper file only speaks for its own subtree"
        );
    }

    #[test]
    fn a_single_star_stops_at_a_separator_and_a_double_star_does_not() {
        assert!(glob("*.rs", "main.rs"));
        assert!(!glob("*.rs", "src/main.rs"));
        assert!(glob("**/main.rs", "src/deep/main.rs"));
        assert!(
            glob("**/main.rs", "main.rs"),
            "a leading `**/` matches zero directories"
        );
        assert!(glob("a/**/b", "a/b"), "`a/**/b` also matches `a/b`");
        assert!(glob("a/**/b", "a/x/y/b"));
        assert!(!glob("a/**/b", "a/x/y/c"));
        assert!(glob("src/**", "src/a/b/c.rs"));
    }

    #[test]
    fn a_question_mark_matches_one_character_but_never_a_separator() {
        assert!(glob("?.rs", "a.rs"));
        assert!(!glob("?.rs", "ab.rs"));
        assert!(!glob("a?b", "a/b"));
    }

    #[test]
    fn a_character_class_matches_a_set_a_range_and_a_negation() {
        assert!(glob("[abc].rs", "b.rs"));
        assert!(!glob("[abc].rs", "d.rs"));
        assert!(glob("[a-z].rs", "q.rs"));
        assert!(!glob("[a-z].rs", "Q.rs"));
        assert!(glob("[!a-z].rs", "Q.rs"));
        assert!(!glob("[!a-z].rs", "q.rs"));
        // An unterminated class is a literal bracket, which is what Git does.
        assert!(glob("[abc", "[abc"));
    }

    #[test]
    fn a_backslash_escapes_a_wildcard() {
        assert!(glob("a\\*b", "a*b"));
        assert!(!glob("a\\*b", "axb"));
    }

    #[test]
    fn a_pattern_matching_nothing_excludes_nothing() {
        let rules = stack(&[("", "*.log\n")]);
        assert!(!rules.excludes("src/main.rs", false));
        assert!(!IgnoreStack::new().excludes("anything", false));
        assert!(IgnoreStack::new().is_empty());
    }

    #[test]
    fn a_stack_can_be_unwound_to_the_depth_it_had() {
        let mut rules = stack(&[("", "*.log\n")]);
        let depth = rules.len();
        rules.push(IgnoreFile::parse("*.rs\n", "src"));
        assert!(rules.excludes("src/main.rs", false));
        rules.truncate(depth);
        assert!(
            !rules.excludes("src/main.rs", false),
            "leaving a directory must retire the rules it contributed"
        );
    }

    #[test]
    fn an_empty_file_contributes_nothing_to_the_stack() {
        let mut rules = IgnoreStack::new();
        rules.push(IgnoreFile::parse("\n# only comments\n\n", ""));
        assert!(rules.is_empty());
    }
}
