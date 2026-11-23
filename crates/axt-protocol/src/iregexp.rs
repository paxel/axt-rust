//! I-Regexp (RFC 9485): a parser of its grammar that decides whether a pattern is valid,
//! and its translation to the expressions of the crate `regex`, whose matching is linear
//! in the value (AXT `spec/metadata.md`, sections 6.4 and 9).
//!
//! Whether a pattern is an I-Regexp is decided by the parser alone, never by whether
//! `regex` compiles the translation: `regex` takes patterns outside the subset with a
//! meaning of its own. The translation writes every character as the escape of its code
//! point, `.` as `[^\n\r]` and each group as `(?:…)`, and matches the whole value with
//! `\A` and `\z`, as RFC 9485, section 5, describes.

use std::str::Chars;
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};

use crate::limits::{METADATA_PATTERN, METADATA_PATTERN_QUANTIFIER};

/// The general categories of Unicode that `\p{…}` may name.
const CATEGORIES: [&str; 36] = [
    "L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No", "P", "Pc",
    "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Z", "Zs", "Zl", "Zp", "S", "Sm", "Sc", "Sk", "So", "C",
    "Cc", "Cf", "Co", "Cn",
];

/// The most bytes of the compiled program of a pattern: enough for a large class repeated
/// up to `metadata.pattern_quantifier` times, such as `[\p{L} \-]{1,1000}`. A pattern
/// above it, such as of nested range quantifiers, is not run, and every value keeps it
/// (metadata.md, section 9).
const SIZE_LIMIT: usize = 64 << 20;

/// The deepest nesting of groups and repeats that a translated pattern may have, the
/// default of `regex`, whose parser and compiler recurse once per level. A pattern nested
/// deeper, about 125 groups with quantifiers, is not run either.
const NEST_LIMIT: u32 = 250;

/// A pattern that is not an I-Regexp.
struct Invalid;

/// An I-Regexp, matching a value as a whole. Its expression is compiled at its first
/// match, so a description that is only validated or shown never pays for it.
#[derive(Debug, Clone)]
pub(crate) struct IRegexp {
    /// The translation, matching the whole value.
    translated: String,
    /// The compiled translation; `None` for one above the bounds of `regex`.
    regex: OnceLock<Option<Regex>>,
}

impl IRegexp {
    /// The I-Regexp `pattern`; `None` when it is not an I-Regexp within the limits
    /// `metadata.pattern` and `metadata.pattern_quantifier`.
    pub(crate) fn compile(pattern: &str) -> Option<Self> {
        if pattern.len() > METADATA_PATTERN {
            return None;
        }
        let mut parser = Parser {
            chars: pattern.chars(),
        };
        let body = parser.regexp().ok()?;
        if parser.peek().is_some() {
            return None;
        }
        Some(Self {
            translated: format!("\\A(?:{body})\\z"),
            regex: OnceLock::new(),
        })
    }

    /// The compiled translation; `None` for one above the bounds of `regex`.
    fn engine(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| {
                RegexBuilder::new(&self.translated)
                    .size_limit(SIZE_LIMIT)
                    .nest_limit(NEST_LIMIT)
                    .build()
                    .ok()
            })
            .as_ref()
    }

    /// Whether `value` as a whole is in the pattern's language; true as well for a pattern
    /// above the bounds of `regex`.
    pub(crate) fn has_match(&self, value: &str) -> bool {
        self.engine().is_none_or(|r| r.is_match(value))
    }
}

/// A character as the escape of its code point.
fn literal(c: char) -> String {
    format!("\\x{{{:X}}}", u32::from(c))
}

/// What an escape stands for.
enum Escape {
    /// A single character.
    Char(char),
    /// A category escape, translated.
    Category(String),
}

/// A parser of the grammar of RFC 9485, section 3, that writes the translation.
struct Parser<'a> {
    chars: Chars<'a>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.clone().next()
    }

    fn peek_second(&self) -> Option<char> {
        self.chars.clone().nth(1)
    }

    /// Consumes `c` or fails.
    fn expect(&mut self, c: char) -> Result<(), Invalid> {
        if self.chars.next() == Some(c) {
            Ok(())
        } else {
            Err(Invalid)
        }
    }

    /// `regExp`: branches separated by `|`.
    fn regexp(&mut self) -> Result<String, Invalid> {
        let mut branches = vec![self.branch()?];
        while self.peek() == Some('|') {
            self.chars.next();
            branches.push(self.branch()?);
        }
        Ok(if branches.len() == 1 {
            branches.concat()
        } else {
            format!("(?:{})", branches.join("|"))
        })
    }

    /// `branch`: pieces up to a `|` or a `)`.
    fn branch(&mut self) -> Result<String, Invalid> {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            out.push_str(&self.piece()?);
        }
        Ok(out)
    }

    /// `piece`: an atom with an optional quantifier.
    fn piece(&mut self) -> Result<String, Invalid> {
        let atom = self.atom()?;
        let quantifier = match self.peek() {
            Some(q @ ('*' | '+' | '?')) => {
                self.chars.next();
                q.to_string()
            }
            Some('{') => {
                self.chars.next();
                let min = self.number()?;
                let mut max = Some(min);
                if self.peek() == Some(',') {
                    self.chars.next();
                    max = match self.peek() {
                        None | Some('}') => None,
                        Some(_) => Some(self.number()?),
                    };
                }
                self.expect('}')?;
                if min > METADATA_PATTERN_QUANTIFIER
                    || max.is_some_and(|m| m > METADATA_PATTERN_QUANTIFIER || m < min)
                {
                    return Err(Invalid);
                }
                match max {
                    Some(m) if m == min => format!("{{{min}}}"),
                    Some(m) => format!("{{{min},{m}}}"),
                    None => format!("{{{min},}}"),
                }
            }
            _ => return Ok(atom),
        };
        Ok(format!("(?:{atom}){quantifier}"))
    }

    /// The digits of a quantifier; a number above `u32` is above every limit.
    fn number(&mut self) -> Result<u32, Invalid> {
        let mut value: Option<u32> = None;
        while let Some(digit) = self.peek().and_then(|c| c.to_digit(10)) {
            self.chars.next();
            value = Some(
                value
                    .unwrap_or(0)
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(Invalid)?,
            );
        }
        value.ok_or(Invalid)
    }

    /// `atom`: a character, `.`, a class, an escape or a group.
    fn atom(&mut self) -> Result<String, Invalid> {
        match self.peek().ok_or(Invalid)? {
            '(' => {
                self.chars.next();
                let inner = self.regexp()?;
                self.expect(')')?;
                Ok(inner)
            }
            '.' => {
                self.chars.next();
                Ok("[^\\n\\r]".into())
            }
            '[' => self.class(),
            '\\' => Ok(match self.escape()? {
                Escape::Char(c) => literal(c),
                Escape::Category(category) => category,
            }),
            ')' | '*' | '+' | '?' | ']' | '{' | '|' | '}' => Err(Invalid),
            c => {
                self.chars.next();
                Ok(literal(c))
            }
        }
    }

    /// An escape: a single-character escape or a category escape.
    fn escape(&mut self) -> Result<Escape, Invalid> {
        self.expect('\\')?;
        let c = self.chars.next().ok_or(Invalid)?;
        Ok(match c {
            'n' => Escape::Char('\n'),
            'r' => Escape::Char('\r'),
            't' => Escape::Char('\t'),
            'p' | 'P' => {
                self.expect('{')?;
                let mut name = String::new();
                loop {
                    match self.chars.next().ok_or(Invalid)? {
                        '}' => break,
                        n => name.push(n),
                    }
                }
                if !CATEGORIES.contains(&name.as_str()) {
                    return Err(Invalid);
                }
                Escape::Category(format!("\\{c}{{{name}}}"))
            }
            '(' | ')' | '*' | '+' | '-' | '.' | '?' | '[' | '\\' | ']' | '^' | '{' | '|' | '}' => {
                Escape::Char(c)
            }
            _ => return Err(Invalid),
        })
    }

    /// A character of a class: a single character or a single-character escape.
    fn class_char(&mut self) -> Result<char, Invalid> {
        match self.peek().ok_or(Invalid)? {
            '\\' => match self.escape()? {
                Escape::Char(c) => Ok(c),
                Escape::Category(_) => Err(Invalid),
            },
            '-' | '[' | ']' => Err(Invalid),
            c => {
                self.chars.next();
                Ok(c)
            }
        }
    }

    /// `charClassExpr`: `[`, an optional `^`, the items and `]`.
    fn class(&mut self) -> Result<String, Invalid> {
        self.expect('[')?;
        let negated = self.peek() == Some('^');
        if negated {
            self.chars.next();
        }
        let mut items: Vec<String> = Vec::new();
        loop {
            match self.peek().ok_or(Invalid)? {
                ']' => {
                    if items.is_empty() {
                        return Err(Invalid);
                    }
                    self.chars.next();
                    break;
                }
                '-' => {
                    // A '-' is allowed first, or last before ']'.
                    if !items.is_empty() && self.peek_second() != Some(']') {
                        return Err(Invalid);
                    }
                    self.chars.next();
                    items.push(literal('-'));
                }
                '\\' if matches!(self.peek_second(), Some('p' | 'P')) => match self.escape()? {
                    Escape::Category(category) => items.push(category),
                    Escape::Char(c) => items.push(literal(c)),
                },
                _ => {
                    let from = self.class_char()?;
                    let range =
                        self.peek() == Some('-') && self.peek_second().is_some_and(|c| c != ']');
                    if range {
                        self.chars.next();
                        if self.peek() == Some('[') {
                            // Class subtraction is not in the subset.
                            return Err(Invalid);
                        }
                        let to = self.class_char()?;
                        if to < from {
                            return Err(Invalid);
                        }
                        items.push(format!("{}-{}", literal(from), literal(to)));
                    } else {
                        items.push(literal(from));
                    }
                }
            }
        }
        Ok(format!(
            "[{}{}]",
            if negated { "^" } else { "" },
            items.concat()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(pattern: &str) -> Option<IRegexp> {
        IRegexp::compile(pattern)
    }

    fn matches(pattern: &str, value: &str) -> bool {
        compile(pattern).unwrap().has_match(value)
    }

    #[test]
    fn the_escapes_of_line_feed_carriage_return_and_tab() {
        assert!(matches(r"\n\r\t", "\n\r\t"));
    }

    #[test]
    fn a_range_that_ends_in_a_category_is_not_valid() {
        assert!(compile(r"[a-\p{L}]").is_none());
    }

    #[test]
    fn a_pattern_above_the_limit_of_bytes_is_not_valid() {
        assert!(compile(&"a".repeat(1025)).is_none());
        assert!(compile(&"a".repeat(1024)).is_some());
        assert!(compile(&"ä".repeat(513)).is_none());
    }

    #[test]
    fn patterns_outside_the_grammar_are_not_valid() {
        for pattern in [
            r"\d",
            "(?:a)",
            "a*?",
            "a**",
            "[^]",
            "[]",
            "[a-[b]]",
            r"\p{IsBasicLatin}",
            "a{2,1}",
            "a{1001}",
            "a{0,1001}",
            "a{99999999999}",
            "(a",
            "a)",
            "[a",
            "{",
            "}",
            "]",
            r"\",
            "[b-a]",
            "[a-b-c]",
            r"\x",
        ] {
            assert!(compile(pattern).is_none(), "{pattern}");
        }
        for pattern in [
            "",
            "[-a]",
            "[a-]",
            "a{1000}",
            "a{2,}",
            "^$",
            r"[\p{L}\-]",
            "[\\^]",
        ] {
            assert!(compile(pattern).is_some(), "{pattern}");
        }
    }

    #[test]
    fn every_category_compiles() {
        for name in CATEGORIES {
            let pattern = format!(r"\p{{{name}}}[\P{{{name}}}]");
            assert!(compile(&pattern).unwrap().engine().is_some(), "{name}");
        }
        assert!(matches(r"\p{Lu}\p{Ll}+", "Mimi"));
        assert!(!matches(r"\p{Lu}\p{Ll}+", "mimi"));
        assert!(!matches(r"\P{N}+", "Ⅻ"));
    }

    #[test]
    fn the_whole_value_matches_and_anchors_are_characters() {
        assert!(matches("[0-9]{5}", "10115"));
        assert!(!matches("[0-9]{5}", "10115\n"));
        assert!(!matches("[0-9]{5}", "10115 Berlin"));
        assert!(matches("^[0-9]+$", "^12$"));
        assert!(!matches("^[0-9]+$", "12"));
        assert!(!matches("colou?r|grey", "colorgrey"));
        assert!(matches("colou?r|grey", "grey"));
        assert!(matches(r"\.\*\{\}", ".*{}"));
        assert!(matches("[a-c-]+", "a-c"));
    }

    #[test]
    fn a_pattern_that_makes_a_backtracking_engine_hang_runs_in_linear_time() {
        let a = "a".repeat(5000);
        assert!(!matches("(a*)*b", &a));
        assert!(!matches("(a|aa)*c", &a));
        assert!(matches("(a*)*b", &format!("{a}b")));
    }

    #[test]
    fn repeats_alternatives_and_empty_loops() {
        assert!(!matches("a{2,3}", "a"));
        assert!(matches("a{2,3}", "aaa"));
        assert!(!matches("a{2,3}", "aaaa"));
        assert!(matches("a{2,}", "aaaaa"));
        assert!(matches("a{0}b", "b"));
        assert!(matches("(ab|cd)+e?", "abcdab"));
        assert!(!matches("(ab|cd)+e?", "abc"));
        assert!(matches("()*x", "x"));
        assert!(matches(r"[^a-c\p{Nd}]", "d"));
        assert!(!matches(r"[^a-c\p{Nd}]", "5"));
        assert!(matches(r"\P{L}.", "1x"));
        assert!(!matches(".", "\n"));
    }

    #[test]
    fn a_pattern_above_the_bounds_of_the_engine_keeps_every_value() {
        let nested = compile("((a{1000}){1000}){1000}").unwrap();
        assert!(nested.engine().is_none());
        assert!(nested.has_match("b"));
        // A large class repeated up to the limit is still run.
        let wide = compile(r"[\p{L} \-]{1,1000}").unwrap();
        assert!(wide.engine().is_some());
        assert!(!wide.has_match(&"A".repeat(1001)));
    }

    #[test]
    fn a_pattern_nested_deeper_than_the_engine_takes_keeps_every_value() {
        let nested = |depth| format!("{}a{}", "(".repeat(depth), ")*".repeat(depth));
        let deep = compile(&nested(120)).unwrap();
        assert!(deep.engine().is_some());
        assert!(deep.has_match("aaa"));
        assert!(!deep.has_match("b"));
        let deepest = nested(340);
        assert!(deepest.len() <= 1024);
        let deepest = compile(&deepest).unwrap();
        assert!(deepest.engine().is_none());
        assert!(deepest.has_match("b"));
    }
}
