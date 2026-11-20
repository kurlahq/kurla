#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobError {
    Empty,
    TripleStar,
    PartialDoubleStar,
}

impl std::fmt::Display for GlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GlobError::Empty => f.write_str("empty glob pattern"),
            GlobError::TripleStar => f.write_str("`***` is not valid in a glob pattern"),
            GlobError::PartialDoubleStar => {
                f.write_str("`**` must be a whole path segment in a glob pattern")
            }
        }
    }
}

impl std::error::Error for GlobError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    AnyChar,
    AnyRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    AnyDepth,
    Pattern(Vec<Token>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    segments: Vec<Segment>,
    anywhere: bool,
}

fn fold(text: &str) -> String {
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.to_string()
    }
}

fn parse_segment(segment: &str) -> Result<Segment, GlobError> {
    if segment.contains("***") {
        return Err(GlobError::TripleStar);
    }
    if segment == "**" {
        return Ok(Segment::AnyDepth);
    }
    if segment.contains("**") {
        return Err(GlobError::PartialDoubleStar);
    }
    let tokens = segment
        .chars()
        .map(|c| match c {
            '*' => Token::AnyRun,
            '?' => Token::AnyChar,
            other => Token::Literal(other),
        })
        .collect();
    Ok(Segment::Pattern(tokens))
}

fn segment_matches(tokens: &[Token], text: &[char]) -> bool {
    let mut token = 0;
    let mut at = 0;
    let mut resume: Option<(usize, usize)> = None;
    while at < text.len() {
        match tokens.get(token) {
            Some(Token::AnyRun) => {
                resume = Some((token, at));
                token += 1;
            }
            Some(Token::AnyChar) => {
                token += 1;
                at += 1;
            }
            Some(Token::Literal(c)) if *c == text[at] => {
                token += 1;
                at += 1;
            }
            _ => match resume {
                Some((star, from)) => {
                    resume = Some((star, from + 1));
                    token = star + 1;
                    at = from + 1;
                }
                None => return false,
            },
        }
    }
    tokens[token..].iter().all(|t| *t == Token::AnyRun)
}

fn segments_match(segments: &[Segment], parts: &[&str]) -> bool {
    match segments.split_first() {
        None => parts.is_empty(),
        Some((Segment::AnyDepth, rest)) => {
            (0..=parts.len()).any(|skip| segments_match(rest, &parts[skip..]))
        }
        Some((Segment::Pattern(tokens), rest)) => match parts.split_first() {
            Some((part, tail)) => {
                let chars: Vec<char> = part.chars().collect();
                segment_matches(tokens, &chars) && segments_match(rest, tail)
            }
            None => false,
        },
    }
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Glob, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        let folded = fold(pattern);
        let segments = folded
            .split('/')
            .map(parse_segment)
            .collect::<Result<Vec<_>, _>>()?;
        let anywhere = !folded.contains('/');
        Ok(Glob { segments, anywhere })
    }

    pub fn matches(&self, rel_path: &str) -> bool {
        let folded = fold(rel_path);
        let parts: Vec<&str> = folded.split('/').collect();
        if self.anywhere {
            return segments_match(&self.segments, &parts[parts.len() - 1..]);
        }
        segments_match(&self.segments, &parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str) -> Glob {
        Glob::new(pattern).unwrap()
    }

    #[test]
    fn glob_without_slash_matches_at_any_depth() {
        let g = glob("*.min.js");
        assert!(g.matches("app.min.js"));
        assert!(g.matches("a/b/c/app.min.js"));
        assert!(!g.matches("app.js"));
        let g = glob("node_modules");
        assert!(g.matches("node_modules"));
        assert!(g.matches("pkg/node_modules"));
        assert!(!g.matches("node_modules/pkg"));
    }

    #[test]
    fn glob_with_slash_is_anchored_to_the_whole_path() {
        let g = glob("docs/*.md");
        assert!(g.matches("docs/a.md"));
        assert!(!g.matches("x/docs/a.md"));
        assert!(!g.matches("docs/sub/a.md"));
    }

    #[test]
    fn glob_star_does_not_cross_segments() {
        let g = glob("a/*/c");
        assert!(g.matches("a/b/c"));
        assert!(!g.matches("a/b/b/c"));
        assert!(!g.matches("a/c"));
        let g = glob("a?c/x");
        assert!(g.matches("abc/x"));
        assert!(!g.matches("a/c/x"));
        assert!(!g.matches("ac/x"));
    }

    #[test]
    fn double_star_matches_zero_or_more_whole_segments() {
        let g = glob("a/**/z");
        assert!(g.matches("a/z"));
        assert!(g.matches("a/b/z"));
        assert!(g.matches("a/b/c/z"));
        assert!(!g.matches("a/b/c"));
        assert!(!g.matches("ab/z"));
        let g = glob("**/target/**");
        assert!(g.matches("target"));
        assert!(g.matches("x/y/target/z/w"));
        assert!(!g.matches("x/targets/z"));
    }

    #[test]
    fn star_and_question_match_within_a_segment() {
        let g = glob("a*b*c");
        assert!(g.matches("abc"));
        assert!(g.matches("aXXbYYc"));
        assert!(g.matches("abbc"));
        assert!(!g.matches("aXXbYY"));
        assert!(glob("*").matches("anything"));
        assert!(glob("*").matches(""));
        assert!(!glob("?").matches(""));
        assert!(glob("??").matches("ab"));
        assert!(!glob("??").matches("abc"));
        assert!(glob("a*").matches("a"));
    }

    #[test]
    fn glob_case_follows_platform() {
        assert_eq!(glob("readme.md").matches("README.MD"), cfg!(windows));
        assert_eq!(glob("Docs/*.md").matches("dOCS/a.md"), cfg!(windows));
        assert!(glob("readme.md").matches("readme.md"));
    }

    #[test]
    fn invalid_glob_is_error() {
        assert_eq!(Glob::new(""), Err(GlobError::Empty));
        assert_eq!(Glob::new("***"), Err(GlobError::TripleStar));
        assert_eq!(Glob::new("a/***/b"), Err(GlobError::TripleStar));
        assert_eq!(Glob::new("a**b"), Err(GlobError::PartialDoubleStar));
        assert_eq!(Glob::new("a/**b/c"), Err(GlobError::PartialDoubleStar));
        assert_eq!(Glob::new("**a"), Err(GlobError::PartialDoubleStar));
        assert!(Glob::new("**").is_ok());
        assert!(Glob::new("a/**/b").is_ok());
    }
}
