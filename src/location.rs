use crate::agent_files::{is_agent_file, normalise};
use crate::model::LocationKind;

const DEPENDENCY_DIRS: [&str; 5] = [
    "node_modules",
    "vendor",
    "bower_components",
    "third_party",
    ".yarn",
];
const DOCS_EXTENSIONS: [&str; 8] = ["md", "markdown", "mdx", "rst", "txt", "adoc", "html", "htm"];
const CODE_EXTENSIONS: [&str; 25] = [
    "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "py", "php", "rb", "go", "java",
    "kt", "cs", "c", "h", "cpp", "hpp", "swift", "sh", "ps1", "sql", "lua",
];
const LONG_LINE_EXTENSIONS: [&str; 4] = ["js", "mjs", "cjs", "css"];
const MINIFIED_LINE_LEN: usize = 1000;

pub fn classify(rel_path: &str, max_line_len: usize) -> LocationKind {
    if is_agent_file(rel_path) {
        return LocationKind::AgentFile;
    }
    let path = normalise(rel_path);
    let segs: Vec<&str> = path.split('/').collect();
    let name = segs[segs.len() - 1];
    let dirs = &segs[..segs.len() - 1];
    let ext = name.rfind('.').map(|i| &name[i + 1..]).unwrap_or("");
    let long_line_ext = LONG_LINE_EXTENSIONS.contains(&ext);
    if dirs.iter().any(|d| DEPENDENCY_DIRS.contains(d))
        || name.contains(".min.")
        || (max_line_len > MINIFIED_LINE_LEN && long_line_ext)
    {
        return LocationKind::Dependency;
    }
    let workflow = dirs.len() >= 2 && dirs[0] == ".github" && dirs[1] == "workflows";
    let in_docs = dirs.first() == Some(&"docs") || (dirs.first() == Some(&".github") && !workflow);
    if DOCS_EXTENSIONS.contains(&ext) || in_docs {
        return LocationKind::DocsTemplate;
    }
    if CODE_EXTENSIONS.contains(&ext) || workflow {
        return LocationKind::Code;
    }
    LocationKind::DataAsset
}

#[cfg(test)]
mod tests {
    use super::*;
    use LocationKind::*;

    #[test]
    fn agent_file_wins_inside_node_modules() {
        assert_eq!(classify("node_modules/p/CLAUDE.md", 0), AgentFile);
        assert_eq!(classify("vendor/x/.mcp.json", 5000), AgentFile);
    }

    #[test]
    fn dependency_directory_segments() {
        for p in [
            "node_modules/a/b.rs",
            "src/vendor/x.py",
            "bower_components/q.js",
            "third_party/z.c",
            ".yarn/cache/x.txt",
            "a\\node_modules\\b.md",
        ] {
            assert_eq!(classify(p, 0), Dependency, "{p}");
        }
    }

    #[test]
    fn dependency_segment_must_be_whole() {
        assert_eq!(classify("src/vendors/x.rs", 0), Code);
        assert_eq!(classify("src/my_vendor.rs", 0), Code);
    }

    #[test]
    fn minified_name_is_dependency() {
        assert_eq!(classify("static/app.min.js", 0), Dependency);
        assert_eq!(classify("a/b.min.css", 0), Dependency);
    }

    #[test]
    fn minified_bundle_is_dependency() {
        assert_eq!(classify("dist/bundle.js", 1001), Dependency);
        assert_eq!(classify("dist/bundle.mjs", 5000), Dependency);
        assert_eq!(classify("dist/bundle.cjs", 5000), Dependency);
        assert_eq!(classify("dist/site.css", 5000), Dependency);
    }

    #[test]
    fn line_length_threshold_is_exclusive_and_js_css_only() {
        assert_eq!(classify("dist/bundle.js", 1000), Code);
        assert_eq!(classify("dist/site.css", 1000), DataAsset);
        assert_eq!(classify("a.py", 5000), Code);
        assert_eq!(classify("a.json", 5000), DataAsset);
        assert_eq!(classify("a.md", 5000), DocsTemplate);
    }

    #[test]
    fn docs_template_extensions() {
        for ext in ["md", "markdown", "mdx", "rst", "txt", "adoc", "html", "htm"] {
            assert_eq!(classify(&format!("x/y.{ext}"), 0), DocsTemplate, "{ext}");
        }
        assert_eq!(classify("X/Y.MD", 0), DocsTemplate);
    }

    #[test]
    fn docs_and_github_directories_are_docs_template() {
        assert_eq!(classify("docs/data.json", 0), DocsTemplate);
        assert_eq!(classify(".github/ISSUE_TEMPLATE/bug.yml", 0), DocsTemplate);
        assert_eq!(classify(".github/FUNDING.yml", 0), DocsTemplate);
    }

    #[test]
    fn docs_directory_wins_over_code_extension() {
        assert_eq!(classify("docs/example.py", 0), DocsTemplate);
    }

    #[test]
    fn workflows_are_code() {
        assert_eq!(classify(".github/workflows/ci.yml", 0), Code);
        assert_eq!(classify(".github/workflows/x.yaml", 0), Code);
    }

    #[test]
    fn code_extensions() {
        for ext in [
            "rs", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "py", "php", "rb", "go",
            "java", "kt", "cs", "c", "h", "cpp", "hpp", "swift", "sh", "ps1", "sql", "lua",
        ] {
            assert_eq!(classify(&format!("src/f.{ext}"), 0), Code, "{ext}");
        }
    }

    #[test]
    fn everything_else_is_data_asset() {
        assert_eq!(classify("a/b.json", 0), DataAsset);
        assert_eq!(classify("a/b.png", 0), DataAsset);
        assert_eq!(classify("Makefile", 0), DataAsset);
        assert_eq!(classify("a.d/noext", 0), DataAsset);
    }

    #[test]
    fn extension_is_last_suffix_of_final_segment() {
        assert_eq!(classify("a.rs/readme", 0), DataAsset);
        assert_eq!(classify("a.tar.rs", 0), Code);
        assert_eq!(classify("a.rs.bak", 0), DataAsset);
    }

    #[test]
    fn leading_dot_slash_is_ignored() {
        assert_eq!(classify("./src/x.rs", 0), Code);
    }
}
