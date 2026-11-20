#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    U,
    M,
    A,
    S,
    B,
    E,
    I,
    L,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn bump(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }

    pub fn lower(self) -> Severity {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleStatus {
    Stable,
    Experimental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationKind {
    AgentFile,
    DocsTemplate,
    Code,
    DataAsset,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CarrierKind {
    HiddenText,
    DecodedPayload,
    HtmlComment,
    SvgText,
    MetadataField,
    AgentFileText,
    ActiveContent,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    Text,
    Svg,
    Png,
    Jpeg,
    Gif,
    Webp,
    Avif,
    Pdf,
    OtherImage,
    UnknownBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Text,
    Svg,
    ImageMetadata,
    Pdf,
    UnknownBinary,
}

impl FileKind {
    pub fn category(self) -> Category {
        match self {
            FileKind::Text => Category::Text,
            FileKind::Svg => Category::Svg,
            FileKind::Png | FileKind::Jpeg | FileKind::Gif | FileKind::Webp | FileKind::Avif => {
                Category::ImageMetadata
            }
            FileKind::Pdf => Category::Pdf,
            FileKind::OtherImage | FileKind::UnknownBinary => Category::UnknownBinary,
        }
    }

    pub fn drawn_text_unscanned(self) -> bool {
        matches!(
            self,
            FileKind::Png
                | FileKind::Jpeg
                | FileKind::Gif
                | FileKind::Webp
                | FileKind::Avif
                | FileKind::Pdf
                | FileKind::OtherImage
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    SizeLimit,
    DecompressionLimit,
    Timeout,
    Unreadable,
    ExcludedByUser,
    SymlinkNotFollowed,
    PdfNotScanned,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub byte_start: u64,
    pub byte_end: u64,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub kind: CarrierKind,
    pub text: String,
    pub span: Span,
    pub hidden: bool,
    pub evidence: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFinding {
    pub rule_id: &'static str,
    pub family: Family,
    pub base: Severity,
    pub status: RuleStatus,
    pub span: Span,
    pub carrier: CarrierKind,
    pub payload: Option<String>,
    pub message: String,
    pub evidence: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub reviewer: String,
    pub reason: String,
    pub counted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub raw: RawFinding,
    pub path: String,
    pub location: LocationKind,
    pub severity: Severity,
    pub fingerprint: String,
    pub review: Option<Review>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedNotScanned {
    pub span: Span,
    pub declared_type: Option<String>,
    pub kind: FileKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCoverage {
    pub path: String,
    pub kind: FileKind,
    pub category: Category,
    pub skip: Option<SkipReason>,
    pub drawn_text_unscanned: bool,
    pub embedded_not_scanned: Vec<EmbeddedNotScanned>,
    pub encoded_runs_not_payloads: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorOutput {
    pub findings: Vec<RawFinding>,
    pub carriers: Vec<Carrier>,
    pub skip: Option<SkipReason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bump_caps_at_critical_and_lower_floors_at_info() {
        assert_eq!(Severity::Info.bump(), Severity::Low);
        assert_eq!(Severity::Low.bump(), Severity::Medium);
        assert_eq!(Severity::Medium.bump(), Severity::High);
        assert_eq!(Severity::High.bump(), Severity::Critical);
        assert_eq!(Severity::Critical.bump(), Severity::Critical);
        assert_eq!(Severity::Critical.lower(), Severity::High);
        assert_eq!(Severity::High.lower(), Severity::Medium);
        assert_eq!(Severity::Medium.lower(), Severity::Low);
        assert_eq!(Severity::Low.lower(), Severity::Info);
        assert_eq!(Severity::Info.lower(), Severity::Info);
    }

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn file_kind_category_maps_every_variant() {
        assert_eq!(FileKind::Text.category(), Category::Text);
        assert_eq!(FileKind::Svg.category(), Category::Svg);
        assert_eq!(FileKind::Png.category(), Category::ImageMetadata);
        assert_eq!(FileKind::Jpeg.category(), Category::ImageMetadata);
        assert_eq!(FileKind::Gif.category(), Category::ImageMetadata);
        assert_eq!(FileKind::Webp.category(), Category::ImageMetadata);
        assert_eq!(FileKind::Avif.category(), Category::ImageMetadata);
        assert_eq!(FileKind::Pdf.category(), Category::Pdf);
        assert_eq!(FileKind::OtherImage.category(), Category::UnknownBinary);
        assert_eq!(FileKind::UnknownBinary.category(), Category::UnknownBinary);
    }

    #[test]
    fn file_kind_drawn_text_unscanned_for_every_variant() {
        assert!(!FileKind::Text.drawn_text_unscanned());
        assert!(!FileKind::Svg.drawn_text_unscanned());
        assert!(FileKind::Png.drawn_text_unscanned());
        assert!(FileKind::Jpeg.drawn_text_unscanned());
        assert!(FileKind::Gif.drawn_text_unscanned());
        assert!(FileKind::Webp.drawn_text_unscanned());
        assert!(FileKind::Avif.drawn_text_unscanned());
        assert!(FileKind::Pdf.drawn_text_unscanned());
        assert!(FileKind::OtherImage.drawn_text_unscanned());
        assert!(!FileKind::UnknownBinary.drawn_text_unscanned());
    }
}
