# Known limits

Kurla reports what it scanned and what it did not. This page lists content that Kurla knowingly does not read, so you can judge whether it matters for your repository. Everything on this page is either listed in the coverage report or is a part of a format that Kurla's readers skip by design.

## Image metadata that is not read

- **JPEG segments other than COM, EXIF and XMP.** These include APP13 (Photoshop and IPTC, which can hold captions and keywords), APP12 (the "Ducky" comment), the ICC profile description in APP2, and APP1 segments in other namespaces, such as the FLIR thermal-camera segment. The detection families in the design name JPEG COM segments, EXIF and XMP. IPTC captions are a candidate for version 0.2.
- **The ICC profile description** inside a PNG `iCCP` chunk. The profile name is read.
- **Private PNG chunks and unknown WebP chunks.** Their content has no defined text layout.
- **QuickTime text atoms** in an AVIF or HEIF file, such as the comment and description atoms under `moov/udta`.
- **EXIF values of type BYTE or UNDEFINED that are not clean UTF-8 text.** This includes the internal structure of most maker notes. Such a value is read only when the whole value decodes as UTF-8 with no control characters other than tab and line breaks.
- **TIFF, PSD, JPEG XL, JPEG 2000, BMP, ICO, TGA, EMF and WMF files.** Kurla does not read their metadata, such as the TGA image ID and the EMF and WMF comment records. Each such file is listed in the coverage report under `not_scanned_for_metadata`.

## Text that is not decoded

- **UTF-16 text without a byte-order mark whose characters are mostly outside ASCII.** Kurla recognises UTF-16 without a byte-order mark by the zero bytes that ASCII characters produce in it. A file with too few of them is handled in one of two ways:
  - When its bytes are not valid UTF-8, as is usual for Chinese, Japanese, Korean, Greek or Hebrew text, the file is listed in the coverage report as `unknown_binary`. That makes the run incomplete only with `--require-complete`.
  - When its bytes happen to be valid UTF-8, as for most Cyrillic or Arabic letters, whose UTF-16 code units are an ASCII byte and a control byte, the file is scanned as UTF-8 text. That text is a string of control characters and stray ASCII characters, so the scan says nothing about the UTF-16 content.

  In both cases a payload hidden in such a file is not active for most readers either: an editor or an agent that reads the file as UTF-8, as most do, sees garbage, not the hidden text. The risk is a tool that guesses BOM-less UTF-16 on its own.

## Unicode characters

- **Ideographic variation sequences** are reported as U003 (high). An ideographic variation sequence is a CJK ideograph followed by a selector from U+E0100 to U+E01EF, used mostly for Japanese place and personal names. Kurla does not ship the Ideographic Variation Database, which lists the registered sequences, so it cannot tell a registered sequence from a selector that carries data. A reviewer can mark such a finding as reviewed.
- **Blank-looking characters that are not default-ignorable** are not flagged. Kurla finds invisible characters by the Unicode `Default_Ignorable_Code_Point` property, and also flags U+2800 BRAILLE PATTERN BLANK unless the same line holds another braille character. Other characters that draw as empty space are not flagged: the space characters U+00A0, U+1680, U+2000 to U+200A, U+202F, U+205F and U+3000, and symbols that draw nothing, such as U+1D159 MUSICAL SYMBOL NULL NOTEHEAD. They show as a gap, so a reader sees spacing where they are.
- **A joiner next to punctuation of a joining script is not flagged.** U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER are not flagged between two characters of the same joining script, such as Arabic or Devanagari, other than digits; combining marks before the joiner are skipped. Kurla tells these characters apart by script only, so a joiner beside that script's own punctuation, such as U+06D4 ARABIC FULL STOP, is not flagged either.

## Markup in Markdown and HTML

- **Raw-text elements are read as markup.** The contents of `<script>`, `<style>`, `<textarea>` and `<title>` are not treated as raw text, so a string inside JavaScript or CSS that looks like hidden markup can give a false M002.
- **Implicit end tags are not modelled.** HTML closes `p`, `li` and `td` elements without an end tag; Kurla does not, so hidden text can run on to the next matching end tag. A page with more than 256 elements left open this way gets an L001 "markup nesting limit", even when it is valid HTML.
- **Some code in Markdown is read as markup.** Fenced code blocks inside lists or block quotes, and `\<` escapes, are not recognised, so markup shown as code there can give a false M002.
- **Content that is never displayed is not checked for hiding.** Kurla does not look inside `<template>` or `<noscript>`, and does not evaluate style sheets, so text hidden by a CSS rule or a class is not found.
- **How code and comments end.** A fenced code block ends as in CommonMark: at a fence of the same character, at least as long as the opening fence, indented by at most three spaces and followed only by spaces or tabs. An HTML comment ends as in the WHATWG HTML tokenizer: at `-->` or `--!>`, and `<!-->` and `<!--->` are complete, empty comments.

## SVG

- **Transforms are not evaluated.** A `transform` on an element or on one of its ancestors turns off the check for text placed outside the drawing.
- **Style sheets are not evaluated.** Hiding through a `<style>` element or a class rule is not found. Inline `style` attributes are read.
- **Clip rectangles are read from attributes only**, not from the `style` attribute.
- **Every attribute whose name starts with `on`** is reported as an event handler, as the design requires, including names that are not real handlers.

## Scanning

- **Files that change during a scan.** Kurla lists the files first and reads each one once. A file changed after it was read is not read again, and a file replaced between the listing and the read is scanned in its new form.
- **NTFS alternate data streams and extended attributes** are not read. Tools that read a file normally do not see them either.
- **Duplicate keys in agent configuration.** When a key appears twice in a JSON settings file, Kurla reads the last one, as JavaScript's `JSON.parse` does.
