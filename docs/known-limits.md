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

- **UTF-16 text without a byte-order mark whose characters are mostly outside ASCII**, such as Chinese, Japanese or Korean text. Kurla recognises UTF-16 without a byte-order mark by the zero bytes that ASCII characters produce in it. A file with too few of them is listed in the coverage report as unknown binary instead of being scanned as text.
