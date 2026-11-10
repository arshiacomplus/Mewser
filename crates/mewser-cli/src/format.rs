use std::fmt::Write;

use mewser_gateway::{ContentBlock, ExtractedPage};

use crate::error::sanitize_url_for_display;

pub fn format_page_for_terminal(page: &ExtractedPage) -> String {
    let mut out = String::new();

    let display_url = sanitize_url_for_display(&page.url);

    let _ = writeln!(out, "{}", "=".repeat(80));
    let _ = writeln!(out, "Title: {}", page.title);
    let _ = writeln!(out, "URL:   {}", display_url);
    let _ = writeln!(out, "{}", "=".repeat(80));

    if let Some(ref desc) = page.description {
        let _ = writeln!(out, "\nDescription:\n  {}\n", desc);
    }

    if !page.headings.is_empty() {
        let _ = writeln!(out, "--- Document Outline ---");
        for h in &page.headings {
            let indent = "  ".repeat((h.level.saturating_sub(1)) as usize);
            let _ = writeln!(out, "{indent}* [h{}] {}", h.level, h.text);
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "--- Content ---");
    for block in &page.content {
        match block {
            ContentBlock::Heading { level, text } => {
                let prefix = "#".repeat(*level as usize);
                let _ = writeln!(out, "\n{prefix} {text}\n");
            }
            ContentBlock::Paragraph { text } => {
                let _ = writeln!(out, "{text}\n");
            }
            ContentBlock::List { items } => {
                for item in items {
                    let _ = writeln!(out, "  * {item}");
                }
                let _ = writeln!(out);
            }
            ContentBlock::ImagePlaceholder { id, src, alt } => {
                let alt_text = alt.as_deref().unwrap_or("No description");
                let _ = writeln!(out, "[Image #{id}: {alt_text} | Source: {src}]");
            }
        }
    }

    if !page.links.is_empty() {
        let _ = writeln!(out, "\n--- Navigation Links ---");
        for (i, link) in page.links.iter().enumerate() {
            let _ = writeln!(out, "[{}] {} -> {}", i + 1, link.text, link.href);
        }
    }

    let _ = writeln!(out, "{}", "=".repeat(80));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mewser_gateway::{HeadingItem, ImagePlaceholder, LinkItem};

    #[test]
    fn test_format_page() {
        let page = ExtractedPage {
            url: "https://example.com/test?token=123".into(),
            title: "Test Page".into(),
            description: Some("Page description".into()),
            headings: vec![HeadingItem {
                level: 1,
                text: "Main Header".into(),
            }],
            content: vec![
                ContentBlock::Heading {
                    level: 1,
                    text: "Main Header".into(),
                },
                ContentBlock::Paragraph {
                    text: "Hello world paragraph.".into(),
                },
                ContentBlock::ImagePlaceholder {
                    id: 1,
                    src: "https://example.com/img.png".into(),
                    alt: Some("A picture".into()),
                },
            ],
            links: vec![LinkItem {
                text: "Home".into(),
                href: "https://example.com/".into(),
            }],
            images: vec![ImagePlaceholder {
                id: 1,
                src: "https://example.com/img.png".into(),
                alt: Some("A picture".into()),
            }],
        };

        let formatted = format_page_for_terminal(&page);
        assert!(formatted.contains("Title: Test Page"));
        assert!(formatted.contains("https://example.com/test?[REDACTED]"));
        assert!(formatted.contains("Description:\n  Page description"));
        assert!(formatted.contains("[Image #1: A picture | Source: https://example.com/img.png]"));
        assert!(formatted.contains("[1] Home -> https://example.com/"));
    }
}
