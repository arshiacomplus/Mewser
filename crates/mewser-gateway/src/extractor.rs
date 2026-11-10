use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;
use url::Url;

use crate::models::{ContentBlock, ExtractedPage, HeadingItem, ImagePlaceholder, LinkItem};

pub fn extract_page(raw_html: &str, base_url: &Url) -> ExtractedPage {
    let document = Html::parse_document(raw_html);

    let title = extract_title(&document, base_url);
    let description = extract_description(&document);

    let container = select_primary_container(&document);

    let mut content = Vec::new();
    let mut headings = Vec::new();
    let mut images = Vec::new();
    let mut image_counter = 0usize;

    walk_content_tree(
        container,
        base_url,
        &mut content,
        &mut headings,
        &mut images,
        &mut image_counter,
    );

    let links = extract_links(&container, base_url);

    ExtractedPage {
        url: base_url.to_string(),
        title,
        description,
        headings,
        content,
        links,
        images,
    }
}

fn extract_title(document: &Html, base_url: &Url) -> String {
    let title_sel = Selector::parse("title").unwrap();
    if let Some(el) = document.select(&title_sel).next() {
        let t = collapse_whitespace(&el.text().collect::<Vec<_>>().join(" "));
        if !t.is_empty() {
            return t;
        }
    }

    let meta_og_sel = Selector::parse("meta[property='og:title']").unwrap();
    if let Some(el) = document.select(&meta_og_sel).next() {
        if let Some(c) = el.value().attr("content") {
            let t = collapse_whitespace(c);
            if !t.is_empty() {
                return t;
            }
        }
    }

    let h1_sel = Selector::parse("h1").unwrap();
    if let Some(el) = document.select(&h1_sel).next() {
        let t = collapse_whitespace(&el.text().collect::<Vec<_>>().join(" "));
        if !t.is_empty() {
            return t;
        }
    }

    base_url.host_str().unwrap_or("Untitled").to_string()
}

fn extract_description(document: &Html) -> Option<String> {
    let meta_desc_sel = Selector::parse("meta[name='description']").unwrap();
    if let Some(el) = document.select(&meta_desc_sel).next() {
        if let Some(c) = el.value().attr("content") {
            let desc = collapse_whitespace(c);
            if !desc.is_empty() {
                return Some(desc);
            }
        }
    }

    let meta_og_desc_sel = Selector::parse("meta[property='og:description']").unwrap();
    if let Some(el) = document.select(&meta_og_desc_sel).next() {
        if let Some(c) = el.value().attr("content") {
            let desc = collapse_whitespace(c);
            if !desc.is_empty() {
                return Some(desc);
            }
        }
    }

    None
}

fn select_primary_container<'a>(document: &'a Html) -> ElementRef<'a> {
    let article_sel = Selector::parse("article").unwrap();
    if let Some(el) = document.select(&article_sel).next() {
        let text_len: usize = el.text().map(|t| t.trim().len()).sum();
        if text_len > 40 {
            return el;
        }
    }

    let main_sel = Selector::parse("main").unwrap();
    if let Some(el) = document.select(&main_sel).next() {
        let text_len: usize = el.text().map(|t| t.trim().len()).sum();
        if text_len > 40 {
            return el;
        }
    }

    let body_sel = Selector::parse("body").unwrap();
    if let Some(el) = document.select(&body_sel).next() {
        return el;
    }

    document.root_element()
}

fn walk_content_tree(
    element: ElementRef<'_>,
    base_url: &Url,
    content: &mut Vec<ContentBlock>,
    headings: &mut Vec<HeadingItem>,
    images: &mut Vec<ImagePlaceholder>,
    counter: &mut usize,
) {
    let tag = element.value().name();

    match tag {
        "script" | "style" | "noscript" | "template" | "svg" | "canvas" | "iframe" | "nav"
        | "footer" | "header" | "aside" => {
            return;
        }

        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            let level = tag[1..].parse::<u8>().unwrap_or(1);
            let text = collapse_whitespace(&element.text().collect::<Vec<_>>().join(" "));
            if !text.is_empty() {
                headings.push(HeadingItem {
                    level,
                    text: text.clone(),
                });
                content.push(ContentBlock::Heading { level, text });
            }
            return;
        }

        "p" => {
            let text = collapse_whitespace(&element.text().collect::<Vec<_>>().join(" "));
            if !text.is_empty() {
                content.push(ContentBlock::Paragraph { text });
            }

            let img_sel = Selector::parse("img").unwrap();
            for img_el in element.select(&img_sel) {
                record_image(img_el, base_url, content, images, counter);
            }
            return;
        }

        "ul" | "ol" => {
            let li_sel = Selector::parse(":scope > li, li").unwrap();
            let mut items = Vec::new();
            for li in element.select(&li_sel) {
                let item_text = collapse_whitespace(&li.text().collect::<Vec<_>>().join(" "));
                if !item_text.is_empty() {
                    items.push(item_text);
                }
            }
            if !items.is_empty() {
                content.push(ContentBlock::List { items });
            }
            return;
        }

        "img" => {
            record_image(element, base_url, content, images, counter);
            return;
        }

        _ => {}
    }

    for child in element.children() {
        if let Some(child_el) = ElementRef::wrap(child) {
            walk_content_tree(child_el, base_url, content, headings, images, counter);
        }
    }
}

fn record_image(
    element: ElementRef<'_>,
    base_url: &Url,
    content: &mut Vec<ContentBlock>,
    images: &mut Vec<ImagePlaceholder>,
    counter: &mut usize,
) {
    let src = match element.value().attr("src") {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return,
    };

    let resolved_src = match base_url.join(src) {
        Ok(u) => u.to_string(),
        Err(_) => src.to_string(),
    };

    let alt = element
        .value()
        .attr("alt")
        .map(collapse_whitespace)
        .filter(|a| !a.is_empty());

    *counter += 1;
    let placeholder = ImagePlaceholder {
        id: *counter,
        src: resolved_src.clone(),
        alt: alt.clone(),
    };

    images.push(placeholder);
    content.push(ContentBlock::ImagePlaceholder {
        id: *counter,
        src: resolved_src,
        alt,
    });
}

fn extract_links(container: &ElementRef<'_>, base_url: &Url) -> Vec<LinkItem> {
    let a_sel = Selector::parse("a[href]").unwrap();
    let mut links = Vec::new();
    let mut seen = HashSet::new();

    for el in container.select(&a_sel) {
        let href_attr = match el.value().attr("href") {
            Some(h) if !h.trim().is_empty() => h.trim(),
            _ => continue,
        };

        if href_attr.starts_with('#') || href_attr.starts_with("javascript:") {
            continue;
        }

        let resolved_url = match base_url.join(href_attr) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let scheme = resolved_url.scheme();
        if scheme != "http" && scheme != "https" {
            continue;
        }

        let text = collapse_whitespace(&el.text().collect::<Vec<_>>().join(" "));
        if text.is_empty() {
            continue;
        }

        let href_str = resolved_url.to_string();
        if seen.insert((text.clone(), href_str.clone())) {
            links.push(LinkItem {
                text,
                href: href_str,
            });
        }
    }

    links
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_article_with_metadata() {
        let html = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Test Page Title</title>
                <meta name="description" content="This is a test description.">
            </head>
            <body>
                <nav><a href="/home">Home</a></nav>
                <article>
                    <h1>Main Headline</h1>
                    <p>First paragraph with informative text.</p>
                    <img src="/assets/photo.jpg" alt="A test photo">
                    <ul>
                        <li>Item one</li>
                        <li>Item two</li>
                    </ul>
                    <p>Read more at <a href="/more">More Info</a>.</p>
                </article>
                <footer><p>Copyright 2026</p></footer>
                <script>console.log("noisy tracking script");</script>
            </body>
            </html>
        "#;

        let base_url = Url::parse("https://example.com/blog/post1").unwrap();
        let page = extract_page(html, &base_url);

        assert_eq!(page.title, "Test Page Title");
        assert_eq!(
            page.description.as_deref(),
            Some("This is a test description.")
        );
        assert_eq!(page.headings.len(), 1);
        assert_eq!(page.headings[0].text, "Main Headline");

        assert_eq!(page.images.len(), 1);
        assert_eq!(page.images[0].src, "https://example.com/assets/photo.jpg");
        assert_eq!(page.images[0].alt.as_deref(), Some("A test photo"));

        assert_eq!(page.links.len(), 1);
        assert_eq!(page.links[0].text, "More Info");
        assert_eq!(page.links[0].href, "https://example.com/more");

        let p_count = page
            .content
            .iter()
            .filter(|b| matches!(b, ContentBlock::Paragraph { .. }))
            .count();
        assert_eq!(p_count, 2);

        let list_count = page
            .content
            .iter()
            .filter(|b| matches!(b, ContentBlock::List { .. }))
            .count();
        assert_eq!(list_count, 1);
    }
}
