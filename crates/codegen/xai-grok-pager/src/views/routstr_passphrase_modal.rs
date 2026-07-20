//! Private BIP-39 passphrase re-entry dialog for `/routstr unlock pass`.
//!
//! Masked input only — never echoes the secret into scrollback/chat history.
//! Process-memory draft is cleared on cancel/submit; never persisted.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;
use unicode_width::UnicodeWidthStr;

use crate::app::app_view::RoutstrPassphraseModalState;
use crate::theme::Theme;

const MIN_DIALOG_WIDTH: u16 = 56;
const DIALOG_HEIGHT: u16 = 7;
const INNER_PAD: u16 = 4;
const LABEL_PREFIX: &str = "Passphrase: ";

/// Render the private passphrase dialog (bullets only; never the secret).
pub fn render_routstr_passphrase_modal(
    area: Rect,
    buf: &mut Buffer,
    state: &RoutstrPassphraseModalState,
) {
    let theme = Theme::current();
    let draft_len = state.draft_char_len();
    let masked: String = "\u{2022}".repeat(draft_len.min(64));
    let dialog_width = dialog_width_for(area.width, &masked);

    if area.height < DIALOG_HEIGHT || area.width < 24 {
        if area.height >= 1 && area.width >= 16 {
            let hint = Line::from(Span::styled(
                "[Esc] cancel",
                Style::default().fg(theme.gray_dim),
            ));
            hint.render(Rect::new(area.x, area.y, area.width.min(16), 1), buf);
        }
        return;
    }

    let [_, dialog_h, _] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(dialog_width),
        Constraint::Min(0),
    ])
    .flex(Flex::Center)
    .areas(area);

    let [_, dialog, _] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(DIALOG_HEIGHT),
        Constraint::Min(0),
    ])
    .flex(Flex::Center)
    .areas(dialog_h);

    let bg_style = Style::default().bg(theme.bg_dark);
    for y in dialog.y..dialog.y + dialog.height {
        for x in dialog.x..dialog.x + dialog.width {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(' ');
                cell.set_style(bg_style);
            }
        }
    }

    let border_style = Style::default().fg(theme.gray_dim).bg(theme.bg_dark);
    if let Some(cell) = buf.cell_mut((dialog.x, dialog.y)) {
        cell.set_char('\u{256D}');
        cell.set_style(border_style);
    }
    for x in dialog.x + 1..dialog.x + dialog.width - 1 {
        if let Some(cell) = buf.cell_mut((x, dialog.y)) {
            cell.set_char('\u{2500}');
            cell.set_style(border_style);
        }
    }
    if let Some(cell) = buf.cell_mut((dialog.x + dialog.width - 1, dialog.y)) {
        cell.set_char('\u{256E}');
        cell.set_style(border_style);
    }
    let bottom = dialog.y + dialog.height - 1;
    if let Some(cell) = buf.cell_mut((dialog.x, bottom)) {
        cell.set_char('\u{2570}');
        cell.set_style(border_style);
    }
    for x in dialog.x + 1..dialog.x + dialog.width - 1 {
        if let Some(cell) = buf.cell_mut((x, bottom)) {
            cell.set_char('\u{2500}');
            cell.set_style(border_style);
        }
    }
    if let Some(cell) = buf.cell_mut((dialog.x + dialog.width - 1, bottom)) {
        cell.set_char('\u{256F}');
        cell.set_style(border_style);
    }
    for y in dialog.y + 1..dialog.y + dialog.height - 1 {
        if let Some(cell) = buf.cell_mut((dialog.x, y)) {
            cell.set_char('\u{2502}');
            cell.set_style(border_style);
        }
        if let Some(cell) = buf.cell_mut((dialog.x + dialog.width - 1, y)) {
            cell.set_char('\u{2502}');
            cell.set_style(border_style);
        }
    }

    let inner_x = dialog.x + 2;
    let inner_width = dialog.width.saturating_sub(INNER_PAD);

    let title = Line::from(Span::styled(
        "BIP-39 passphrase (private)",
        Style::default()
            .fg(theme.text_primary)
            .add_modifier(Modifier::BOLD),
    ));
    title.render(Rect::new(inner_x, dialog.y + 1, inner_width, 1), buf);

    let note = Line::from(Span::styled(
        "Empty = default path. Never stored. Esc cancels unlock.",
        Style::default().fg(theme.gray_dim),
    ));
    note.render(Rect::new(inner_x, dialog.y + 2, inner_width, 1), buf);

    let prefix_w = LABEL_PREFIX.width() as u16;
    let cursor_w = 1u16;
    let input_budget = inner_width
        .saturating_sub(prefix_w)
        .saturating_sub(cursor_w) as usize;
    let visible = if masked.width() <= input_budget {
        masked
    } else if input_budget == 0 {
        String::new()
    } else if input_budget == 1 {
        "…".to_string()
    } else {
        // Keep the end (cursor) visible for long drafts.
        let suffix_budget = input_budget - 1;
        let tail: String = masked
            .chars()
            .rev()
            .take(suffix_budget)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!("…{tail}")
    };

    let input_line = Line::from(vec![
        Span::styled(LABEL_PREFIX, Style::default().fg(theme.gray_bright)),
        Span::styled(visible, Style::default().fg(theme.text_primary)),
        Span::styled("\u{2588}", Style::default().fg(theme.accent_user)),
    ]);
    input_line.render(Rect::new(inner_x, dialog.y + 3, inner_width, 1), buf);

    let hints = Line::from(vec![
        Span::styled(
            "enter",
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" = unlock   ", Style::default().fg(theme.gray)),
        Span::styled(
            "esc",
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" = cancel", Style::default().fg(theme.gray)),
    ]);
    hints.render(Rect::new(inner_x, dialog.y + 5, inner_width, 1), buf);
}

fn dialog_width_for(area_width: u16, masked: &str) -> u16 {
    let max_width = area_width.saturating_sub(4);
    let needed = (LABEL_PREFIX.width() + masked.width() + 1 + INNER_PAD as usize) as u16;
    needed.max(MIN_DIALOG_WIDTH).min(max_width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::actions::SensitiveString;
    use crate::app::agent::AgentId;

    #[test]
    fn render_never_paints_passphrase_plaintext() {
        let state = RoutstrPassphraseModalState::new(
            AgentId(0),
            SensitiveString::new("abandon abandon abandon"),
            None,
        );
        // Push a secret that must never appear in the buffer.
        let mut state = state;
        for c in "super-secret-passphrase-xyz".chars() {
            state.push_char(c);
        }
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        render_routstr_passphrase_modal(area, &mut buf, &state);
        let mut painted = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                if let Some(cell) = buf.cell((x, y)) {
                    painted.push_str(cell.symbol());
                }
            }
            painted.push('\n');
        }
        assert!(
            !painted.contains("super-secret"),
            "modal painted passphrase plaintext: {painted}"
        );
        assert!(
            !painted.contains("abandon"),
            "modal painted recovery phrase: {painted}"
        );
        assert!(
            painted.contains('\u{2022}') || painted.contains('•'),
            "expected masked bullets: {painted}"
        );
    }
}
