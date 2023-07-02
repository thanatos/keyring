use std::fmt::{self, Display};
use std::io::{self, Write};

use unicode_width::UnicodeWidthStr;

pub fn display_table<ItemType: TableDisplay>(
    rows: &[ItemType],
    mut output: impl Write,
) -> io::Result<()> {
    let mut column_widths = Vec::new();
    let mut column_header_width = Vec::new();
    let column_count = ItemType::columns();
    for column_index in 0..column_count {
        let column_width = ItemType::column_name(column_index).width();
        column_widths.push(column_width);
        column_header_width.push(column_width);
    }

    for row in rows {
        for column_index in 0..column_count {
            column_widths[column_index] = std::cmp::max(
                row.item(column_index).width(),
                column_widths[column_index],
            );
        }
    }

    output_row(&mut output, column_count, |column_index| {
        Padded(
            ItemType::column_name(column_index),
            column_widths[column_index],
        )
    })?;
    output_row(&mut output, column_count, |column_index| {
        Divider(column_widths[column_index])
    })?;
    for row in rows {
        output_row(&mut output, column_count, |column_index| {
            Padded(row.item(column_index), column_widths[column_index])
        })?;
    }

    Ok(())
}

pub trait TableDisplay {
    type Item: Display;

    fn columns() -> usize;
    fn column_name(column_index: usize) -> &'static str;
    fn item(&self, column_index: usize) -> &str;
}

fn output_row<F, D>(
    mut output: impl Write,
    column_count: usize,
    get_column_display: F,
) -> io::Result<()>
where
    D: Display,
    F: Fn(usize) -> D,
{
    let mut first = true;
    for column_index in 0..column_count {
        if first {
            first = false;
        } else {
            write!(&mut output, "  ")?;
        }
        write!(&mut output, "{}", get_column_display(column_index))?;
    }
    write!(&mut output, "\n")?;
    Ok(())
}

struct Divider(usize);

impl Display for Divider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..self.0 {
            write!(f, "─")?;
        }
        Ok(())
    }
}

struct Padded<'a>(&'a str, usize);

impl Display for Padded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = self.0.width();
        let padding = self.1.checked_sub(width).unwrap();
        write!(f, "{}", self.0)?;
        for _ in 0..padding {
            write!(f, " ")?;
        }
        Ok(())
    }
}
