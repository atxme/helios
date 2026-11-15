//! Human-readable time conventions shared by Helios operator interfaces.
//!
//! Protocol objects continue to carry Unix timestamps. This module only
//! renders those instants for humans, consistently in the Europe/Paris civil
//! time used by the deployment: CET in winter and CEST in summer.

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// Renders a Unix timestamp in Europe/Paris civil time, to the minute.
pub fn format_paris_timestamp(seconds: u64) -> String {
    let Ok(seconds) = i64::try_from(seconds) else {
        return format!("{seconds} (hors plage)");
    };
    let Ok(utc) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return format!("{seconds} (horodatage illisible)");
    };
    let Some((offset, zone)) = paris_offset(utc) else {
        return format!("{seconds} (horodatage illisible)");
    };
    let local = utc.to_offset(offset);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} {zone}",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute()
    )
}

/// The Europe/Paris civil date of a Unix timestamp, as `AAAA-MM-JJ`. `None` when the
/// timestamp is out of range.
pub fn format_paris_date(seconds: u64) -> Option<String> {
    let utc = OffsetDateTime::from_unix_timestamp(i64::try_from(seconds).ok()?).ok()?;
    let (offset, _) = paris_offset(utc)?;
    let local = utc.to_offset(offset);
    Some(format!(
        "{:04}-{:02}-{:02}",
        local.year(),
        u8::from(local.month()),
        local.day()
    ))
}

/// Europe/Paris follows the EU rule: summer time starts and ends at 01:00 UTC
/// on the last Sundays of March and October respectively.
fn paris_offset(utc: OffsetDateTime) -> Option<(UtcOffset, &'static str)> {
    let year = utc.year();
    let summer_start = last_sunday_at_one_utc(year, Month::March)?;
    let summer_end = last_sunday_at_one_utc(year, Month::October)?;
    if utc.unix_timestamp() >= summer_start && utc.unix_timestamp() < summer_end {
        Some((UtcOffset::from_hms(2, 0, 0).ok()?, "CEST"))
    } else {
        Some((UtcOffset::from_hms(1, 0, 0).ok()?, "CET"))
    }
}

fn last_sunday_at_one_utc(year: i32, month: Month) -> Option<i64> {
    let last_day = Date::from_calendar_date(year, month, 31).ok()?;
    let date = last_day.checked_sub(Duration::days(i64::from(
        last_day.weekday().number_days_from_sunday(),
    )))?;
    let one_utc = Time::from_hms(1, 0, 0).ok()?;
    Some(
        PrimitiveDateTime::new(date, one_utc)
            .assume_utc()
            .unix_timestamp(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paris_time_uses_cest_in_summer_and_cet_in_winter() {
        assert_eq!(
            format_paris_timestamp(1_791_792_171),
            "2026-10-12 10:02 CEST"
        );
        assert_eq!(
            format_paris_timestamp(1_796_652_921),
            "2026-12-07 15:15 CET"
        );
    }

    #[test]
    fn paris_time_switches_at_the_european_dst_instants() {
        assert_eq!(
            format_paris_timestamp(1_774_745_999),
            "2026-03-29 01:59 CET"
        );
        assert_eq!(
            format_paris_timestamp(1_774_746_000),
            "2026-03-29 03:00 CEST"
        );
        assert_eq!(
            format_paris_timestamp(1_792_889_999),
            "2026-10-25 02:59 CEST"
        );
        assert_eq!(
            format_paris_timestamp(1_792_890_000),
            "2026-10-25 02:00 CET"
        );
    }

    #[test]
    fn an_unrepresentable_timestamp_is_named() {
        assert!(format_paris_timestamp(u64::MAX).contains("hors plage"));
    }

    #[test]
    fn the_paris_date_is_the_civil_date_and_not_the_utc_one() {
        // 2026-11-15 23:30 UTC is already 16 November in Paris (CET).
        assert_eq!(
            format_paris_date(1_794_785_400).as_deref(),
            Some("2026-11-16")
        );
        assert_eq!(
            format_paris_date(1_794_744_000).as_deref(),
            Some("2026-11-15")
        );
        assert_eq!(format_paris_date(u64::MAX), None);
    }
}
