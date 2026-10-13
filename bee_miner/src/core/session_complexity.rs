use ackinacki_kit::contracts::deserialize::deserialize_u32;
use serde::Deserialize;

/// Seeds and complexity fields of the miner contract account data.
#[derive(Debug, Clone, Deserialize)]
pub struct MinerComplexityData {
    #[serde(rename = "_seed")]
    pub seed: String,
    #[serde(rename = "_seedNext")]
    pub next_seed: String,
    #[serde(rename = "_easyComplexity", deserialize_with = "deserialize_u32")]
    pub easy: u32,
    #[serde(rename = "_hardComplexity", deserialize_with = "deserialize_u32")]
    pub hard: u32,
    #[serde(rename = "_easyComplexityOld", deserialize_with = "deserialize_u32")]
    pub easy_old: u32,
    #[serde(rename = "_hardComplexityOld", deserialize_with = "deserialize_u32")]
    pub hard_old: u32,
}

/// Complexity `(easy, hard)` the contract will verify a session on `seed`
/// against.
///
/// The miner contract verifies the current seed with `_*ComplexityOld`, which
/// only takes the value of `_*Complexity` when a session is accepted. After the
/// game root changes complexity, mining with `_*Complexity` (what `getDetails`
/// and `NewComplexity` report) would be rejected on every session.
///
/// The next seed becomes current in one of two ways: the in-flight session is
/// accepted (`Old` takes `_*Complexity`), or a stale commit is cancelled
/// (`cancelCommitData` rotates the seed and leaves `Old` as it is). So for the
/// next seed `_*Complexity` is used only while another session is in flight.
/// Returns `None` for a seed the contract no longer knows.
pub fn select_session_complexity(
    seed: &str,
    data: &MinerComplexityData,
    session_in_flight: bool,
) -> Option<(u32, u32)> {
    if seed == data.seed {
        Some((data.easy_old, data.hard_old))
    } else if seed == data.next_seed {
        if session_in_flight {
            Some((data.easy, data.hard))
        } else {
            Some((data.easy_old, data.hard_old))
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Decoded data of a shellnet miner right after the game root raised hard
    // complexity 11 -> 12: `_hardComplexity` is already 12,
    // `_hardComplexityOld` is still 11.
    const MINER_DATA_AFTER_SWITCH: &str = include_str!("fixtures/miner_account_data.json");

    fn data(easy: u32, hard: u32, easy_old: u32, hard_old: u32) -> MinerComplexityData {
        MinerComplexityData {
            seed: "0xseed".to_string(),
            next_seed: "0xnext".to_string(),
            easy,
            hard,
            easy_old,
            hard_old,
        }
    }

    #[test]
    fn current_seed_uses_old_complexity_after_switch() {
        let d = data(10, 12, 10, 11);
        assert_eq!(select_session_complexity("0xseed", &d, false), Some((10, 11)));
        assert_eq!(select_session_complexity("0xseed", &d, true), Some((10, 11)));
    }

    #[test]
    fn next_seed_after_accepted_session_uses_current_complexity() {
        // A session on the current seed is being submitted: once accepted,
        // `Old` takes `_*Complexity`.
        let d = data(10, 12, 10, 11);
        assert_eq!(select_session_complexity("0xnext", &d, true), Some((10, 12)));
    }

    #[test]
    fn next_seed_after_cancelled_commit_uses_old_complexity() {
        // `Miner::new` cancels a stale commit and mines on the next seed before
        // the cancel lands: `cancelCommitData` does not touch `Old`.
        let d = data(10, 12, 10, 11);
        assert_eq!(select_session_complexity("0xnext", &d, false), Some((10, 11)));
    }

    #[test]
    fn unknown_seed_is_none() {
        let d = data(10, 12, 10, 11);
        assert_eq!(select_session_complexity("0xstale", &d, false), None);
        assert_eq!(select_session_complexity("0xstale", &d, true), None);
    }

    #[test]
    fn unchanged_complexity_matches_previous_behaviour() {
        // Before any change `Old == current`, so every seed gets what
        // `getDetails` reports — same as the client before this fix.
        let d = data(10, 11, 10, 11);
        for in_flight in [false, true] {
            assert_eq!(select_session_complexity("0xseed", &d, in_flight), Some((10, 11)));
            assert_eq!(select_session_complexity("0xnext", &d, in_flight), Some((10, 11)));
        }
    }

    #[test]
    fn easy_and_hard_are_resolved_independently() {
        let d = data(13, 19, 12, 18);
        assert_eq!(select_session_complexity("0xseed", &d, false), Some((12, 18)));
        assert_eq!(select_session_complexity("0xnext", &d, true), Some((13, 19)));
    }

    #[test]
    fn parses_real_miner_account_data() {
        let value: serde_json::Value = serde_json::from_str(MINER_DATA_AFTER_SWITCH).unwrap();
        let d = serde_json::from_value::<MinerComplexityData>(value).unwrap();

        assert_eq!((d.easy, d.hard), (10, 12));
        assert_eq!((d.easy_old, d.hard_old), (10, 11));
        assert_eq!(select_session_complexity(&d.seed, &d, false), Some((10, 11)));
        assert_eq!(select_session_complexity(&d.next_seed, &d, false), Some((10, 11)));
        assert_eq!(select_session_complexity(&d.next_seed, &d, true), Some((10, 12)));
    }
}
