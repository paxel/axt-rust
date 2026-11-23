//! What a sending device owes a receiver, and what it does with the outcomes of its
//! withdrawals (AXT `spec/shares.md`, sections 3.2, 5 to 7; `spec/sync.md`, section 5.3).
//! Each function works on one record and one receiver.

use crate::records::{Outcome, RecordKind};

/// What a device owes a receiver of one record (shares.md, section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owes {
    /// The record's `DATA`.
    Data,
    /// The record's `DELETE`.
    Delete,
    /// The `WITHDRAW` of its last recorded withdrawal.
    Withdraw,
    /// Nothing.
    Nothing,
    /// A `WITHDRAW` of a new version.
    NewWithdrawal,
}

impl Owes {
    /// The code of the vectors, such as `DATA` or `new_withdrawal`.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::Delete => "DELETE",
            Self::Withdraw => "WITHDRAW",
            Self::Nothing => "nothing",
            Self::NewWithdrawal => "new_withdrawal",
        }
    }

    /// The value of a code of [`Owes::code`].
    pub(crate) fn from_code(code: &str) -> Option<Self> {
        [
            Self::Data,
            Self::Delete,
            Self::Withdraw,
            Self::Nothing,
            Self::NewWithdrawal,
        ]
        .into_iter()
        .find(|o| o.code() == code)
    }
}

/// The last record message of a record that a device sent a receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sent {
    /// Its kind.
    pub(crate) kind: RecordKind,
    /// Its version.
    pub(crate) version: i64,
}

/// What a device owes a receiver of a record that is `shared` with it or not, `deleted`
/// or not, under its state stamp `version`, with `withdrawal`, the version of its last
/// recorded withdrawal from that receiver, and `last`, the last record message it sent
/// there (sections 5.3 and 6.1); with the version of the message it owes.
pub(crate) fn owed(
    shared: bool,
    deleted: bool,
    version: i64,
    withdrawal: Option<i64>,
    last: Option<Sent>,
) -> (Owes, Option<i64>) {
    if shared {
        return (
            if deleted { Owes::Delete } else { Owes::Data },
            Some(version),
        );
    }
    if let Some(last) = last
        && last.kind == RecordKind::Data
        && withdrawal.is_none_or(|w| last.version > w)
    {
        return (Owes::NewWithdrawal, None);
    }
    match withdrawal {
        Some(w) => (Owes::Withdraw, Some(w)),
        None => (Owes::Nothing, None),
    }
}

/// The next version of an installation that counts (sections 3.2 and 6.2), and its state
/// stamp then: a withdrawal leaves the state stamp, a sharing again takes the version.
/// `None` when the versions are spent.
pub(crate) fn take_version(
    share_again: bool,
    highest_given: i64,
    state_stamp: i64,
) -> Option<(i64, i64)> {
    let version = highest_given.checked_add(1)?;
    Some((version, if share_again { version } else { state_stamp }))
}

/// What a device does next for a record and a receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Then {
    /// Nothing.
    Nothing,
    /// It sends a `WITHDRAW` of a new version.
    NewWithdrawal,
    /// It sends the record's state.
    SendState,
    /// It waits for its siblings.
    Wait,
}

impl Then {
    /// The code of the vectors, such as `send_state`.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Nothing => "nothing",
            Self::NewWithdrawal => "new_withdrawal",
            Self::SendState => "send_state",
            Self::Wait => "wait",
        }
    }
}

/// What a device knows when an entry of an `ACK` comes in for a record message it sent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Acked {
    /// The kind of the message it sent.
    pub(crate) sent: RecordKind,
    /// The outcome it holds already, if any.
    pub(crate) held: Option<Outcome>,
    /// The outcome of the entry.
    pub(crate) outcome: Outcome,
    /// The receiver's version in the entry.
    pub(crate) receiver_version: i64,
    /// Whether the record is shared with the receiver.
    pub(crate) shared: bool,
    /// The version of its last recorded withdrawal from the receiver.
    pub(crate) withdrawal: Option<i64>,
    /// The record's state stamp.
    pub(crate) state_stamp: i64,
    /// The highest state stamp of a sibling it knows, if any.
    pub(crate) sibling_stamp: Option<i64>,
    /// Whether it has siblings.
    pub(crate) sibling: bool,
}

/// The outcome a device holds after one entry of an `ACK` (shares.md, 5.2; protocol.md,
/// 7.4), what it does then (shares.md, 5.3; sync.md, 5.3), and the version to pass when
/// it waits.
pub(crate) fn acked(a: Acked) -> (Outcome, Then, Option<i64>) {
    let mut taken = a.outcome;
    let removal_applied =
        a.sent == RecordKind::Withdraw && matches!(a.outcome, Outcome::Applied | Outcome::Merged);
    let state_withdrawn = a.sent != RecordKind::Withdraw && a.outcome == Outcome::Withdrawn;
    if removal_applied || state_withdrawn {
        taken = Outcome::Duplicate;
    }
    if let Some(held) = a.held
        && held != Outcome::Duplicate
        && !(taken == Outcome::Applied && matches!(held, Outcome::Kept | Outcome::Merged))
        && !(taken == Outcome::Withdrawn && held == Outcome::Kept)
    {
        taken = held;
    }
    if taken != Outcome::Stale {
        return (taken, Then::Nothing, None);
    }
    let highest = if a.sent == RecordKind::Withdraw {
        a.withdrawal.unwrap_or(0)
    } else {
        [Some(a.state_stamp), a.sibling_stamp, a.withdrawal]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(a.state_stamp)
    };
    if a.receiver_version <= highest {
        return (taken, Then::Nothing, None);
    }
    if a.sibling {
        return (taken, Then::Wait, Some(a.receiver_version));
    }
    (
        taken,
        if a.shared {
            Then::SendState
        } else {
            Then::NewWithdrawal
        },
        None,
    )
}

/// What a device does with the version to pass `to_pass` after it has waited for its
/// siblings (shares.md, section 5.3).
pub(crate) fn pass_withdrawal(
    shared: bool,
    withdrawal: Option<i64>,
    to_pass: i64,
    state_stamp: i64,
) -> Then {
    if shared {
        return if state_stamp > to_pass {
            Then::Nothing
        } else {
            Then::SendState
        };
    }
    if withdrawal.is_some_and(|w| w >= to_pass) {
        Then::Nothing
    } else {
        Then::NewWithdrawal
    }
}

/// The record toward receivers that join (shares.md, section 7.3), each `shared` or not
/// with its last withdrawal: whether it is shared with the joined receiver, its
/// withdrawal, and whether it takes a new state stamp.
pub(crate) fn join_receivers(receivers: &[(bool, Option<i64>)]) -> (bool, Option<i64>, bool) {
    let shared = receivers.iter().any(|(s, _)| *s);
    let withdrawal = receivers.iter().filter_map(|(_, w)| *w).max();
    (shared, withdrawal, shared && withdrawal.is_some())
}

/// The types a device offers a receiver of another user, with the number of messages it
/// still owes of each (shares.md, section 2.2), sorted by type; each record is its type,
/// what is owed and whether that was delivered.
pub(crate) fn offer_types(records: &[(String, Owes, bool)]) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for (type_name, owes, delivered) in records {
        if *owes == Owes::Nothing || *delivered {
            continue;
        }
        let count = counts.entry(type_name.clone()).or_default();
        *count = count.saturating_add(1);
    }
    counts.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(kind: RecordKind, version: i64) -> Option<Sent> {
        Some(Sent { kind, version })
    }

    #[test]
    fn what_a_device_owes_a_receiver() {
        assert_eq!(owed(true, false, 5, Some(3), None), (Owes::Data, Some(5)));
        assert_eq!(owed(true, true, 5, None, None), (Owes::Delete, Some(5)));
        assert_eq!(
            owed(false, false, 5, None, sent(RecordKind::Data, 4)),
            (Owes::NewWithdrawal, None)
        );
        assert_eq!(
            owed(false, false, 5, Some(6), sent(RecordKind::Data, 4)),
            (Owes::Withdraw, Some(6))
        );
        assert_eq!(
            owed(false, false, 5, Some(3), sent(RecordKind::Data, 4)),
            (Owes::NewWithdrawal, None)
        );
        assert_eq!(owed(false, false, 5, None, None), (Owes::Nothing, None));
        assert_eq!(
            owed(false, false, 5, None, sent(RecordKind::Delete, 4)),
            (Owes::Nothing, None)
        );
    }

    #[test]
    fn a_withdrawal_leaves_the_state_stamp_a_sharing_again_takes_it() {
        assert_eq!(take_version(false, 7, 4), Some((8, 4)));
        assert_eq!(take_version(true, 7, 4), Some((8, 8)));
        assert_eq!(take_version(true, i64::MAX, 4), None);
    }

    fn ack(sent: RecordKind, held: Option<Outcome>, outcome: Outcome, version: i64) -> Acked {
        Acked {
            sent,
            held,
            outcome,
            receiver_version: version,
            shared: false,
            withdrawal: Some(5),
            state_stamp: 4,
            sibling_stamp: None,
            sibling: false,
        }
    }

    #[test]
    fn the_outcome_of_an_ack_and_what_follows() {
        // An APPLIED of a WITHDRAW is taken as a DUPLICATE.
        let a = ack(RecordKind::Withdraw, None, Outcome::Applied, 5);
        assert_eq!(acked(a), (Outcome::Duplicate, Then::Nothing, None));
        // A held KEPT stands against a later APPLIED only when it is no KEPT or MERGED.
        let a = ack(RecordKind::Data, Some(Outcome::Kept), Outcome::Applied, 5);
        assert_eq!(acked(a).0, Outcome::Applied);
        let a = ack(RecordKind::Data, Some(Outcome::Kept), Outcome::Stale, 5);
        assert_eq!(acked(a).0, Outcome::Kept);
        // A STALE above every version it gave calls for a new withdrawal.
        let a = ack(RecordKind::Withdraw, None, Outcome::Stale, 9);
        assert_eq!(acked(a), (Outcome::Stale, Then::NewWithdrawal, None));
        let a = Acked {
            shared: true,
            ..ack(RecordKind::Data, None, Outcome::Stale, 9)
        };
        assert_eq!(acked(a), (Outcome::Stale, Then::SendState, None));
        let a = Acked {
            sibling: true,
            ..ack(RecordKind::Data, None, Outcome::Stale, 9)
        };
        assert_eq!(acked(a), (Outcome::Stale, Then::Wait, Some(9)));
        let a = ack(RecordKind::Data, None, Outcome::Stale, 5);
        assert_eq!(acked(a), (Outcome::Stale, Then::Nothing, None));
        // A WITHDRAWN stands against a later KEPT, and replaces a KEPT.
        let a = ack(
            RecordKind::Withdraw,
            Some(Outcome::Withdrawn),
            Outcome::Kept,
            5,
        );
        assert_eq!(acked(a).0, Outcome::Withdrawn);
        let a = ack(
            RecordKind::Withdraw,
            Some(Outcome::Kept),
            Outcome::Withdrawn,
            5,
        );
        assert_eq!(acked(a).0, Outcome::Withdrawn);
        // The state stamp of a sibling counts among the versions the device knows.
        let a = Acked {
            withdrawal: Some(6),
            state_stamp: 7,
            sibling_stamp: Some(8),
            ..ack(RecordKind::Data, None, Outcome::Stale, 9)
        };
        assert_eq!(acked(a).1, Then::NewWithdrawal);
        let a = Acked {
            receiver_version: 8,
            ..a
        };
        assert_eq!(acked(a).1, Then::Nothing);
        // A STALE for a WITHDRAW without a recorded withdrawal.
        let a = Acked {
            withdrawal: None,
            ..ack(RecordKind::Withdraw, None, Outcome::Stale, 7)
        };
        assert_eq!(acked(a).1, Then::NewWithdrawal);
    }

    #[test]
    fn a_withdrawal_kept_against_then_taken() {
        use crate::records::{
            DeleteWithLocalChanges, ElementMerge, HeldState, RecordMessage, RecordPolicy,
            apply_record_message, take_kept_removal,
        };
        use crate::value::Value;
        let policy = RecordPolicy {
            withdraw_with_local_changes: Some(DeleteWithLocalChanges::Keep),
            delete_with_local_changes: DeleteWithLocalChanges::Delete,
            ..RecordPolicy::default()
        };
        let value = |t: &str| Value::Record(vec![("t".into(), Value::String(t.into()))]);
        let message = |kind, version, value| RecordMessage {
            kind,
            version,
            type_name: (kind == RecordKind::Data).then_some("a.M"),
            value,
        };
        let elements = ElementMerge::default();
        let a = value("a");
        let mine = value("mine");
        let first = apply_record_message(
            None,
            None,
            message(RecordKind::Data, 1, Some(&a)),
            &policy,
            &elements,
        )
        .unwrap();
        let kept = apply_record_message(
            Some(&first.held),
            Some(&mine),
            message(RecordKind::Withdraw, 2, None),
            &policy,
            &elements,
        )
        .unwrap();
        assert_eq!(kept.outcome, Outcome::Kept);
        assert_eq!(kept.held.kept_against, Some(RecordKind::Withdraw));
        let taken = take_kept_removal(&kept.held).unwrap();
        assert_eq!(taken.outcome, Outcome::Withdrawn);
        assert_eq!(taken.held.state, HeldState::Withdrawn);
        let deleted = apply_record_message(
            Some(&first.held),
            Some(&mine),
            message(RecordKind::Delete, 2, None),
            &RecordPolicy::default(),
            &elements,
        )
        .unwrap();
        assert_eq!(
            take_kept_removal(&deleted.held).unwrap().outcome,
            Outcome::Applied
        );
        assert!(take_kept_removal(&first.held).is_none());
    }

    #[test]
    fn a_version_to_pass_after_the_siblings() {
        assert_eq!(pass_withdrawal(true, None, 5, 6), Then::Nothing);
        assert_eq!(pass_withdrawal(true, None, 5, 5), Then::SendState);
        assert_eq!(pass_withdrawal(false, Some(5), 5, 1), Then::Nothing);
        assert_eq!(pass_withdrawal(false, Some(4), 5, 1), Then::NewWithdrawal);
        assert_eq!(pass_withdrawal(false, None, 5, 1), Then::NewWithdrawal);
    }

    #[test]
    fn receivers_that_join() {
        assert_eq!(
            join_receivers(&[(false, Some(3)), (true, None)]),
            (true, Some(3), true)
        );
        assert_eq!(
            join_receivers(&[(false, Some(3)), (false, Some(7))]),
            (false, Some(7), false)
        );
        assert_eq!(join_receivers(&[(true, None)]), (true, None, false));
    }

    #[test]
    fn the_types_offered_count_what_is_owed_and_not_delivered() {
        let records = vec![
            ("b.T".to_owned(), Owes::Data, false),
            ("a.T".to_owned(), Owes::Withdraw, false),
            ("b.T".to_owned(), Owes::Delete, false),
            ("c.T".to_owned(), Owes::Nothing, false),
            ("a.T".to_owned(), Owes::Data, true),
        ];
        assert_eq!(
            offer_types(&records),
            vec![("a.T".to_owned(), 1), ("b.T".to_owned(), 2)]
        );
        assert_eq!(Owes::from_code("new_withdrawal"), Some(Owes::NewWithdrawal));
        assert_eq!(Owes::from_code("x"), None);
    }
}
