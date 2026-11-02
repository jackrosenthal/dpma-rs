//! Reassembly of incoming chunks (`session-reassembly.py`;
//! incoming_add_msg, incoming_check_finalize, prune_inactive in
//! FUN_0014f280): chunks out of order, the same transaction id from
//! another MAC, and incomplete transactions dropped when more than 40 s
//! old.  Sends hand-made Echo chunks.  Pruning runs at the start of a
//! read cycle, so the age checks backdate the incomplete transactions
//! (`dpmadev session txage`, which also lets the next cycle prune at
//! once) and complete an Echo to start a new cycle.

use std::time::Duration;

use anyhow::{bail, Result};
use bstr::BString;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::proto::{H_FINISHED, H_ID, H_MAC, H_REQUEST_TYPE, H_SEQUENCE};
use dpma_tests::sim::Phone;
use rand::Rng;

/// A hand-made chunk: sequence, finished, body.
type Part<'a> = (u32, bool, &'a str);

/// Sends Echo chunks of transaction `txid` (as `mac`, default the
/// phone's).
fn send_parts(phone: &Phone, txid: &str, parts: &[Part<'_>], mac: Option<&str>) -> Result<()> {
    for &(seq, fin, body) in parts {
        let mut h: Vec<(String, BString)> = vec![
            (H_REQUEST_TYPE.into(), "Echo".into()),
            (H_ID.into(), txid.into()),
            (H_MAC.into(), mac.unwrap_or(phone.mac()).into()),
            (H_SEQUENCE.into(), seq.to_string().into()),
        ];
        if fin {
            h.push((H_FINISHED.into(), "1".into()));
        }
        let resp = phone.send_message(&h, body.as_bytes())?;
        match resp.as_ref().and_then(|r| r.status()) {
            Some(s) if s < 300 => {}
            s => bail!("MESSAGE failed: {s:?}"),
        }
    }
    Ok(())
}

/// Sends the chunks and returns the body of the reply with id `txid`
/// (waiting up to `timeout` seconds).
fn send_and_wait(
    phone: &Phone,
    txid: &str,
    parts: &[Part<'_>],
    mac: Option<&str>,
    timeout: f64,
) -> Result<Option<BString>> {
    let mut ex = phone.expect_reply("Echo", txid);
    send_parts(phone, txid, parts, mac)?;
    phone.wait_reply(&mut ex, Some(Duration::from_secs_f64(timeout)));
    Ok(ex.reply.map(|r| r.body))
}

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let mut opts = ctx.sim_options();
    // As the original script: no X-Digium-User-Agent (the test identify
    // routes the chunks).
    opts.digium_ua_header = false;
    let phone = Phone::start(opts)?;
    let base: u32 = rand::thread_rng().gen_range(100000..900000);
    let c = &mut ctx.c;
    let some = |s: &str| Some(BString::from(s));

    // Out of order: the finishing chunk first.
    let r = send_and_wait(
        &phone,
        &base.to_string(),
        &[(2, true, "CCCC"), (0, false, "AAAA"), (1, false, "BBBB")],
        None,
        3.0,
    )?;
    c.same(
        "chunks out of order reassemble in sequence order",
        r,
        some("AAAABBBBCCCC"),
    );

    // The same ID from two MACs: two transactions ("<ID>-<MAC>").
    let txid = (base + 1).to_string();
    send_parts(&phone, &txid, &[(0, false, "mac1-")], None)?;
    send_parts(&phone, &txid, &[(0, false, "mac2-")], Some("000fd3000002"))?;
    let r = send_and_wait(&phone, &txid, &[(1, true, "end")], None, 3.0)?;
    c.same("transactions are keyed by ID and MAC", r, some("mac1-end"));
    let r = send_and_wait(
        &phone,
        &txid,
        &[(1, true, "END")],
        Some("000fd3000002"),
        3.0,
    )?;
    c.same(
        "the other MAC's transaction completes on its own",
        r,
        some("mac2-END"),
    );

    // Incomplete transactions are kept at 39 s and dropped at 41 s.
    for (n, age) in [(2, 39), (4, 41)] {
        let txid = (base + n).to_string();
        send_parts(&phone, &txid, &[(0, false, "early-")], None)?;
        ctx.cli(&format!("dpmadev session txage {age}"));
        let cycle = (base + n + 1).to_string();
        let r = send_and_wait(&phone, &cycle, &[(0, true, "cycle")], None, 3.0)?;
        let c = &mut ctx.c;
        c.same(format!("a new read cycle runs ({age} s)"), r, some("cycle"));
        if age < 40 {
            let r = send_and_wait(&phone, &txid, &[(1, true, "late")], None, 3.0)?;
            c.same(
                "an incomplete transaction is kept at 39 s",
                r,
                some("early-late"),
            );
            continue;
        }
        // (A reply would come at once, as the others do.)
        let r = send_and_wait(&phone, &txid, &[(1, true, "late")], None, 0.5)?;
        c.same("an incomplete transaction is dropped at 41 s", r, None);
        // The late chunk alone (sequence 1 of a new transaction) completes
        // once a sequence 0 arrives.
        let r = send_and_wait(&phone, &txid, &[(0, false, "again-")], None, 3.0)?;
        c.same(
            "the late chunk started a new transaction",
            r,
            some("again-late"),
        );
    }
    Ok(())
}
