//! Reassembly of incoming chunks (`session-reassembly.py`;
//! incoming_add_msg, incoming_check_finalize, prune_inactive in
//! FUN_0014f280): chunks out of order, the same transaction id from
//! another MAC, and incomplete transactions dropped after 40 s.  Sends
//! hand-made Echo chunks; takes about 50 s.

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

/// Sends the chunks and returns the body of the reply with id `txid`.
fn send_and_wait(
    phone: &Phone,
    txid: &str,
    parts: &[Part<'_>],
    mac: Option<&str>,
    timeout: u64,
) -> Result<Option<BString>> {
    let mut ex = phone.expect_reply("Echo", txid);
    send_parts(phone, txid, parts, mac)?;
    phone.wait_reply(&mut ex, Some(Duration::from_secs(timeout)));
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
        3,
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
    let r = send_and_wait(&phone, &txid, &[(1, true, "end")], None, 3)?;
    c.same("transactions are keyed by ID and MAC", r, some("mac1-end"));
    let r = send_and_wait(&phone, &txid, &[(1, true, "END")], Some("000fd3000002"), 3)?;
    c.same(
        "the other MAC's transaction completes on its own",
        r,
        some("mac2-END"),
    );

    // Incomplete transactions are dropped after 40 s.
    let txid = (base + 2).to_string();
    send_parts(&phone, &txid, &[(0, false, "early-")], None)?;
    std::thread::sleep(Duration::from_secs(42));
    ctx.cli("dpmadev session prune");
    let c = &mut ctx.c;
    let r = send_and_wait(
        &phone,
        &(base + 3).to_string(),
        &[(0, true, "cycle")],
        None,
        3,
    )?;
    c.same("a new read cycle runs", r, some("cycle"));
    let r = send_and_wait(&phone, &txid, &[(1, true, "late")], None, 2)?;
    c.same("an incomplete transaction is dropped after 40 s", r, None);
    // The late chunk alone (sequence 1 of a new transaction) completes
    // once a sequence 0 arrives.
    let r = send_and_wait(&phone, &txid, &[(0, false, "again-")], None, 3)?;
    c.same(
        "the late chunk started a new transaction",
        r,
        some("again-late"),
    );
    Ok(())
}
