# M0 Spike 2+3 — AppKit from pure Zig via zig-objc (PROJECT GATE)

**Status: PASS.** Real run, window on screen, all six proofs in one binary:

```
$ zig build spike-ui -- --auto-exit-seconds 6
spike-ui: window up with 100000 rows (auto-exit: 6s)
SPIKE-UI PASS rows=105000 scroll_ms=83 updates_received=165 (views created=81 reused=8571 viewFor calls=8652 sort_events=1)
```

Reproduced twice with identical numbers; exit code 0. Environment: Zig 0.16.0,
zig-objc @ c8de82ff, macOS 15 / Xcode 26.2 SDK (MacOSX26.2.sdk), Apple Silicon.

Proofs covered: (1) NSApplication/NSWindow from Zig `main()` with manual
`[NSApp run]`; (2) view-based NSTableView, 3 columns, fixed 24pt rows,
`usesAutomaticRowHeights=NO`, 100k Zig-owned rows; (3) dataSource+delegate is
an ObjC class defined from Zig; (4) custom NSView subclass cell drawing text +
colored badge in `drawRect:`; (5) header sorting via
`sortDescriptorPrototype` + `tableView:sortDescriptorsDidChange:` re-sorting a
Zig index array; (6) background thread → main thread marshaling at 30Hz with
`dispatch_async` + zig-objc `Block` (165 updates received, 5×1000 rows
appended live, UI responsive throughout the run).

## Class-definition pattern that worked

Exactly the Ghostty mechanics, via zig-objc:

```zig
const cls = objc.allocateClassPair(objc.getClass("NSObject").?, "SpikeDataSource").?;
_ = cls.addIvar("relayState");                                   // id-sized slot
_ = cls.addMethod("numberOfRowsInTableView:", dsNumberOfRows);   // callconv(.c) fn
_ = cls.addMethod("tableView:viewForTableColumn:row:", dsViewForColumnRow);
objc.registerClassPair(cls);
```

- IMPs are plain `callconv(.c)` Zig fns taking `(c.id, c.SEL, ...)`;
  `addMethod` comptime-derives the ObjC type-encoding from the fn type.
- Define classes **before** the first `setDelegate:`/`setDataSource:` call —
  NSTableView probes `respondsToSelector:` at set time to decide it is a
  view-based table.
- Overriding superclass methods on a runtime subclass (`drawRect:`,
  `isFlipped` on an NSView subclass) works with plain `addMethod`; AppKit
  dispatches to it directly.
- No protocol conformance registration was needed; AppKit only checks
  `respondsToSelector:`.

## State-pointer recovery convention (CHOSEN: cached-Ivar raw pointer)

Each runtime class gets an id-sized ivar holding a raw `*AppState`. The
`Ivar` handle is fetched **once** after `registerClassPair` with
`class_getInstanceVariable` and cached in a global; callbacks then do a single
`object_getIvar` (no string lookup) and `@ptrCast(@alignCast(...))` back:

```zig
g_ds_state_ivar = c.class_getInstanceVariable(cls.value, "relayState");
// at instance creation:
c.object_setIvar(ds.value, g_ds_state_ivar, @ptrCast(state));
// in every callback:
const st: *AppState = @ptrCast(@alignCast(c.object_getIvar(target, ivar).?));
```

Why this over the alternatives:
- **global**: doesn't scale to multiple instances (Relay needs ≥2 file-list
  panes, each with its own data source).
- **associated objects**: requires boxing the pointer in an NSValue (alloc +
  retain/release churn on a hot path) and a runtime hash lookup per call.
- Safety note: runtime-allocated classes have no ARC ivar layout, so
  `object_setIvar` is a plain pointer store — the runtime never
  retains/releases the fake "id". Verified across ~8.7k callback invocations.
- Gotcha: when smuggling a plain integer (row index) through an id ivar,
  Debug-mode `@ptrFromInt` enforces non-null + alignment of the pointee, so
  encode it as `(index + 1) << 3`.

## Struct-return / struct-arg msgSend notes (arm64)

- On aarch64 zig-objc routes **everything** through `objc_msgSend` (no
  `_stret`), which is correct: NSRect/CGRect is a homogeneous float aggregate
  of 4 doubles, returned in v0–v3 per the AAPCS64. `msgSend(NSRect, "bounds",
  .{})` and passing NSRect by value to `initWithContentRect:...` both worked
  first try with `extern struct { origin: NSPoint, size: NSSize }` (all f64).
- Declare `NSInteger` as `i64`, **not** `c_long`: zig-objc's encoder emits
  `'l'` for `c_long` but Apple's LP64 encoding for long is `'q'`. Harmless for
  direct dispatch, wrong if anything ever introspects the signature.
- The type-encoding string for struct params embeds the Zig type name
  (`{ui_spike.NSRect=...}` instead of `{CGRect=...}`). Fine for direct
  dispatch (AppKit calls `drawRect:` through the IMP), but would confuse
  `NSInvocation`-based forwarding/KVC. If that ever matters, name the Zig
  structs `CGRect`/`CGPoint`/`CGSize` at file scope or hand-write the encoding.

## zig-objc gaps hit + workarounds

1. **`c.BOOL` is `i8`, not `bool`** in the translated SDK headers (objc.h
   old-style BOOL). ABI-compatible, but Zig won't coerce: compare `!= 0` and
   return `1`/`0` from BOOL-returning IMPs. Three compile errors on the first
   build, trivially fixed.
2. **No dispatch bindings.** Externs are 4 lines (the Ghostty pattern):
   `extern "c" fn dispatch_async(*anyopaque, *anyopaque) void;` and
   `const dispatch_main_q = @extern(*opaque {}, .{ .name = "_dispatch_main_q" });`.
   `dispatch_async` Block_copy's the stack block before returning, so a
   stack-initialized `objc.Block` context is safe to hand off from the worker.
3. **No exported-constant helpers.** AppKit NSString* constants
   (`NSFontAttributeName`, …) need `@extern(*const c.id, .{ .name = ... }).*`.
4. **`addIvar` only supports id-sized ivars** — fine, that is exactly the
   pointer-slot convention above.
5. **Returning autoreleased objects from a pool-wrapped callback**: zig-objc
   pools are raw push/pop, so `tableView:viewForTableColumn:row:` retains the
   view, pops its pool, then re-autoreleases into AppKit's event-loop pool
   (textbook MRR). Everything else (worker iterations, blocks, drawRect,
   timer) is a plain `init()`/`defer deinit()` pair.
6. Variadic ObjC methods (`dictionaryWithObjectsAndKeys:`) can't be expressed
   through `msgSend`'s comptime fn-type builder — use NSMutableDictionary
   `setObject:forKey:` instead. Non-issue in practice.

## Performance evidence

- 105 programmatic `scrollRowToVisible:` + full `displayIfNeeded` passes over
  a 105k-row table: **83 ms total** (~0.8 ms per scroll+layout+draw, Debug
  build), with 8,652 delegate `viewFor` calls.
- View reuse works exactly as in ObjC: 81 views created vs 8,571 reuses from
  `makeViewWithIdentifier:owner:`.
- 30Hz background→main marshaling (165 dispatches in ~5.5s) + 1000-row/s live
  appends with `noteNumberOfRowsChanged` caused no visible stalls; the scroll
  benchmark ran while the worker was still ticking.
- Sorting 105k rows by name on the main thread (index-array sort + reload):
  imperceptible in this run.

## MAINTAINABILITY VERDICT — GO (with conventions)

Building the whole app this way is viable. The spike is ~560 lines for a
fully working window + 100k-row sortable custom-drawn live-updating table,
written against AppKit semantics that map 1:1 to the ObjC documentation. The
runtime held no surprises; every failure mode encountered was a compile-time
type error, not a runtime mystery.

What makes it maintainable, if treated as law from M1:
1. One `relay_mac` wrapper layer owning all selector strings and geometry
   types (`NSRect`/`NSInteger`/BOOL helpers); feature code never calls
   `msgSend` with string selectors directly.
2. The cached-Ivar state-pointer convention everywhere (this spike is the
   reference implementation).
3. Class definitions in `comptime`-checked builder fns; pools per callback;
   main-thread-only UI-state mutation with `dispatch_async` as the only
   crossing point.

Honest costs to budget for: selectors are stringly-typed (typos surface as
runtime no-ops/crashes, not compile errors — wrapper layer mitigates);
manual retain/release discipline at pool boundaries needs review attention;
BOOL/encoding mismatches are paper cuts. None of these are gate-level risks —
Ghostty ships a production app on exactly these mechanics, and this spike
reproduced them in an afternoon-sized file.
