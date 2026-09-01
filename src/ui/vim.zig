//! vim — the shared opt-in browser keymap layer (pref "ui.vimMode", off by
//! default; phase 2 browser power features).
//!
//! PURE state machine: a `Keymap` consumes normalized `Key`s and yields
//! `Action`s; it never touches AppKit. browser.zig owns the only instance
//! per pane, feeds it from the table keyDown hook when vim mode is on, and
//! executes the actions (selection moves, goUp, deleteSelection, …).
//! Multi-key sequences (`gg`, `dd`) ride a one-slot pending prefix; an
//! unrecognized second key is re-processed as fresh input, so `dj` moves
//! down instead of dying in the operator. Type-to-select is the browser's
//! job to suppress while the layer is active (every printable key is
//! swallowed, handled or not).

const std = @import("std");

/// One normalized key press. `char` is the LOWERCASED ASCII character ('g'
/// for both g and G) with the original case carried by `shift`; control
/// characters arrive decoded (Ctrl+D = .{ .char = 'd', .control = true }).
/// Return and Escape ride as flags because they have no printable char.
pub const Key = struct {
    char: u8 = 0,
    shift: bool = false,
    control: bool = false,
    enter: bool = false,
    escape: bool = false,
};

pub const Action = enum {
    /// Not a vim binding; the caller decides whether to swallow the key
    /// (printables — type-to-select stays disabled) or pass it through
    /// (Escape, control chords).
    none,
    /// Ate the key as part of a sequence (pending prefix) or as a cleared
    /// state (Escape with a pending prefix/anchor); nothing to execute.
    consumed,
    move_down, // j
    move_up, // k
    parent, // h
    open, // l / Return
    top, // gg
    bottom, // G
    half_page_down, // Ctrl+d
    half_page_up, // Ctrl+u
    focus_filter, // /
    next_match, // n
    prev_match, // N
    toggle_select, // x
    range_anchor, // v
    delete, // dd (confirm flow applies)
    yank, // y — full path to the clipboard
    rename, // r
};

/// The keymap state: just the pending operator prefix. The visual-range
/// anchor lives with the caller (it is row state, not key state).
pub const Keymap = struct {
    pub const Pending = enum { none, g, d };

    pending: Pending = .none,

    pub fn reset(km: *Keymap) void {
        km.pending = .none;
    }

    /// Consume one key, yield the action. Sequences: a recognized second
    /// key completes (gg → .top, dd → .delete); anything else clears the
    /// prefix and is re-processed as fresh input.
    pub fn feed(km: *Keymap, key: Key) Action {
        if (key.escape) {
            if (km.pending != .none) {
                km.pending = .none;
                return .consumed;
            }
            return .none; // caller: clear anchor / fall through
        }

        switch (km.pending) {
            .none => {},
            .g => {
                km.pending = .none;
                if (key.char == 'g' and !key.shift and !key.control) return .top;
                return km.feed(key); // fresh re-process
            },
            .d => {
                km.pending = .none;
                if (key.char == 'd' and !key.shift and !key.control) return .delete;
                return km.feed(key); // fresh re-process
            },
        }

        if (key.control) {
            return switch (key.char) {
                'd' => .half_page_down,
                'u' => .half_page_up,
                else => .none,
            };
        }
        if (key.enter) return .open;

        return switch (key.char) {
            'j' => .move_down,
            'k' => .move_up,
            'h' => .parent,
            'l' => .open,
            'g' => if (key.shift) .bottom else blk: {
                km.pending = .g;
                break :blk .consumed;
            },
            'd' => if (key.shift) .none else blk: {
                km.pending = .d;
                break :blk .consumed;
            },
            '/' => .focus_filter,
            'n' => if (key.shift) .prev_match else .next_match,
            'x' => .toggle_select,
            'v' => .range_anchor,
            'y' => .yank,
            'r' => .rename,
            else => .none,
        };
    }
};

// ---------------------------------------------------------------------------
// Headless tests — the keymap state machine, sequence by sequence.
// ---------------------------------------------------------------------------
const testing = std.testing;

fn ch(character: u8) Key {
    return .{ .char = character };
}

fn shifted(character: u8) Key {
    return .{ .char = character, .shift = true };
}

test "single-key motions and commands" {
    var km: Keymap = .{};
    try testing.expectEqual(Action.move_down, km.feed(ch('j')));
    try testing.expectEqual(Action.move_up, km.feed(ch('k')));
    try testing.expectEqual(Action.parent, km.feed(ch('h')));
    try testing.expectEqual(Action.open, km.feed(ch('l')));
    try testing.expectEqual(Action.open, km.feed(.{ .enter = true }));
    try testing.expectEqual(Action.bottom, km.feed(shifted('g')));
    try testing.expectEqual(Action.focus_filter, km.feed(ch('/')));
    try testing.expectEqual(Action.next_match, km.feed(ch('n')));
    try testing.expectEqual(Action.prev_match, km.feed(shifted('n')));
    try testing.expectEqual(Action.toggle_select, km.feed(ch('x')));
    try testing.expectEqual(Action.range_anchor, km.feed(ch('v')));
    try testing.expectEqual(Action.yank, km.feed(ch('y')));
    try testing.expectEqual(Action.rename, km.feed(ch('r')));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
}

test "gg reaches the top; dd deletes" {
    var km: Keymap = .{};
    try testing.expectEqual(Action.consumed, km.feed(ch('g')));
    try testing.expectEqual(Keymap.Pending.g, km.pending);
    try testing.expectEqual(Action.top, km.feed(ch('g')));
    try testing.expectEqual(Keymap.Pending.none, km.pending);

    try testing.expectEqual(Action.consumed, km.feed(ch('d')));
    try testing.expectEqual(Keymap.Pending.d, km.pending);
    try testing.expectEqual(Action.delete, km.feed(ch('d')));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
}

test "a broken sequence re-processes the second key as fresh input" {
    var km: Keymap = .{};
    _ = km.feed(ch('g'));
    try testing.expectEqual(Action.move_down, km.feed(ch('j'))); // gj → j
    try testing.expectEqual(Keymap.Pending.none, km.pending);

    _ = km.feed(ch('d'));
    try testing.expectEqual(Action.move_up, km.feed(ch('k'))); // dk → k
    _ = km.feed(ch('d'));
    try testing.expectEqual(Action.bottom, km.feed(shifted('g'))); // dG → G
    // dg leaves a fresh g prefix: dgg still reaches the top.
    _ = km.feed(ch('d'));
    try testing.expectEqual(Action.consumed, km.feed(ch('g')));
    try testing.expectEqual(Action.top, km.feed(ch('g')));
    // G (shift) never starts a sequence; D (shift) is not an operator.
    try testing.expectEqual(Action.none, km.feed(shifted('d')));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
}

test "control chords: half page; unknown control falls through" {
    var km: Keymap = .{};
    try testing.expectEqual(Action.half_page_down, km.feed(.{ .char = 'd', .control = true }));
    try testing.expectEqual(Action.half_page_up, km.feed(.{ .char = 'u', .control = true }));
    try testing.expectEqual(Action.none, km.feed(.{ .char = 'x', .control = true }));
    // Ctrl+d does NOT complete a pending d (dd only).
    _ = km.feed(ch('d'));
    try testing.expectEqual(Action.half_page_down, km.feed(.{ .char = 'd', .control = true }));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
}

test "escape clears a pending prefix, otherwise falls through" {
    var km: Keymap = .{};
    _ = km.feed(ch('g'));
    try testing.expectEqual(Action.consumed, km.feed(.{ .escape = true }));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
    try testing.expectEqual(Action.none, km.feed(.{ .escape = true }));
}

test "unbound printables yield none and leave no state behind" {
    var km: Keymap = .{};
    try testing.expectEqual(Action.none, km.feed(ch('q')));
    try testing.expectEqual(Action.none, km.feed(ch(' ')));
    try testing.expectEqual(Action.none, km.feed(ch('1')));
    try testing.expectEqual(Keymap.Pending.none, km.pending);
}

test {
    testing.refAllDecls(@This());
}
