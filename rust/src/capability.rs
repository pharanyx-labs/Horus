use core::ptr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub typ: u32,
    pub rights: u32,
    pub object: u64,
    /// The serial of the capability this one was derived from (an edge of the
    /// derivation graph), or 0 for a root. 64 bits wide for the same reason
    /// `serial` is: an edge has to name its parent as exactly as the parent
    /// names itself.
    pub badge: u64,
    /// This capability's identity: a node of the derivation graph, issued once
    /// by `assign_fresh_serial` and never again. 64 bits because the property
    /// is "never reused", and a 32-bit counter wrapped after about 4.3 billion
    /// mints, which ring 3 can reach by minting and revoking in a loop (see
    /// `assign_fresh_serial`). Revocation and the snapshot check both rest on
    /// it: a serial names one capability in one slot, for the life of the boot.
    pub serial: u64,
    /// A server-defined identity carried by an endpoint capability (design
    /// `docs/design/filesystem.md` §5.1). Zero means "no token". The kernel
    /// never interprets it: it delivers it, with the capability's rights, to the
    /// receiver of every message sent through this capability, so a server can
    /// tell which of the capabilities it issued a request arrived on.
    ///
    /// THE RULE THAT MAKES IT AN IDENTITY: a token is set in exactly two places,
    /// `rust_cap_mint_token` (from an UNTOKENED endpoint capability holding MINT)
    /// and `rust_cap_reply_mint` (by the endpoint's receiver, into a child of the
    /// capability the request came through). Every other derivation copies it
    /// unchanged, and `nullify` clears it. So a holder can narrow a tokened
    /// capability's rights but can never point it at a different token.
    pub token: u64,
}

pub const CAP_NULL: u32 = 0;
/// The capability type the token primitives operate on (`CAP_ENDPOINT` in
/// `src/include/kernel.h`). Pinned against the C value by the layout check below.
pub const CAP_ENDPOINT: u32 = 3;
/// A pipe end (`CAP_PIPE` in `src/include/kernel.h`). Pinned against the C value
/// by a `_Static_assert` in `src/kernel/capability.c`.
pub const CAP_PIPE: u32 = 13;

/// May a ring-3 task copy a capability of this type into another slot? (S133)
///
/// Everything but a pipe end. A pipe is freed and scrubbed when its count of
/// reader and writer ends falls to zero, and that count lives in the C kernel's
/// pipe table, not in the capability, so a copy this module made would be an
/// end the count never saw: when the original holder closed its end the pipe
/// would be freed under the copy, and the next pipe to reuse the index would be
/// joined to it (LIMITATIONS 1.29). The kernel's own copies (a fork's, the spawn
/// path's stdio wiring) count each end they make and do not come through here.
///
/// Refusing by type, rather than counting copies made from ring 3 as well, was
/// the maintainer's choice on 2026-10-12: no program in the tree passes a pipe
/// end on that way, and an end that can only be had by being created, forked or
/// wired in at spawn is one whose every holder the pipe table already accounts.
#[inline]
const fn copyable_from_ring3(typ: u32) -> bool {
    typ != CAP_PIPE
}
/// The endpoint receive right (`CAP_RIGHT_READ`). A tokened capability never
/// carries it: a token is a client identity, and a client that could receive
/// could dequeue its peers' requests (finding C-1).
pub const CAP_RIGHT_READ: u32 = 1 << 0;
/// The write right (`CAP_RIGHT_WRITE`). On a pipe end it is the direction: a
/// writer end carries it and a reader end never does, which is how the C close
/// paths and `PipeTally` tell the two apart. Pinned against the C value by a
/// `_Static_assert` in `src/kernel/capability.c`.
pub const CAP_RIGHT_WRITE: u32 = 1 << 1;
/// The mint right (`CAP_RIGHT_MINT`). On an untokened endpoint capability it is
/// what `rust_cap_mint_token` requires. A tokened capability MAY keep it, and
/// then it means only what it means everywhere else, the right to make narrowed
/// copies with `rust_cap_mint`, which keep the token. It can never mint a new
/// token, because `rust_cap_mint_token` refuses every tokened source.
pub const CAP_RIGHT_MINT: u32 = 1 << 4;
/// What the kernel strips from every capability it gives a token to: the
/// receive right. MINT is deliberately NOT stripped; see `CAP_RIGHT_MINT`.
pub const TOKEN_STRIPPED_RIGHTS: u32 = CAP_RIGHT_READ;

// ---------------------------------------------------------------------------
// FFI layout contract.
//
// `Capability` (Rust) and `capability_t` (src/include/kernel.h) MUST have the
// identical layout — the kernel passes raw `*mut Capability` across the FFI and
// both sides index the same memory. These compile-time assertions pin the field
// offsets so reordering or retyping a field in either language fails to build.
// The mirror image of these checks lives in src/kernel/capability.c as
// `_Static_assert`s. Every field after `rights` is a u64 at an 8-byte offset,
// so the layout is the same on the 32- and 64-bit targets with no implicit
// padding anywhere, and the size is pinned as well as the offsets.
// ---------------------------------------------------------------------------
const _: () = {
    assert!(core::mem::offset_of!(Capability, typ) == 0);
    assert!(core::mem::offset_of!(Capability, rights) == 4);
    assert!(core::mem::offset_of!(Capability, object) == 8);
    assert!(core::mem::offset_of!(Capability, badge) == 16);
    assert!(core::mem::offset_of!(Capability, serial) == 24);
    assert!(core::mem::offset_of!(Capability, token) == 32);
    assert!(core::mem::size_of::<Capability>() == 40);
    assert!(CAP_NULL == 0);
};

const CNODE_SIZE: u32 = 256;
const KERNEL_RESERVED_CAPS: u32 = 4;


/// The first serial `assign_fresh_serial` hands out. Every derived serial is at
/// least 2^32, so no derived serial can ever fall in the primordial range below
/// (`0xC0DE_0000..=0xC0DE_FFFF`, all under 2^32). With 32-bit serials the counter
/// walked through that range on its way to wrapping, and a derived capability
/// that landed there read as a non-revocable kernel root.
const MIN_DERIVED_SERIAL: u64 = 1 << 32;

// ---------------------------------------------------------------------------
// Why a capability in its slot is valid, and a snapshot is checked by serial.
//
// ONE SERIAL, ONE SLOT. A serial is issued once (`assign_fresh_serial` never
// repeats one: it is 64 bits wide and refuses rather than wrap), and every way
// a capability comes into a slot gives it a fresh serial. So a serial names one
// capability in one slot. A revoke empties, under `cap_lock`, every slot holding
// the revoked serial and every slot whose capability descends from it
// (`revoke_subtree`). Two consequences carry S5:
//
//   * a capability still in a slot has not been revoked, because the revoke
//     that would have reached it emptied that slot. Lookup needs no second
//     record of revocation;
//   * a copy taken OUT of a slot (`cap_snapshot` in capability.c) is still the
//     capability it was iff the slot still holds the same serial. A revoke
//     empties the slot, and a later install there takes a new serial, so a
//     revoked capability can never be confused with what replaced it.
//
// Until 2026-10-11 a second record backed this up: a generation per serial,
// kept in a 4096-cell table indexed by a hash of the serial, bumped on revoke
// and compared on every lookup. Different serials share a cell, so revoking one
// capability made every live capability in the same cell unusable. It failed
// closed, but an ordinary shell session revokes a capability for every file it
// closes, and it lost the shell its root directory in CI (LIMITATIONS 2.23,
// #538). It also was not needed: everything it caught, the structural revoke
// above already caught, except a stale snapshot after a 32-bit serial wrap,
// which 64-bit serials remove. It is gone, and `captest` 16b is the witness that
// a live capability survives any number of unrelated revokes.
// ---------------------------------------------------------------------------

// Primordial root capabilities (kernel-only, in the reserved slots) carry the
// `0xC0DE****` serial tag and are deliberately non-revocable (see
// `is_primordial_root`).
const PRIMORDIAL_SERIAL_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;
const PRIMORDIAL_SERIAL_TAG: u64 = 0xC0DE_0000;

#[inline]
fn serial_is_primordial(serial: u64) -> bool {
    (serial & PRIMORDIAL_SERIAL_MASK) == PRIMORDIAL_SERIAL_TAG
}

/// CONTROL ARM for LIMITATIONS 2.23 (`--features revoke_hashed_backstop`, the
/// `REVOKE_HASHED_BACKSTOP=1` defect flag). Never shipped.
///
/// Puts back the defect's shape: revocation recorded in a fixed table of 4096
/// cells chosen by a hash of the serial, consulted on every lookup. Each cell
/// keeps the highest serial revoked into it, and a capability reads as revoked
/// when its cell holds a serial at least as new as its own, which is to say a
/// revoke into its cell happened after it was born. That is what the removed
/// generation table did (a capability was stamped with its cell's generation at
/// birth and failed once anything bumped the cell), without needing a field in
/// the capability to stamp. `captest` 16b must go red under it.
#[cfg(feature = "revoke_hashed_backstop")]
mod hashed_backstop {
    use core::sync::atomic::{AtomicU64, Ordering};

    const CELLS: usize = 4096;
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    static CELL: [AtomicU64; CELLS] = [ZERO; CELLS];

    fn idx(serial: u64) -> usize {
        let mut x = serial;
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d049bb133111eb);
        x ^= x >> 31;
        (x as usize) & (CELLS - 1)
    }

    pub fn record(serial: u64) {
        if serial != 0 && !super::serial_is_primordial(serial) {
            CELL[idx(serial)].fetch_max(serial, Ordering::SeqCst);
        }
    }

    pub fn reads_revoked(serial: u64) -> bool {
        serial != 0
            && !super::serial_is_primordial(serial)
            && CELL[idx(serial)].load(Ordering::SeqCst) >= serial
    }
}

/// Note that `serial` is being revoked. Nothing to record in a shipping build:
/// emptying its slot is the record. The control arm keeps its lossy table here.
#[inline]
fn note_revoked(_serial: u64) {
    #[cfg(feature = "revoke_hashed_backstop")]
    hashed_backstop::record(_serial);
}

/// Resolve a slot to a live capability carrying at least `required_rights`, or
/// null. The single authority on what "live" means: type, rights and a real
/// serial are all checked here. A revoked capability is not in any slot (see
/// "One serial, one slot" above), so there is no revocation record to consult.
///
/// # Safety
/// `cspace` must be null, or point to at least `cspace_size` valid
/// `Capability`s -- and `cspace_size` must be the TRUE length of that array, not
/// a larger number the C side hoped was right. Null is handled and every slot
/// index is bounds-checked against `cspace_size`, so the one obligation this
/// code cannot discharge for itself is the truthfulness of that length. Call
/// under `cap_lock`: these read and write the array non-atomically, and a
/// concurrent revoke would otherwise be able to change a capability between the
/// validity check and the use.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_lookup(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    required_rights: u32,
) -> *mut Capability {
    if cspace.is_null() {
        return ptr::null_mut();
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return ptr::null_mut();
    }

    let cap = &mut *cspace.add(slot as usize);

    
    
    if cap.typ == CAP_NULL {
        return ptr::null_mut();
    }
    if (cap.rights & required_rights) != required_rights {
        return ptr::null_mut();
    }

    
    
    if cap.serial == 0 {
        return ptr::null_mut();
    }
    #[cfg(feature = "revoke_hashed_backstop")]
    if hashed_backstop::reads_revoked(cap.serial) {
        return ptr::null_mut();
    }
    cap
}

/// Allocate a fresh derived serial, advancing `*next_serial`, or return 0 when
/// none can be issued. This is the SINGLE implementation of serial allocation:
/// both the Rust derivations and the C `cap_alloc_fresh_serial` go through it,
/// so the two cannot drift.
///
/// THE PROPERTY IS "NEVER THE SAME SERIAL TWICE", and every derived serial is at
/// least `MIN_DERIVED_SERIAL`, so none is 0 or primordial. It does not wrap: at
/// the top of the range it returns 0, and every caller refuses on 0. That end is
/// not reachable (2^64 - 2^32 mints, centuries at a mint a nanosecond); what
/// matters is that if it were, the failure would be a refusal and never a
/// repeated serial. With 32 bits the counter did wrap, after about 4.3 billion
/// mints, and a repeated serial is two capabilities fused into one node of the
/// derivation graph, which is what "one serial, one slot" above rules out.
///
/// A null counter also returns 0. It returned the constant `0xC0DEFFFF` until
/// 2026-10-11, which handed every such caller the same serial.
///
/// # Safety
/// `next_serial` must be null, or point to a valid, writable `u64` -- the
/// kernel's monotonic serial counter, which this reads and advances. Call under
/// `cap_lock`: the read-modify-write is not atomic, and two callers racing here
/// would hand out one serial twice.
#[inline]
unsafe fn assign_fresh_serial(next_serial: *mut u64) -> u64 {
    if next_serial.is_null() {
        return 0;
    }
    let cur = *next_serial;
    let base = if cur < MIN_DERIVED_SERIAL { MIN_DERIVED_SERIAL } else { cur };
    match base.checked_add(1) {
        Some(fresh) => {
            *next_serial = fresh;
            fresh
        }
        None => 0,
    }
}

/// FFI: centralized fresh-serial allocation for the C kernel.
///
/// # Safety
/// As `assign_fresh_serial`, which this is a thin wrapper over: `next_serial`
/// must be null or a valid writable `u64`, and the caller must hold `cap_lock`.
/// A return of 0 means no serial was issued, and the caller must refuse.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_alloc_serial(next_serial: *mut u64) -> u64 {
    assign_fresh_serial(next_serial)
}

/// Mint a capability into `dest_slot`, derived from the one at `src_slot`, with
/// rights masked down to `new_rights & src.rights`. Cannot widen authority: that
/// intersection is the enforcement point for S2 and it is here, not in C.
///
/// # Safety
/// `cspace` must be null, or point to at least `cspace_size` valid
/// `Capability`s -- and `cspace_size` must be the TRUE length of that array, not
/// a larger number the C side hoped was right. Null is handled and every slot
/// index is bounds-checked against `cspace_size`, so the one obligation this
/// code cannot discharge for itself is the truthfulness of that length. Call
/// under `cap_lock`: these read and write the array non-atomically, and a
/// concurrent revoke would otherwise be able to change a capability between the
/// validity check and the use.
/// `next_serial` carries `assign_fresh_serial`'s obligation in addition.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_mint(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    new_rights: u32,
    next_serial: *mut u64,
    _current_task_caps_in_use: u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if dest_slot >= cspace_size || dest_slot >= CNODE_SIZE {
        return false;
    }
    if src_slot >= cspace_size || src_slot >= CNODE_SIZE {
        return false;
    }
    
    if dest_slot < KERNEL_RESERVED_CAPS {
        return false;
    }

    let src = &*cspace.add(src_slot as usize);
    if src.typ == CAP_NULL {
        return false;
    }
    
    if src.serial == 0 {
        return false;
    }
    // Mint and transfer are only ever asked for from ring 3 (SYS_CAP_MINT,
    // SYS_CAP_TRANSFER, SYS_CAP_MOVE). The C side already demands
    // CAP_RIGHT_MINT on the source, which no pipe end is given; this refuses
    // a pipe end whatever rights it carries, so the rule does not rest on
    // every installer remembering to leave MINT off.
    if !copyable_from_ring3(src.typ) {
        return false;
    }

    let dest = &mut *cspace.add(dest_slot as usize);

    
    
    let parent_serial = src.serial;

    let fresh = assign_fresh_serial(next_serial);
    if fresh == 0 {
        return false;
    }

    
    let effective_rights = new_rights & src.rights;

    // The child is a new node with its OWN fresh serial, and names its parent in
    // `badge`, so a revoke of the parent (or of any ancestor) reaches it.
    *dest = Capability {
        typ: src.typ,
        rights: effective_rights,
        object: src.object,
        badge: parent_serial,
        serial: fresh,
        // Attenuation keeps identity: a narrowed copy of a tokened capability
        // names the same thing, with fewer rights. See `Capability::token`.
        token: src.token,
    };
    true
}

/// Copy a capability to `dest_slot` with the source's rights unchanged. This is
/// `rust_cap_mint` with an all-ones mask, so the `& src.rights` intersection
/// still applies and this cannot widen either.
///
/// # Safety
/// `cspace` must be null, or point to at least `cspace_size` valid
/// `Capability`s -- and `cspace_size` must be the TRUE length of that array, not
/// a larger number the C side hoped was right. Null is handled and every slot
/// index is bounds-checked against `cspace_size`, so the one obligation this
/// code cannot discharge for itself is the truthfulness of that length. Call
/// under `cap_lock`: these read and write the array non-atomically, and a
/// concurrent revoke would otherwise be able to change a capability between the
/// validity check and the use.
/// `next_serial` carries `assign_fresh_serial`'s obligation in addition.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_transfer(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u64,
) -> bool {
    rust_cap_mint(cspace, cspace_size, dest_slot, src_slot, !0u32, next_serial, 0)
}

/// FFI: grant (delegate) a capability derived from `src` into ANOTHER task's
/// cspace at `dest_slot`. This is the cross-cspace analogue of `rust_cap_mint`:
/// `src` points at the grantor's own capability (in the grantor's cspace) and
/// `dest_cspace` is the grantee's cspace. It exists so `SYS_CAP_GRANT` writes
/// through the same audited, rights-reducing, lineage-correct logic every other
/// cap write uses, rather than a raw `dest = *src` store in the C kernel.
///
/// Semantics (mirrors mint):
///   - the minted rights are `new_rights & src.rights` (grant can only *reduce*;
///     pass `!0` for the historical "copy full rights" behaviour);
///   - the grantee records the grantor's cap as its parent (`badge = src.serial`)
///     so a later revoke of the grantor's cap sweeps the grantee too, and the
///     derivation tree stays well-formed;
///   - the grantee gets a fresh serial of its own.
///
/// Unlike mint there is intentionally NO `dest_slot < KERNEL_RESERVED_CAPS`
/// floor: grant writes into a *child* the caller already dominates (it holds the
/// child's `CAP_TCB`), and endowing a child's low slots — e.g. its IPC gate at
/// slot 3 — is exactly what grant is for. The C caller enforces the CAP_TCB /
/// admin authority and the `caps_in_use` ceiling under `cap_lock`.
///
/// # Safety
/// `src` must be null or a valid pointer to a live `Capability`; `dest_cspace`
/// must be null or point to at least `dest_cspace_size` `Capability` entries;
/// `next_serial` must be null or a valid `*mut u32`. Called under `cap_lock`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_grant_into(
    src: *const Capability,
    dest_cspace: *mut Capability,
    dest_cspace_size: u32,
    dest_slot: u32,
    new_rights: u32,
    next_serial: *mut u64,
) -> bool {
    if src.is_null() || dest_cspace.is_null() {
        return false;
    }
    if dest_slot >= dest_cspace_size || dest_slot >= CNODE_SIZE {
        return false;
    }
    let s = &*src;
    // Authority cannot be fabricated from an empty or serial-0 (lookup-invalid)
    // source — same guard mint enforces.
    if s.typ == CAP_NULL || s.serial == 0 {
        return false;
    }

    let parent_serial = s.serial;
    let fresh = assign_fresh_serial(next_serial);
    if fresh == 0 {
        return false;
    }
    let effective_rights = new_rights & s.rights;

    let dest = &mut *dest_cspace.add(dest_slot as usize);
    // The grantee is a new node with its own fresh serial, as with mint.
    *dest = Capability {
        typ: s.typ,
        rights: effective_rights,
        object: s.object,
        badge: parent_serial,
        serial: fresh,
        // Delegation keeps identity, exactly as mint does.
        token: s.token,
    };
    true
}

/// FFI: `rust_cap_grant_into` for a grant a ring-3 task asked for
/// (`SYS_CAP_GRANT`), which refuses a source of a type ring 3 may not copy (see
/// `copyable_from_ring3`): a pipe end. The kernel's own delegations (the libc
/// pages, the console endpoint at spawn, a driver's peer, fork) call
/// `rust_cap_grant_into` directly; fork may copy a pipe end through it because
/// it counts every end it copies (`pipe_count_forked_ends`).
///
/// Refuses, and writes nothing, on a pipe end; otherwise exactly
/// `rust_cap_grant_into`.
///
/// # Safety
/// As `rust_cap_grant_into`: `src` must be null or a valid pointer to a live
/// `Capability`; `dest_cspace` must be null or point to at least
/// `dest_cspace_size` `Capability` entries; `next_serial` must be null or a
/// valid `*mut u64`. Called under `cap_lock`, so the source's type cannot
/// change between this check and the copy.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_grant_from_user(
    src: *const Capability,
    dest_cspace: *mut Capability,
    dest_cspace_size: u32,
    dest_slot: u32,
    new_rights: u32,
    next_serial: *mut u64,
) -> bool {
    if src.is_null() || !copyable_from_ring3((*src).typ) {
        return false;
    }
    rust_cap_grant_into(src, dest_cspace, dest_cspace_size, dest_slot, new_rights, next_serial)
}

/// FFI: mint a TOKENED endpoint capability from an untokened one, within the
/// caller's own cspace (`SYS_CAP_MINT_TOKEN`). This is how authority over a
/// service starts: the task that made an endpoint holds MINT on it, and mints the
/// first capability a client will hold, for example the root directory of a
/// filesystem (`docs/design/filesystem.md` §6.1).
///
/// Refuses unless ALL of these hold, and writes nothing when it refuses:
///   - the source is a live `CAP_ENDPOINT` (non-null type, non-zero serial);
///   - the source holds `CAP_RIGHT_MINT`;
///   - the source carries NO token. This is the rule that keeps a token an
///     identity: without it, a client holding a tokened capability with MINT
///     could re-point it at any other token the server has issued;
///   - the requested token is non-zero, since zero means "untokened" and an
///     untokened result would be a plain copy wearing the wrong name.
///
/// The child's rights are `new_rights & src.rights`, minus `CAP_RIGHT_READ`
/// (`TOKEN_STRIPPED_RIGHTS`): a tokened capability can never receive on the
/// endpoint. It cannot mint further tokens either, but that is the tokened-source
/// refusal above doing it, not a stripped right. It records the source as its
/// parent, so revoking the minter's capability sweeps every token minted from it.
///
/// # Safety
/// `cspace` must be null, or point to at least `cspace_size` valid
/// `Capability`s, and `cspace_size` must be the TRUE length of that array. Every
/// slot index is bounds-checked against it; its truthfulness is the one
/// obligation this code cannot discharge. Call under `cap_lock`.
/// `next_serial` carries `assign_fresh_serial`'s obligation in addition.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_mint_token(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    new_rights: u32,
    token: u64,
    next_serial: *mut u64,
) -> bool {
    if cspace.is_null() || token == 0 {
        return false;
    }
    if dest_slot >= cspace_size || dest_slot >= CNODE_SIZE || dest_slot < KERNEL_RESERVED_CAPS {
        return false;
    }
    if src_slot >= cspace_size || src_slot >= CNODE_SIZE || src_slot == dest_slot {
        return false;
    }
    let src = *cspace.add(src_slot as usize);
    if src.typ != CAP_ENDPOINT || src.serial == 0 {
        return false;
    }
    if src.rights & CAP_RIGHT_MINT == 0 || src.token != 0 {
        return false;
    }
    let fresh = assign_fresh_serial(next_serial);
    if fresh == 0 {
        return false;
    }
    *cspace.add(dest_slot as usize) = Capability {
        typ: CAP_ENDPOINT,
        rights: new_rights & src.rights & !TOKEN_STRIPPED_RIGHTS,
        object: src.object,
        badge: src.serial,
        serial: fresh,
        token,
    };
    true
}

/// FFI: the reply-mint (`SYS_IPC_REPLY_CAP`, `docs/design/filesystem.md` §5.1).
/// A server answering a call hands the caller ONE new capability, placed in the
/// slot the caller named, and derived from `src`, which is the capability the
/// caller's request was sent through. `src` and `dest_cspace` are both the
/// CALLER's: the server supplies only the token and the rights it asks for.
///
/// What makes this safe to give a server that holds no mint authority of its own:
///   - the child's rights are `new_rights & src.rights`, minus
///     `TOKEN_STRIPPED_RIGHTS`. A server can narrow the caller's authority and
///     can never widen it, whatever it asks for;
///   - the child names the same endpoint as `src` (the server's own), so a
///     server cannot mint a capability to anyone else's service;
///   - the child records `src` as its parent, so revoking the capability a
///     directory was opened through revokes everything opened through it;
///   - the destination must be EMPTY. The caller chose the slot, but a server
///     that could overwrite it could destroy a capability the caller holds.
///
/// Writes nothing when it refuses.
///
/// # Safety
/// `src` must be null or point to a live `Capability`; `dest_cspace` must be
/// null or point to at least `dest_cspace_size` `Capability` entries, that
/// length being true; `next_serial` must be null or a valid `*mut u32`. `src`
/// may point INTO `dest_cspace` (it usually does): it is read once, by value,
/// before anything is written. Call under `cap_lock`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_reply_mint(
    src: *const Capability,
    dest_cspace: *mut Capability,
    dest_cspace_size: u32,
    dest_slot: u32,
    new_rights: u32,
    token: u64,
    next_serial: *mut u64,
) -> bool {
    if src.is_null() || dest_cspace.is_null() || token == 0 {
        return false;
    }
    if dest_slot >= dest_cspace_size || dest_slot >= CNODE_SIZE || dest_slot < KERNEL_RESERVED_CAPS {
        return false;
    }
    let s = *src;
    if s.typ != CAP_ENDPOINT || s.serial == 0 {
        return false;
    }
    if (*dest_cspace.add(dest_slot as usize)).typ != CAP_NULL {
        return false;
    }
    let fresh = assign_fresh_serial(next_serial);
    if fresh == 0 {
        return false;
    }
    *dest_cspace.add(dest_slot as usize) = Capability {
        typ: CAP_ENDPOINT,
        rights: new_rights & s.rights & !TOKEN_STRIPPED_RIGHTS,
        object: s.object,
        badge: s.serial,
        serial: fresh,
        token,
    };
    true
}

/// Clear a capability slot to the null capability.
///
/// # Safety
/// Takes a `&mut` and dereferences nothing raw, so it has no preconditions of
/// its own; it is `unsafe` because every caller reaches it from a raw pointer
/// walk and the reference must therefore be unaliased for the call, which in
/// this kernel means `cap_lock` is held.
#[inline]
unsafe fn nullify(c: &mut Capability) {
    c.typ = CAP_NULL;
    c.rights = 0;
    c.object = 0;
    c.badge = 0;
    c.serial = 0;
    // A slot that is later reused must not inherit an identity: the token is
    // what a server authorises on, so a stale one is a forged one.
    c.token = 0;
}

/// Transient `typ` sentinels used only inside `revoke_subtree`, between its mark
/// and sweep phases, to record subtree membership without a side array — see the
/// documentation there for why the mark lives in `typ` and why that is safe.
///
/// These must never collide with a real capability type. They sit at the top of
/// the `u32` range and the assertion below pins that: types are assigned upward
/// from `CAP_NULL == 0` and there are a few dozen of them, so a collision would
/// require the type space to grow by four billion.
const CAP_MARK_NEW: u32 = 0xFFFF_FFFF;
const CAP_MARK_DONE: u32 = 0xFFFF_FFFE;
const _: () = {
    assert!(CAP_MARK_NEW != CAP_NULL);
    assert!(CAP_MARK_DONE != CAP_NULL);
    assert!(CAP_MARK_NEW != CAP_MARK_DONE);
    // `PipeTally::note` is a no-op on a marked capability because a sentinel is
    // not CAP_PIPE; the sweep relies on that not to count a pipe end twice.
    assert!(CAP_MARK_NEW != CAP_PIPE);
    assert!(CAP_MARK_DONE != CAP_PIPE);
};

/// Where a revocation records the pipe ends it removes (LIMITATIONS 1.14, S134).
///
/// A pipe end is two pieces of state: the capability, and a count of ends in the
/// C kernel's pipe table, which frees the pipe when its readers and writers both
/// reach zero. This module empties slots and knows nothing of that table, so a
/// sweep that removed a pipe end and said nothing would leave the count one too
/// high, and the peer would wait for an EOF that never comes. So every pipe end
/// a revocation empties is counted here, by pipe and direction, and `cap_revoke`
/// subtracts the counts from the table before it releases `cap_lock`.
///
/// Counted in the same step that decides the slot is emptied, not by comparing
/// before and after: a capability marked as a descendant loses its type to the
/// mark, so `mark_children_of` counts it as it marks it (every marked capability
/// is emptied by the sweep that follows, with no return in between), and the
/// sweep counts the ones it empties unmarked (the target, a holder of the root's
/// serial, the by-object match).
///
/// The cells are the C side's: `[2 * pipe]` counts reader ends and
/// `[2 * pipe + 1]` writer ends, `len` cells in all. Every write is checked
/// against `len`, so an end naming a pipe outside the table is not counted (none
/// can exist: `h_pipe` names a pipe it allocated, and every other end is derived
/// from one of its two), and a null pointer counts nothing. The direction is the
/// end's WRITE right, the same test the C close paths use, so a revoke and a close
/// of the same end always release the same direction.
#[derive(Clone, Copy)]
struct PipeTally {
    cells: *mut u32,
    len: u32,
}

impl PipeTally {
    /// Counts nothing: for the single-cspace tests and proofs that do not
    /// involve pipes.
    #[cfg(kani)]
    const NONE: PipeTally = PipeTally { cells: ptr::null_mut(), len: 0 };

    /// Count `c` if it is a pipe end. Call it exactly once for each capability
    /// the revocation empties, before the slot is emptied.
    ///
    /// # Safety
    /// `self.cells` must be null or point to `self.len` writable `u32`s that
    /// nothing else accesses during the call (in the kernel, `cap_lock` is held
    /// and the cells are `cap_revoke`'s own).
    #[inline]
    unsafe fn note(self, c: &Capability) {
        if c.typ != CAP_PIPE || self.cells.is_null() {
            return;
        }
        let pipes = u64::from(self.len / 2);
        if c.object >= pipes {
            return;
        }
        let writer = usize::from(c.rights & CAP_RIGHT_WRITE != 0);
        // c.object < len / 2 <= u32::MAX / 2, so this neither overflows nor
        // reaches past cell len - 1.
        let cell = &mut *self.cells.add(c.object as usize * 2 + writer);
        *cell = cell.saturating_add(1);
    }
}

/// Mark every not-yet-marked capability whose `badge` names `parent_serial` — the
/// direct children of one node of the derivation tree — as `CAP_MARK_NEW`.
///
/// Capabilities with `badge == 0` have no parent and are skipped, as are ones
/// already carrying either sentinel, so a capability is marked at most once. That
/// is what bounds the caller's fixpoint loop.
///
/// # Safety
/// As `revoke_subtree`: `spaces` must be null or point to `space_count` valid
/// `CSpaceDesc`s whose `caps`/`size` describe live arrays, and `tally` must
/// satisfy `PipeTally::note`. Called under `cap_lock`.
#[inline]
// Unused when the [I-3] control arm is compiled in, which selects the legacy
// bounded closure instead. Not dead code in any shipping configuration.
#[cfg_attr(feature = "revoke_legacy_bounded", allow(dead_code))]
unsafe fn mark_children_of(
    spaces: *const CSpaceDesc,
    space_count: u32,
    parent_serial: u64,
    tally: PipeTally,
) {
    if parent_serial == 0 {
        return;
    }
    for s in 0..space_count {
        let d = &*spaces.add(s as usize);
        if d.caps.is_null() {
            continue;
        }
        let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
        for i in 0..limit {
            let c = &mut *d.caps.add(i as usize);
            if c.typ == CAP_NULL || c.typ == CAP_MARK_NEW || c.typ == CAP_MARK_DONE {
                continue;
            }
            if c.serial == 0 || c.badge == 0 {
                continue;
            }
            if c.badge == parent_serial {
                // Counted now, while `typ` still says what it is: the mark
                // replaces it, and the sweep empties every marked slot.
                tally.note(c);
                c.typ = CAP_MARK_NEW;
            }
        }
    }
}

/// Revoke the derivation *subtree* rooted at `root_serial` across every cspace in
/// `spaces`: null the root's transitive descendants — a capability whose `badge`
/// chains back to `root_serial` through the derivation tree (each derived cap
/// records its parent's serial in `badge`) — and NOTHING else. Ancestors,
/// unrelated siblings, and independent capabilities that merely share the same
/// `object` are left intact.
///
/// This is the least-privilege-correct revocation semantics (audit A1). The
/// previous implementation matched an object/badge/serial *equivalence set*,
/// which also revoked the grantor's own capability and every same-`object` peer —
/// far broader than "this capability and everything derived from it".
///
/// The root capability itself is expected to be nulled by the caller already for
/// the `*_global` / `rust_cap_revoke` paths (so it is not double-counted); its
/// serial is still passed here as the closure seed, and any un-nulled cap holding
/// `root_serial` (e.g. the revoke-by-values path) is nulled by the sweep below.
///
/// Descendants are found by marking IN PLACE and iterating to a fixpoint, so the
/// closure is exact at any subtree size and no capability outside the subtree is
/// ever touched (finding **[I-3]**, roadmap 1.6).
///
/// Until 2026-08-16 the closure accumulated revoked serials in a fixed
/// `MAX_REVOKE_LINEAGE`-entry array, and a subtree larger than that set
/// `overflow`, whereupon the null pass ALSO nulled every capability sharing
/// `root_object`. That fallback was safe in the "no descendant survives"
/// direction — mint/transfer/grant preserve `object`, so the object set is a
/// superset of the descendant set — but it is reachable from ring 3: deriving
/// more than `MAX_REVOKE_LINEAGE` capabilities and then revoking the root made
/// the kernel destroy every *unrelated peer's* capability naming the same object.
/// An unprivileged task could therefore revoke authority it had never been
/// delegated, which is a denial of service against a peer and, worse, an
/// over-broad revocation the capability graph does not describe.
///
/// The replacement needs no side array and no allocation, which matters in a
/// `no_std` kernel where the previous bound existed precisely because there is
/// nowhere to grow one. The mark lives in the capability's own `typ` field, in
/// two states, while `serial` and `badge` are left intact so the derivation tree
/// is still readable mid-sweep:
///
///   `CAP_MARK_NEW`  — in the subtree; its children have not been expanded yet.
///   `CAP_MARK_DONE` — in the subtree; its children have been expanded.
///
/// Each capability is marked at most once and moves `NEW -> DONE` exactly once,
/// so the loop performs at most one expansion per capability and terminates
/// without needing a depth bound or a cycle check. Cost is O(subtree × slots) —
/// proportional to what the revoker actually derived, rather than to the whole
/// system, and revocation is not a hot path.
///
/// The `typ` sentinels are only ever observed between the mark and sweep phases
/// below, both of which run under `cap_lock` with no early return between them.
/// Should that ever cease to hold, a capability left carrying a sentinel is not
/// a valid type and fails every type check — the fail-closed direction.
///
/// Every pipe end it empties is counted in `tally` (see `PipeTally`), so the
/// caller can release the ends in the pipe table.
///
/// # Safety
/// `spaces` must be null or point to `space_count` valid `CSpaceDesc`s whose
/// `caps`/`size` describe live arrays, and `tally` must satisfy
/// `PipeTally::note`. Called under `cap_lock`.
/// Carries S3 (a revoke reaches the whole derivation subtree) and S4 (it
/// reaches nothing else: no ancestor, sibling or independent peer). The
/// exactness half is what `--features=revoke_legacy_bounded` falsifies.
#[cfg(not(feature = "revoke_legacy_bounded"))]
unsafe fn revoke_subtree(
    spaces: *const CSpaceDesc,
    space_count: u32,
    root_serial: u64,
    root_object: u64,
    tally: PipeTally,
) {
    if spaces.is_null() {
        return;
    }

    // Revoke-by-object has no lineage seed by definition, so the object sweep is
    // not a fallback there — it is the only complete answer, and it is exact for
    // a shared-object lineage. This is the one path that still nulls by object.
    let by_object = root_serial == 0;

    if !by_object {
        // Seed: mark the root's direct children. The root capability itself is
        // handled by the sweep below via `serial == root_serial`, so it is not
        // marked here and cannot be mistaken for its own child.
        mark_children_of(spaces, space_count, root_serial, tally);

        // Expand to a fixpoint. Each pass promotes every NEW mark to DONE and
        // marks that capability's children NEW; a mark created late in a pass is
        // picked up by the next one. Terminates because a capability is marked at
        // most once and promoted at most once.
        loop {
            let mut progress = false;
            for s in 0..space_count {
                let d = &*spaces.add(s as usize);
                if d.caps.is_null() {
                    continue;
                }
                let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
                for i in 0..limit {
                    let c = &mut *d.caps.add(i as usize);
                    if c.typ != CAP_MARK_NEW {
                        continue;
                    }
                    c.typ = CAP_MARK_DONE;
                    let serial = c.serial;
                    if serial != 0 {
                        mark_children_of(spaces, space_count, serial, tally);
                    }
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }

    // Sweep. Null every marked capability (the exact descendant set), the root's
    // own serial, and — only on the by-object path — every cap sharing the root
    // object.
    for s in 0..space_count {
        let d = &*spaces.add(s as usize);
        if d.caps.is_null() {
            continue;
        }
        let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
        for i in 0..limit {
            let c = &mut *d.caps.add(i as usize);
            if c.typ == CAP_NULL {
                continue;
            }
            let marked = c.typ == CAP_MARK_NEW || c.typ == CAP_MARK_DONE;
            let hit = marked
                || (root_serial != 0 && c.serial == root_serial)
                || (by_object && root_object != 0 && c.object == root_object);
            if hit {
                // A marked end was counted when it was marked; its `typ` is
                // now a sentinel, so this counts only the unmarked hits.
                tally.note(c);
                // Emptying the slot is the whole record of the revoke: no
                // other slot holds this serial (one serial, one slot), and
                // none will again.
                note_revoked(c.serial);
                nullify(c);
                if !d.caps_in_use.is_null() && *d.caps_in_use > 0 {
                    *d.caps_in_use -= 1;
                }
            }
        }
    }
}

/// CONTROL ARM for **[I-3]** — the pre-2026-08-16 revocation closure, restored
/// verbatim behind `--features revoke_legacy_bounded` so the defect stays
/// reproducible on demand and the regression tests above have a failing arm.
///
/// Descendants accumulate in a fixed `MAX_REVOKE_LINEAGE` array. A subtree larger
/// than that sets `overflow`, and the null pass then also nulls every capability
/// sharing `root_object`. That is safe in the "no descendant survives" direction
/// but destroys unrelated peers' capabilities, and ring 3 can force it by
/// deriving more than 256 capabilities before revoking the root.
///
/// # Safety
/// As the non-legacy `revoke_subtree`.
#[cfg(feature = "revoke_legacy_bounded")]
unsafe fn revoke_subtree(
    spaces: *const CSpaceDesc,
    space_count: u32,
    root_serial: u64,
    root_object: u64,
    tally: PipeTally,
) {
    const MAX_REVOKE_LINEAGE: usize = 256;

    fn set_contains(set: &[u64], v: u64) -> bool {
        let mut i = 0;
        while i < set.len() {
            if set[i] == v {
                return true;
            }
            i += 1;
        }
        false
    }

    if spaces.is_null() {
        return;
    }
    let mut revoked = [0u64; MAX_REVOKE_LINEAGE];
    let mut n = 0usize;
    let mut overflow = false;

    if root_serial != 0 {
        revoked[0] = root_serial;
        n = 1;
        loop {
            let mut added = false;
            for s in 0..space_count {
                let d = &*spaces.add(s as usize);
                if d.caps.is_null() {
                    continue;
                }
                let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
                for i in 0..limit {
                    let c = &*d.caps.add(i as usize);
                    if c.typ == CAP_NULL || c.serial == 0 || c.badge == 0 {
                        continue;
                    }
                    if set_contains(&revoked[..n], c.badge)
                        && !set_contains(&revoked[..n], c.serial)
                    {
                        if n < MAX_REVOKE_LINEAGE {
                            revoked[n] = c.serial;
                            n += 1;
                            added = true;
                        } else {
                            overflow = true;
                        }
                    }
                }
            }
            if !added {
                break;
            }
        }
    } else {
        overflow = true;
    }

    for s in 0..space_count {
        let d = &*spaces.add(s as usize);
        if d.caps.is_null() {
            continue;
        }
        let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
        for i in 0..limit {
            let c = &mut *d.caps.add(i as usize);
            if c.typ == CAP_NULL {
                continue;
            }
            let hit = set_contains(&revoked[..n], c.serial)
                || (overflow && root_object != 0 && c.object == root_object);
            if hit {
                // No marks on this path, so every hit still has its type.
                tally.note(c);
                note_revoked(c.serial);
                nullify(c);
                if !d.caps_in_use.is_null() && *d.caps_in_use > 0 {
                    *d.caps_in_use -= 1;
                }
            }
        }
    }
}

/// Is this slot one of the kernel's non-revocable primordial roots?
///
/// # Safety
/// `cspace` must point to an array with at least `slot + 1` valid
/// `Capability`s. Unlike its neighbours this does NOT bounds-check `slot`
/// itself: it is a file-private helper and every caller has already validated
/// the index against `cspace_size`. Adding a caller that has not is the way to
/// make this read out of bounds.
#[inline]
unsafe fn is_primordial_root(cspace: *mut Capability, slot: u32) -> bool {
    let s = (*cspace.add(slot as usize)).serial;
    slot < KERNEL_RESERVED_CAPS && serial_is_primordial(s)
}

/// Single-cspace revoke. Used for moves and for revoking a CAP_REVOCATION
/// helper slot. For system-wide revocation use `rust_cap_revoke_global`.
///
/// Every pipe end it empties is counted in `pipe_tally` (see `PipeTally`),
/// exactly as the global revoke counts them, so no path that empties a pipe end
/// leaves its count behind.
///
/// # Safety
/// `cspace` must be null, or point to at least `cspace_size` valid
/// `Capability`s -- and `cspace_size` must be the TRUE length of that array, not
/// a larger number the C side hoped was right. Null is handled and every slot
/// index is bounds-checked against `cspace_size`, so the one obligation this
/// code cannot discharge for itself is the truthfulness of that length. Call
/// under `cap_lock`: these read and write the array non-atomically, and a
/// concurrent revoke would otherwise be able to change a capability between the
/// validity check and the use. `pipe_tally` must be null or point to
/// `pipe_tally_len` writable `u32`s; the length is trusted in the same way, and
/// every index is checked against it.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    _next_serial: *mut u64,
    pipe_tally: *mut u32,
    pipe_tally_len: u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(cspace, slot) {
        return false;
    }

    let target = &mut *cspace.add(slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;
    let tally = PipeTally { cells: pipe_tally, len: pipe_tally_len };

    tally.note(target);
    nullify(target);
    note_revoked(ts);

    // Descendant-only sweep of this one cspace (audit A1). The target slot is
    // already nulled, so the closure only reaches capabilities derived from it.
    let desc = CSpaceDesc {
        caps: cspace,
        size: cspace_size,
        caps_in_use: core::ptr::null_mut(),
    };
    revoke_subtree(&desc as *const CSpaceDesc, 1, ts, to, tally);
    true
}

/// Descriptor for one capability space, passed across the FFI so the entire
/// system-wide revocation sweep happens inside one Rust call.
#[repr(C)]
pub struct CSpaceDesc {
    pub caps: *mut Capability,
    pub size: u32,
    /// Optional pointer to the owning task's `caps_in_use` counter; null to skip
    /// accounting (e.g. the kernel root cnode).
    pub caps_in_use: *mut u32,
}

/// SYSTEM-WIDE capability revocation — the authoritative revocation entry point.
///
/// Revokes the capability at `target_slot` of `target_cspace` and then sweeps
/// EVERY cspace in `spaces` (which the caller populates with all live tasks'
/// cspaces plus the kernel root cnode) for the target's derivation *subtree* —
/// the capabilities transitively derived from it (mint/transfer/grant) — nulling
/// them. Every slot holding one of those serials is emptied, and no other slot
/// holds one (one serial, one slot), so nothing that was revoked stays usable.
///
/// INVARIANT (see ARCHITECTURE.md): after this returns true, no live cspace
/// retains the target capability or any capability derived from it — and, per
/// audit A1, capabilities that are NOT descendants (the grantor/ancestor, unrelated
/// siblings, independent capabilities to the same object) are left intact. This is
/// what makes revocation both complete (no descendant survives its ancestor's
/// revocation) and least-privilege-correct (revoking a delegated capability does
/// not strip the grantor's own authority).
///
/// Must be called by C under `cap_lock` so the `spaces` snapshot is stable.
///
/// Every pipe end the revoke empties, the target included, is counted in
/// `pipe_tally` (see `PipeTally`). The caller must release those ends in the pipe
/// table before it drops `cap_lock`, or a pipe's count stays above the ends that
/// exist and its peer never sees EOF (LIMITATIONS 1.14).
///
/// # Safety
/// `target_cspace` carries the obligation described on `rust_cap_lookup`.
/// `spaces` must be null, or point to `space_count` valid `CSpaceDesc`s, each of
/// whose `caps`/`size` pairs describes a live array with a truthful length --
/// every cspace in the system, since the sweep is system-wide and a cspace
/// omitted here keeps a derived copy the revoke was supposed to reach.
/// `caps_in_use` pointers must be null or valid writable `u32`s. `cap_lock` must
/// be held for the whole call: the snapshot of `tasks[]` this describes has to
/// stay stable across a sweep that visits every task. `pipe_tally` must be null
/// or point to `pipe_tally_len` writable `u32`s, a length trusted like the
/// cspace sizes; every index into it is checked against that length.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_global(
    target_cspace: *mut Capability,
    target_cspace_size: u32,
    target_slot: u32,
    target_caps_in_use: *mut u32,
    spaces: *const CSpaceDesc,
    space_count: u32,
    _next_serial: *mut u64,
    pipe_tally: *mut u32,
    pipe_tally_len: u32,
) -> bool {
    if target_cspace.is_null() {
        return false;
    }
    if target_slot >= target_cspace_size || target_slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(target_cspace, target_slot) {
        return false;
    }

    let target = &mut *target_cspace.add(target_slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;
    let tally = PipeTally { cells: pipe_tally, len: pipe_tally_len };

    tally.note(target);
    nullify(target);
    if !target_caps_in_use.is_null() && *target_caps_in_use > 0 {
        *target_caps_in_use -= 1;
    }

    note_revoked(ts);

    // Sweep every supplied cspace for the target's derivation subtree only — the
    // target's descendants, not its ancestors, siblings, or same-object peers
    // (audit A1). The target slot is already null, so it cannot re-match.
    revoke_subtree(spaces, space_count, ts, to, tally);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;

    fn cap(typ: u32, rights: u32, object: u64, badge: u64, serial: u64) -> Capability {
        Capability { typ, rights, object, badge, serial, token: 0 }
    }

    /// What `cap_revalidate` in capability.c asks of a snapshot at the point of
    /// use: the slot still resolves, and still holds the same serial and object.
    /// One serial, one slot, so a revoke (which empties the slot) or a
    /// replacement (which brings a new serial) both fail it.
    unsafe fn still_holds(cs: *mut Capability, size: u32, slot: u32, snap: &Capability) -> bool {
        let p = rust_cap_lookup(cs, size, slot, 0);
        !p.is_null() && (*p).serial == snap.serial && (*p).object == snap.object
    }

    /// Regression: a derived capability minted into a *second* task's cspace
    /// must be revoked when the parent is revoked in the first task — the system-wide revocation invariant.
    #[test]
    fn test_global_revoke_reaches_other_task_cspace() {
        let mut a = [cap(0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0); 16];

        // Task A holds the parent CAP_FRAME (object 0x5000, serial 0x4000).
        a[4] = cap(1, 0x3f, 0x5000, 0, 0x4000);
        // Task B holds a derived copy: badge == parent serial, same object,
        // reduced rights, its own fresh serial — exactly what cap_mint produces.
        b[7] = cap(1, 0x03, 0x5000, 0x4000, 0x9001);

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;

        unsafe {
            let a_ptr = a.as_mut_ptr();
            let b_ptr = b.as_mut_ptr();
            // Precondition: B's derived cap is currently usable.
            assert!(!rust_cap_lookup(b_ptr, 16, 7, 0x1).is_null());

            let spaces = [
                CSpaceDesc { caps: a_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];

            let ok = rust_cap_revoke_global(
                a_ptr,
                16,
                4,
                addr_of_mut!(ciu_a),
                spaces.as_ptr(),
                2,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            );
            assert!(ok);

            // Parent revoked in task A.
            assert_eq!(a[4].typ, CAP_NULL);
            assert!(rust_cap_lookup(a_ptr, 16, 4, 0x1).is_null());

            // Derived copy in the OTHER task's cspace is gone — the core fix.
            assert_eq!(b[7].typ, CAP_NULL,
                "derived capability in another task must be revoked system-wide");
            assert!(rust_cap_lookup(b_ptr, 16, 7, 0x1).is_null());

            // No slot in either cspace still holds either serial: one serial,
            // one slot, and the revoke emptied it.
            assert!(a.iter().chain(b.iter()).all(|c| c.serial != 0x4000 && c.serial != 0x9001),
                "a revoked serial must not survive in any slot");

            // Accounting: both tasks' caps_in_use were decremented exactly once.
            assert_eq!(ciu_a, 0);
            assert_eq!(ciu_b, 0);
        }
    }

    /// A capability for a *different* object/lineage in another cspace must
    /// survive an unrelated revocation (no over-broad nulling).
    #[test]
    fn test_global_revoke_does_not_touch_unrelated() {
        let mut a = [cap(0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0); 16];
        a[4] = cap(1, 0x3f, 0x7000, 0, 0x7700);
        b[7] = cap(1, 0x3f, 0x8000, 0, 0x8800); // unrelated lineage (distinct serial)

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;
        unsafe {
            let a_ptr = a.as_mut_ptr();
            let b_ptr = b.as_mut_ptr();
            let spaces = [
                CSpaceDesc { caps: a_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            let ok = rust_cap_revoke_global(
                a_ptr, 16, 4, addr_of_mut!(ciu_a), spaces.as_ptr(), 2, core::ptr::null_mut(), core::ptr::null_mut(), 0);
            assert!(ok);
            assert!(!rust_cap_lookup(b_ptr, 16, 7, 0x1).is_null(),
                "unrelated capability must not be revoked");
            assert_eq!(ciu_b, 1);
        }
    }

    #[test]
    fn test_lookup_and_mint_basic() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 42, badge: 0, serial: 0x1000, token: 0 };

        let mut next = 0x1001u64;

        unsafe {
            let ok = rust_cap_mint(
                cspace.as_mut_ptr(),
                16,
                5,
                0,
                0x3,
                &mut next as *mut u64,
                0,
            );
            assert!(ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 5, 0x1);
            assert!(!looked.is_null());
            let c5 = &*looked;
            assert_eq!(c5.typ, 1);
            assert_eq!(c5.rights, 0x3);
            assert_eq!(c5.badge, 0x1000);
            assert!(c5.serial > 0x1000);
        }
    }

    #[test]
    fn test_revoke_clears_and_serial_is_fresh() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 99, badge: 0, serial: 0x2000, token: 0 };

        let mut next = 0x2001u64;
        unsafe {
            let mint_ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 6, 0, 0x7, &mut next, 0);
            assert!(mint_ok);
            let child_before = *cspace.as_ptr().add(6);
            assert_eq!(child_before.badge, 0x2000);
            assert!(child_before.serial >= MIN_DERIVED_SERIAL, "the child has a serial of its own");

            
            let rev_ok = rust_cap_revoke(cspace.as_mut_ptr(), 16, 0, core::ptr::null_mut(), core::ptr::null_mut(), 0);
            assert!(rev_ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 6, 0x1);
            assert!(looked.is_null(), "derived cap must be revoked together with parent (badge lineage)");
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 0, 0).is_null());
        }
    }

    /// LIMITATIONS 2.23, at unit scale. One live capability, then many sibling
    /// copies minted from it and revoked one after another. Every revoke is of a
    /// capability unrelated to the live one except as its child, and none may
    /// make it unusable. Under the removed hashed generation table the live
    /// capability's cell was bumped by some revoke well inside 40,000 rounds; the
    /// `revoke_hashed_backstop` control arm puts that table's shape back, and this
    /// test fails under it.
    #[test]
    fn test_unrelated_revokes_never_invalidate_a_live_capability() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        cs[4] = cap(3 /*CAP_ENDPOINT*/, 0x3f, 0xD000, 0, MIN_DERIVED_SERIAL + 7);
        let mut next = MIN_DERIVED_SERIAL + 100;
        unsafe {
            let p = cs.as_mut_ptr();
            for round in 0..40_000u32 {
                assert!(rust_cap_mint(p, 16, 6, 4, 0x1, &mut next, 0),
                    "round {round}: minting from the live capability was refused");
                assert!(rust_cap_revoke(p, 16, 6, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            }
            assert!(!rust_cap_lookup(p, 16, 4, 0x3f).is_null(),
                "40,000 unrelated revokes must leave the live capability usable");
        }
    }

    #[test]
    fn test_strict_rights_and_no_escalation() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 16];
        cspace[0] = Capability { typ: 5, rights: 0b0011, object: 7, badge: 0, serial: 0x3000, token: 0 };

        let mut next = 0x3001u64;
        unsafe {
            
            let ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 4, 0, 0xFFFF, &mut next, 0);
            assert!(ok);
            let child = &*rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0);
            
            assert_eq!(child.rights, 0b0011);
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0b0100).is_null());
        }
    }

    /// Serial allocation (the C kernel routes cap_alloc_fresh_serial through this
    /// FFI) must advance monotonically and never hand back a serial in the
    /// reserved primordial range or 0, never wrap, and refuse at the top of the
    /// range rather than repeat a serial. Uses only a local counter, so it is
    /// fully deterministic under parallel tests.
    #[test]
    fn test_alloc_serial_stays_above_reserved_and_nonzero() {
        unsafe {
            // Starting below the floor snaps up to the first derived serial.
            let mut s: u64 = 0;
            let a = rust_cap_alloc_serial(&mut s);
            assert!(a >= MIN_DERIVED_SERIAL);
            assert_eq!(s, a, "counter is advanced in place");
            let b = rust_cap_alloc_serial(&mut s);
            assert!(b > a && b >= MIN_DERIVED_SERIAL);

            // At the wrap boundary it must not yield 0 or dip below the floor.
            // 2^32 serials on, where a 32-bit counter would have wrapped, a
            // 64-bit one just carries on.
            let mut w: u64 = MIN_DERIVED_SERIAL + u32::MAX as u64;
            let f = rust_cap_alloc_serial(&mut w);
            assert_eq!(f, MIN_DERIVED_SERIAL + u32::MAX as u64 + 1,
                "2^32 mints in is an ordinary step");

            // At the very top it refuses (0) and leaves the counter where it
            // was, so every later call refuses too: never a repeated serial.
            let mut top: u64 = u64::MAX;
            assert_eq!(rust_cap_alloc_serial(&mut top), 0);
            assert_eq!(top, u64::MAX);
            assert_eq!(rust_cap_alloc_serial(&mut top), 0);

            // A null counter refuses rather than dereferencing null.
            assert_eq!(rust_cap_alloc_serial(core::ptr::null_mut()), 0);
        }
    }

    /// A primordial root capability (serial prefix `0xC0DE`, sitting in a
    /// kernel-reserved slot) must survive BOTH single-cspace and system-wide
    /// revocation — the check refuses before any mutation, so the cap stays
    /// intact and usable. This is what stops a userspace path from revoking a
    /// system-critical root capability.
    #[test]
    fn test_primordial_root_cannot_be_revoked() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        // slot 2 is within KERNEL_RESERVED_CAPS (4); the serial carries the
        // primordial 0xC0DE prefix.
        cs[2] = cap(9 /*CAP_ENCRYPTED_STORAGE*/, 0x3f, 0xA011, 0, 0xC0DE0002);
        unsafe {
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap is usable to begin with");

            // Single-cspace revoke refuses and leaves the slot untouched.
            assert!(!rust_cap_revoke(cs.as_mut_ptr(), 16, 2, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            assert_eq!(cs[2].serial, 0xC0DE0002, "primordial cap must be untouched");

            // System-wide revoke refuses too, and performs no sweep. One
            // `as_mut_ptr()`, reused -- see test_caps_in_use_never_underflows.
            let cs_ptr = cs.as_mut_ptr();
            let spaces = [CSpaceDesc { caps: cs_ptr, size: 16, caps_in_use: core::ptr::null_mut() }];
            assert!(!rust_cap_revoke_global(
                cs_ptr, 16, 2, core::ptr::null_mut(),
                spaces.as_ptr(), 1, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            assert_eq!(cs[2].typ, 9);
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap remains usable after an attempted revocation");
        }
    }

    /// `rust_cap_transfer` copies a capability with the source's full (unmasked)
    /// rights and the parent's serial as its badge, and the copy shares the
    /// parent's lineage: revoking the source clears the transferred copy too.
    #[test]
    fn test_transfer_copies_rights_and_shares_lineage() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        cs[4] = cap(4 /*CAP_FRAME*/, 0x3f, 0xA200, 0, 0xA201);
        let mut next = 0x20000u64;
        unsafe {
            assert!(rust_cap_transfer(cs.as_mut_ptr(), 16, 8, 4, &mut next));
            let d = cs[8];
            assert_eq!(d.typ, 4);
            assert_eq!(d.rights, 0x3f, "transfer preserves the source's full rights");
            assert_eq!(d.object, 0xA200);
            assert_eq!(d.badge, 0xA201, "the copy records the source serial as its badge");
            assert!(d.serial >= MIN_DERIVED_SERIAL && d.serial != 0xA201,
                "the copy gets a fresh serial, distinct from the source");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 8, 0x3f).is_null());

            // Revoking the source lineage clears the transferred copy as well.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            assert_eq!(cs[4].typ, CAP_NULL);
            assert_eq!(cs[8].typ, CAP_NULL,
                "a transferred copy is revoked together with its source (shared lineage)");
        }
    }

    /// A snapshot a caller took before a revoke fails the re-check at the point
    /// of use (`cap_revalidate`: same slot, same serial), both straight after the
    /// revoke and after something new is installed in the slot (the TOCTOU
    /// close, finding 3.3).
    ///
    /// This exercised `rust_cap_revoke_by_values` until 2026-09-10. That export
    /// described itself as "retained for compatibility" and had no caller in the
    /// kernel, in Rust or in any other test, so it was deleted -- but the
    /// property is real and belongs to the path the kernel actually takes, which
    /// is `rust_cap_revoke_global`. Re-pointed rather than deleted with it: the
    /// coverage was never about which entry point was called.
    #[test]
    fn test_revoke_invalidates_pre_revoke_snapshot() {
        let obj = 0xA300u64;
        let serial: u64 = 0xA301;
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        let mut next = MIN_DERIVED_SERIAL;
        unsafe {
            cs[5] = cap(3 /*CAP_ENDPOINT*/, 0x3f, obj, 0, serial);
            cs[6] = cap(3, 0x3f, obj, 0, 0xA302);
            // What a caller snapshotted for a later revalidate-at-use.
            let snapshot = cs[5];
            // ONE `as_mut_ptr()`, reused -- taking it twice retags `cs` and
            // invalidates the pointer already stored in `spaces`. The C kernel
            // passes one `struct capability *`, which is one provenance.
            let cs_ptr = cs.as_mut_ptr();
            assert!(still_holds(cs_ptr, 16, 5, &snapshot), "snapshot is valid before the revoke");

            let mut ciu = 1u32;
            let spaces = [CSpaceDesc { caps: cs_ptr, size: 16, caps_in_use: addr_of_mut!(ciu) }];
            assert!(rust_cap_revoke_global(
                cs_ptr, 16, 5, addr_of_mut!(ciu), spaces.as_ptr(), 1, core::ptr::null_mut(), core::ptr::null_mut(), 0));

            // The live slot is emptied, so the snapshot fails its re-check...
            assert_eq!((*cs_ptr.add(5)).typ, CAP_NULL);
            assert!(!still_holds(cs_ptr, 16, 5, &snapshot),
                "a pre-revoke snapshot must fail the re-check (finding 3.3)");
            // ...and still fails once the slot is reused for the same object:
            // the new capability has a new serial, never the revoked one.
            assert!(rust_cap_mint(cs_ptr, 16, 5, 6, 0x3f, &mut next, 0));
            assert_eq!((*cs_ptr.add(5)).object, obj);
            assert!(!still_holds(cs_ptr, 16, 5, &snapshot),
                "a capability installed in the revoked slot is not the snapshot's");
        }
    }

    /// Minting into a kernel-reserved slot (`0..KERNEL_RESERVED_CAPS`) must be
    /// refused, leaving the slot untouched — this is what stops a userspace mint
    /// from overwriting a primordial root capability by naming its slot.
    #[test]
    fn test_mint_into_reserved_slot_refused() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        // A valid, mint-worthy source in a normal slot.
        cs[5] = cap(1, 0x3f, 0xB100, 0, 0x5100);
        let mut next = 0x10000u64;
        unsafe {
            for dest in 0..KERNEL_RESERVED_CAPS {
                assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, dest, 5, 0x3f, &mut next, 0),
                    "mint into reserved slot {dest} must be refused");
                assert_eq!(cs[dest as usize].typ, CAP_NULL,
                    "reserved slot {dest} must be left untouched");
            }
            // The first non-reserved slot succeeds — proving the guard is the
            // destination slot number, not a broken source or exhausted serial.
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, KERNEL_RESERVED_CAPS, 5, 0x3f, &mut next, 0));
        }
    }

    /// Authority cannot be fabricated from nothing: minting from an empty
    /// (CAP_NULL) source, or from a structurally-present source whose serial is 0
    /// (which lookup also treats as empty), must both be refused with the
    /// destination left untouched.
    #[test]
    fn test_mint_from_invalid_source_refused() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        // slot 6 is empty (CAP_NULL); slot 7 is non-null but carries serial 0.
        cs[7] = cap(1, 0x3f, 0xB101, 0, 0 /* serial */);
        let mut next = 0x10000u64;
        unsafe {
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 8, 6, 0x3f, &mut next, 0),
                "mint from an empty source slot must be refused");
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 8, 7, 0x3f, &mut next, 0),
                "mint from a serial-0 source must be refused");
            assert_eq!(cs[8].typ, CAP_NULL, "destination must stay empty when the source is invalid");
        }
    }

    /// Out-of-range slot indices must fail closed on every entry point — null /
    /// false, never an out-of-bounds access or a mutation. Crucially the hard
    /// `CNODE_SIZE` cap holds even when the caller claims an oversized
    /// `cspace_size`, so a bad size argument cannot authorize an OOB read.
    /// Complements the J5 fuzz targets with a fast, explicit regression check.
    #[test]
    fn test_out_of_range_slots_fail_closed() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        cs[5] = cap(1, 0x3f, 0xB102, 0, 0x5102); // a valid in-range cap
        let mut next = 0x10000u64;
        unsafe {
            // slot >= cspace_size
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 16, 0x1).is_null());
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 99, 0x1).is_null());
            // slot >= CNODE_SIZE even when the caller over-claims the size: the
            // hard cap must reject BEFORE indexing the (only 16-long) array.
            assert!(rust_cap_lookup(cs.as_mut_ptr(), u32::MAX, CNODE_SIZE, 0x1).is_null());

            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 16, 5, 0x3f, &mut next, 0),
                "out-of-range dest must be refused");
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 5, 16, 0x3f, &mut next, 0),
                "out-of-range src must be refused");
            assert!(!rust_cap_revoke(cs.as_mut_ptr(), 16, 16, core::ptr::null_mut(), core::ptr::null_mut(), 0),
                "out-of-range revoke must be refused");

            // None of the above disturbed the one valid in-range capability.
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null());
        }
    }

    /// Revocation is transitive across a multi-level derivation chain, not just
    /// parent->child. Minting a grandchild from a child and then revoking the
    /// original parent must null the child AND the grandchild, because every
    /// derived copy shares the parent's `object` and the sweep matches on it.
    #[test]
    fn test_transitive_revoke_across_derivation_chain() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        // Parent in slot 4.
        cs[4] = cap(1, 0x3f, 0xB600, 0, 0x5600);
        let mut next = 0x30000u64;
        unsafe {
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 5, 4, 0x3f, &mut next, 0)); // child  <- parent
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 6, 5, 0x3f, &mut next, 0)); // grandchild <- child
            for slot in [4u32, 5, 6] {
                assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, slot, 0x1).is_null(),
                    "slot {slot} must be usable before revocation");
            }
            // Revoke the ROOT parent only.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            for slot in [4u32, 5, 6] {
                assert_eq!(cs[slot as usize].typ, CAP_NULL,
                    "slot {slot} in the derivation chain must be revoked with its ancestor");
            }
        }
    }

    /// The `caps_in_use` accounting must saturate at zero: if a revocation sweep
    /// nulls capabilities while the counter is already 0 (an accounting
    /// inconsistency), it must stay 0 rather than wrap to `u32::MAX` — an
    /// underflow would permanently defeat the `MAX_CAPS_PER_TASK` ceiling.
    #[test]
    fn test_caps_in_use_never_underflows() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        // A parent and a same-object derived copy (badge == parent serial).
        cs[4] = cap(1, 0x3f, 0xB700, 0, 0x5700);
        cs[5] = cap(1, 0x03, 0xB700, 0x5700, 0x9700);
        let mut ciu = 0u32; // deliberately understated relative to the two caps present
        unsafe {
            // ONE `as_mut_ptr()`, reused. Two calls is how this test read until
            // 2026-08-24, and each one retags `cs` afresh -- so the second
            // invalidated the pointer the first had already stored in `spaces`,
            // and the sweep's write through it was UB before any library code
            // ran. Miri named it; the C kernel does not do this (it passes one
            // `struct capability *` twice, which is one provenance, not two
            // borrows), so the defect was in the harness rather than in the
            // path it exercises. Taking the pointer once models what C does.
            let cs_ptr = cs.as_mut_ptr();
            let spaces = [CSpaceDesc { caps: cs_ptr, size: 16, caps_in_use: addr_of_mut!(ciu) }];
            assert!(rust_cap_revoke_global(
                cs_ptr, 16, 4, addr_of_mut!(ciu), spaces.as_ptr(), 1, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            assert_eq!(cs[4].typ, CAP_NULL);
            assert_eq!(cs[5].typ, CAP_NULL, "the same-object derived copy is swept too");
            assert_eq!(ciu, 0, "caps_in_use must saturate at 0, never wrap to u32::MAX");
        }
    }

    /// `rust_cap_grant_into` delegates a capability across cspaces: the grantee
    /// gets rights reduced to `new_rights & src.rights`, a fresh serial, and the
    /// grantor's cap recorded as its parent (`badge == src.serial`) — so the
    /// derivation tree is well-formed and a later revoke of the grantor sweeps it.
    #[test]
    fn test_grant_into_reduces_rights_and_records_parent() {
        let mut grantor = [cap(0, 0, 0, 0, 0); 16];
        let mut grantee = [cap(0, 0, 0, 0, 0); 16];
        // Grantor holds a full-rights CAP_ENDPOINT (rights 0x3f) at slot 5.
        grantor[5] = cap(3, 0x3f, 0xC100, 0, 0x5100);
        let mut next = 0x40000u64;
        unsafe {
            // Grant with rights reduced to READ|WRITE (0x03), into a low slot 3
            // (allowed: grant endows a dominated child's slots).
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee.as_mut_ptr(), 16, 3, 0x03, &mut next));
            let d = grantee[3];
            assert_eq!(d.typ, 3);
            assert_eq!(d.rights, 0x03, "grant reduces rights to new_rights & src.rights");
            assert_eq!(d.object, 0xC100);
            assert_eq!(d.badge, 0x5100, "grantee records the grantor's cap as its parent");
            assert!(d.serial >= MIN_DERIVED_SERIAL && d.serial != 0x5100,
                "grantee gets a fresh serial distinct from the grantor");
            // A right the source lacks can never be granted, even if requested.
            let mut grantee2 = [cap(0, 0, 0, 0, 0); 16];
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee2.as_mut_ptr(), 16, 4, 0xFFFF, &mut next));
            assert_eq!(grantee2[4].rights, 0x3f, "requested rights are masked by the source's");
        }
    }

    /// Grant refuses an empty / serial-0 source and out-of-range destinations,
    /// leaving the destination untouched — authority cannot be fabricated.
    #[test]
    fn test_grant_into_fails_closed() {
        let mut grantor = [cap(0, 0, 0, 0, 0); 16];
        grantor[7] = cap(3, 0x3f, 0xC200, 0, 0 /* serial 0 => invalid */);
        let mut grantee = [cap(0, 0, 0, 0, 0); 16];
        let mut next = 0x40000u64;
        unsafe {
            // serial-0 source refused.
            assert!(!rust_cap_grant_into(
                &grantor[7] as *const Capability, grantee.as_mut_ptr(), 16, 5, 0x3f, &mut next));
            // null source / null dest refused.
            assert!(!rust_cap_grant_into(
                core::ptr::null(), grantee.as_mut_ptr(), 16, 5, 0x3f, &mut next));
            let valid = cap(3, 0x3f, 0xC201, 0, 0x5201);
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, core::ptr::null_mut(), 16, 5, 0x3f, &mut next));
            // out-of-range dest refused (>= size and >= CNODE_SIZE).
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, grantee.as_mut_ptr(), 16, 16, 0x3f, &mut next));
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, grantee.as_mut_ptr(), u32::MAX, CNODE_SIZE, 0x3f, &mut next));
            assert_eq!(grantee[5].typ, CAP_NULL, "destination untouched on refusal");
        }
    }

    /// A granted capability shares the grantor's lineage: revoking the grantor's
    /// source (system-wide) sweeps the grantee's delegated copy too, because they
    /// share the object and the grantee's badge is the grantor's serial.
    #[test]
    fn test_grant_into_then_revoke_source_sweeps_grantee() {
        let mut grantor = [cap(0, 0, 0, 0, 0); 16];
        let mut grantee = [cap(0, 0, 0, 0, 0); 16];
        grantor[5] = cap(4 /*CAP_FRAME*/, 0x3f, 0xC300, 0, 0x5300);
        let mut next = 0x50000u64;
        let mut ciu_g = 1u32;
        let mut ciu_e = 0u32; // grantee accounting starts at 0; the C caller bumps it
        unsafe {
            let grantee_ptr = grantee.as_mut_ptr();
            let grantor_ptr = grantor.as_mut_ptr();
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee_ptr, 16, 6, !0u32, &mut next));
            ciu_e += 1; // mirror the C caller's was-null increment
            assert!(!rust_cap_lookup(grantee_ptr, 16, 6, 0x1).is_null());

            let spaces = [
                CSpaceDesc { caps: grantor_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_g) },
                CSpaceDesc { caps: grantee_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_e) },
            ];
            assert!(rust_cap_revoke_global(
                grantor_ptr, 16, 5, addr_of_mut!(ciu_g), spaces.as_ptr(), 2, &mut next, core::ptr::null_mut(), 0));
            assert_eq!(grantor[5].typ, CAP_NULL);
            assert_eq!(grantee[6].typ, CAP_NULL, "the delegated copy is revoked with its grantor");
            assert_eq!(ciu_e, 0, "grantee accounting decremented for the swept copy");
        }
    }

    /// AUDIT A1 (core regression): revoking a *delegated child* must NOT disturb
    /// the grantor's original or a sibling child. The old equivalence-set match
    /// nulled the parent (its serial == the child's badge) and same-object peers;
    /// descendant-only revocation touches only what is derived FROM the revoked
    /// capability, not its ancestors or siblings.
    #[test]
    fn test_revoke_child_leaves_parent_and_siblings_intact() {
        let mut grantor = [cap(0, 0, 0, 0, 0); 16];
        let mut child_space = [cap(0, 0, 0, 0, 0); 16];
        // The parent/root of the lineage.
        grantor[4] = cap(3, 0x3f, 0xD100, 0, 0x6100);
        // Two children derived from it (badge == parent serial): a sibling in the
        // grantor's own cspace, and one delegated into another task.
        grantor[5] = cap(3, 0x3f, 0xD100, 0x6100, 0x6101);
        child_space[6] = cap(3, 0x3f, 0xD100, 0x6100, 0x6102);
        let mut ciu_g = 2u32;
        let mut ciu_c = 1u32;
        unsafe {
            let child_space_ptr = child_space.as_mut_ptr();
            let grantor_ptr = grantor.as_mut_ptr();
            let spaces = [
                CSpaceDesc { caps: grantor_ptr,     size: 16, caps_in_use: addr_of_mut!(ciu_g) },
                CSpaceDesc { caps: child_space_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_c) },
            ];
            // Revoke the DELEGATED CHILD (child_space slot 6) — not the parent.
            assert!(rust_cap_revoke_global(
                child_space_ptr, 16, 6, addr_of_mut!(ciu_c),
                spaces.as_ptr(), 2, core::ptr::null_mut(), core::ptr::null_mut(), 0));

            // The child is gone...
            assert_eq!(child_space[6].typ, CAP_NULL);
            assert_eq!(ciu_c, 0);
            // ...but the grantor's original and the sibling child are UNTOUCHED
            // and still usable (the crux of audit A1).
            assert_eq!(grantor[4].typ, 3, "revoking a child must not revoke its parent (A1)");
            assert_eq!(grantor[5].typ, 3, "revoking a child must not revoke a sibling (A1)");
            assert!(!rust_cap_lookup(grantor_ptr, 16, 4, 0x1).is_null(),
                "parent stays usable after a child is revoked");
            assert!(!rust_cap_lookup(grantor_ptr, 16, 5, 0x1).is_null(),
                "sibling stays usable after a child is revoked");
            assert_eq!(ciu_g, 2, "grantor accounting unchanged");
        }
    }

    /// AUDIT A1: two capabilities to the *same object* but with independent
    /// lineages (each installed directly, badge 0, distinct serials — e.g. two
    /// tasks each connected to the fs_server endpoint) must be independent. The
    /// old object-equality match co-revoked them; descendant-only revocation does
    /// not, because neither is derived from the other.
    #[test]
    fn test_revoke_does_not_touch_independent_same_object_cap() {
        let mut a = [cap(0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0); 16];
        // Same object 0xE000, independent lineages (badge 0, distinct serials).
        a[5] = cap(3, 0x3f, 0xE000, 0, 0x7000);
        b[5] = cap(3, 0x3f, 0xE000, 0, 0x7001);
        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;
        unsafe {
            let a_ptr = a.as_mut_ptr();
            let b_ptr = b.as_mut_ptr();
            let spaces = [
                CSpaceDesc { caps: a_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            assert!(rust_cap_revoke_global(
                a_ptr, 16, 5, addr_of_mut!(ciu_a), spaces.as_ptr(), 2, core::ptr::null_mut(), core::ptr::null_mut(), 0));
            assert_eq!(a[5].typ, CAP_NULL, "the revoked cap is gone");
            assert_eq!(b[5].typ, 3, "an independent same-object cap must survive (A1)");
            assert!(!rust_cap_lookup(b_ptr, 16, 5, 0x1).is_null(),
                "the independent same-object cap stays usable");
            assert_eq!(ciu_b, 1, "the other task's accounting is untouched");
        }
    }

    /// **[I-3]** regression, roadmap 1.6. A large derivation subtree must be
    /// revoked EXACTLY, and an unrelated peer's capability that merely shares the
    /// same object must survive it.
    ///
    /// This is the test that used to assert the opposite. The closure kept revoked
    /// serials in a fixed 256-entry array, and a subtree larger than that nulled
    /// every capability sharing the root object instead. That never left a
    /// descendant alive, so it was safe in the direction that matters — but it was
    /// reachable from ring 3, and it destroyed authority belonging to tasks that
    /// had no relationship to the revoker beyond naming the same object.
    ///
    /// The subtree here is deliberately built past the old 256 bound and is also
    /// three levels deep, so a closure that stopped at direct children, or at a
    /// fixed number of them, fails.
    #[test]
    fn test_revoke_large_subtree_is_exact_and_spares_independent_peers() {
        const ROOT_SERIAL: u64 = 0x8000_0001;
        const OBJ: u64 = 0xF000;

        let mut a = [cap(0, 0, 0, 0, 0); 256];
        let mut b = [cap(0, 0, 0, 0, 0); 256];

        // Root in a[0]; the *_global caller nulls it before the sweep and its
        // serial remains the closure seed.
        a[0] = cap(4, 0x3f, OBJ, 0, ROOT_SERIAL);

        let mut serial = 0x9000_0000u64;
        let mut descendants = 0usize;

        // Level 1: fill the rest of cspace A with direct children of the root.
        let mut level1 = [0u64; 255];
        for (k, c) in a.iter_mut().skip(1).enumerate() {
            serial += 1;
            *c = cap(4, 0x3f, OBJ, ROOT_SERIAL, serial);
            level1[k] = serial;
            descendants += 1;
        }

        // Levels 2 and 3 in cspace B: grandchildren of the root, then one
        // great-grandchild, so depth is exercised as well as breadth. Two slots
        // at the end of B are reserved for the peers that must survive.
        let mut deepest = 0u64;
        for (k, c) in b.iter_mut().enumerate().take(256 - 2) {
            serial += 1;
            let parent = if k == 0 { level1[0] } else { deepest };
            *c = cap(4, 0x3f, OBJ, parent, serial);
            deepest = serial;
            descendants += 1;
        }
        assert!(descendants > 256,
            "the subtree must exceed the old 256-entry worklist to be a regression test");

        // The two capabilities that must SURVIVE: same object, no lineage to the
        // root. b[254] is a completely independent root; b[255] is derived from
        // it. Under the old overflow fallback both were destroyed.
        const PEER_SERIAL: u64 = 0x7000_0001;
        b[254] = cap(3, 0x1, OBJ, 0, PEER_SERIAL);
        b[255] = cap(3, 0x1, OBJ, PEER_SERIAL, 0x7000_0002);

        let mut ciu_a = 256u32;
        let mut ciu_b = 256u32;
        unsafe {
            let a_ptr = a.as_mut_ptr();
            let b_ptr = b.as_mut_ptr();
            let descs = [
                CSpaceDesc { caps: a_ptr, size: 256, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b_ptr, size: 256, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            assert!(rust_cap_revoke_global(
                a_ptr, 256, 0, addr_of_mut!(ciu_a),
                descs.as_ptr(), 2, core::ptr::null_mut(), core::ptr::null_mut(), 0));

            // Every descendant, at every depth, is gone.
            for (i, c) in a.iter().enumerate() {
                assert_eq!(c.typ, CAP_NULL, "a[{i}] is in the subtree and must be revoked");
            }
            for (i, c) in b.iter().enumerate().take(256 - 2) {
                assert_eq!(c.typ, CAP_NULL, "b[{i}] is in the subtree and must be revoked");
            }

            // No sentinel may survive the sweep: a capability left carrying one
            // would not be a valid type, and finding one here means the mark and
            // sweep phases have gone out of step.
            for c in a.iter().chain(b.iter()) {
                assert_ne!(c.typ, CAP_MARK_NEW, "a mark sentinel escaped the sweep");
                assert_ne!(c.typ, CAP_MARK_DONE, "a mark sentinel escaped the sweep");
            }

            // The independent peers are untouched — the whole point of [I-3].
            assert_eq!(b[254].typ, 3, "an independent same-object cap must survive");
            assert_eq!(b[254].serial, PEER_SERIAL, "and keep its identity");
            assert_eq!(b[255].typ, 3, "so must a cap derived from it");
            assert!(!rust_cap_lookup(b_ptr, 256, 254, 0x1).is_null(),
                "the independent peer stays usable after the revoke");
            assert!(!rust_cap_lookup(b_ptr, 256, 255, 0x1).is_null(),
                "and so does its child");
        }
    }

    /// The closure must be exact at depth, not merely at breadth: a chain of
    /// derivations longer than any fixed worklist is still fully revoked, and a
    /// sibling chain hanging off an unrelated root is not.
    #[test]
    fn test_revoke_deep_chain_is_fully_closed() {
        const ROOT_SERIAL: u64 = 0x8100_0001;
        const OBJ: u64 = 0xE000;

        let mut a = [cap(0, 0, 0, 0, 0); 256];
        a[0] = cap(4, 0x3f, OBJ, 0, ROOT_SERIAL);

        // A single 300-link chain spread across two cspaces, so the closure has
        // to iterate far past the old bound one level at a time.
        let mut b = [cap(0, 0, 0, 0, 0); 256];
        let mut serial = 0xA000_0000u64;
        let mut parent = ROOT_SERIAL;
        for c in a.iter_mut().skip(1) {
            serial += 1;
            *c = cap(4, 0x3f, OBJ, parent, serial);
            parent = serial;
        }
        for c in b.iter_mut().take(45) {
            serial += 1;
            *c = cap(4, 0x3f, OBJ, parent, serial);
            parent = serial;
        }

        // An unrelated chain sharing the object; none of it may be revoked.
        const OTHER: u64 = 0x7100_0001;
        b[100] = cap(3, 0x1, OBJ, 0, OTHER);
        b[101] = cap(3, 0x1, OBJ, OTHER, 0x7100_0002);

        let mut ciu_a = 256u32;
        let mut ciu_b = 47u32;
        unsafe {
            let a_ptr = a.as_mut_ptr();
            let b_ptr = b.as_mut_ptr();
            let descs = [
                CSpaceDesc { caps: a_ptr, size: 256, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b_ptr, size: 256, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            assert!(rust_cap_revoke_global(
                a_ptr, 256, 0, addr_of_mut!(ciu_a),
                descs.as_ptr(), 2, core::ptr::null_mut(), core::ptr::null_mut(), 0));

            for (i, c) in a.iter().enumerate() {
                assert_eq!(c.typ, CAP_NULL, "a[{i}] is link {i} of the chain");
            }
            for (i, c) in b.iter().enumerate().take(45) {
                assert_eq!(c.typ, CAP_NULL, "b[{i}] is deep in the chain and must be revoked");
            }
            assert_eq!(b[100].typ, 3, "the unrelated chain's root must survive");
            assert_eq!(b[101].typ, 3, "and its child");
        }
    }

    /// FINDING 3.3 regression. Reproduces the production scenario: a parent and
    /// a child minted from it. Under the old object-keyed, gen-0-immune check a
    /// detached SNAPSHOT of the child survived the parent's revocation forever,
    /// defeating the use-after-revoke / IPC revalidate guard. Revoking the parent
    /// must now (a) leave the child's snapshot failing its re-check (the child's
    /// slot is emptied, and its serial is never reissued), while (b) leaving an
    /// INDEPENDENT same-object capability (a different serial) valid, so the fix
    /// does not regress A1.
    #[test]
    fn test_gen0_snapshot_invalidated_after_revoke_finding_3_3() {
        let mut owner = [cap(0, 0, 0, 0, 0); 16];
        let mut other = [cap(0, 0, 0, 0, 0); 16];
        // Parent, real object. An independent capability to the SAME
        // object in another task (badge 0, distinct serial) — e.g. two tasks each
        // independently connected to the fs_server endpoint.
        owner[4] = cap(3 /*CAP_ENDPOINT*/, 0x3f, 0xEE00, 0, 0x4400);
        other[9] = cap(3, 0x3f, 0xEE00, 0, 0x8800);
        let mut ciu_o = 1u32;
        let mut ciu_x = 1u32;
        let mut next = 0x7_0000u64;
        unsafe {
            let other_ptr = other.as_mut_ptr();
            let owner_ptr = owner.as_mut_ptr();
            // Derive a child from the parent (production mint): fresh serial.
            assert!(rust_cap_mint(owner_ptr, 16, 5, 4, 0x3, &mut next, 0));
            // A caller snapshots the child for a later revalidate-at-use.
            let snapshot = *owner_ptr.add(5);
            assert!(still_holds(owner_ptr, 16, 5, &snapshot),
                "the child snapshot is valid before the revoke");

            // System-wide revoke of the PARENT (the reachable SYS_CAP_REVOKE path).
            let spaces = [
                CSpaceDesc { caps: owner_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_o) },
                CSpaceDesc { caps: other_ptr, size: 16, caps_in_use: addr_of_mut!(ciu_x) },
            ];
            assert!(rust_cap_revoke_global(
                owner_ptr, 16, 4, addr_of_mut!(ciu_o), spaces.as_ptr(), 2, &mut next, core::ptr::null_mut(), 0));

            // (a) The child's detached snapshot now fails revalidation: its slot
            // was swept, the hole finding 3.3 identified.
            assert!(!still_holds(owner_ptr, 16, 5, &snapshot),
                "the child snapshot must be stale after its parent is revoked (finding 3.3)");
            assert_eq!((*owner_ptr.add(5)).typ, CAP_NULL, "the live child slot is also swept");

            // (b) The independent same-object capability (different serial) is
            // untouched and still usable — the fix does not over-revoke (A1).
            assert_eq!(other[9].typ, 3, "an independent same-object cap must survive");
            assert!(!rust_cap_lookup(other_ptr, 16, 9, 0x1).is_null(),
                "the independent same-object cap stays valid (serial-keyed, not object-keyed)");
            assert_eq!(ciu_x, 1, "the other task's accounting is untouched");
        }
    }

    // ---- Tokens (docs/design/filesystem.md §5.1) -------------------------------

    fn ep(rights: u32, serial: u64, token: u64) -> Capability {
        Capability {
            typ: CAP_ENDPOINT, rights, object: 77, badge: 0, serial, token,
        }
    }

    const NULLCAP: Capability = Capability {
        typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
    };

    #[test]
    fn mint_token_from_an_untokened_minter_strips_receive() {
        let mut cs = [NULLCAP; 8];
        cs[4] = ep(!0u32, 0x2_0000, 0);
        let mut next = 0x2_0000u64;
        let ok = unsafe { rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, !0u32, 0xABCD, &mut next) };
        assert!(ok);
        assert_eq!(cs[5].token, 0xABCD);
        assert_eq!(cs[5].rights & TOKEN_STRIPPED_RIGHTS, 0, "a token never receives");
        assert_eq!(cs[5].rights, !TOKEN_STRIPPED_RIGHTS);
        assert_eq!(cs[5].badge, 0x2_0000, "the minter is the parent");
        assert_eq!(cs[5].object, 77);
    }

    #[test]
    fn mint_token_refuses_a_tokened_source_a_source_without_mint_and_a_zero_token() {
        let mut next = 0x3_0000u64;
        // Tokened source, even one holding every right.
        let mut cs = [NULLCAP; 8];
        cs[4] = ep(!0u32, 0x3_0000, 9);
        assert!(!unsafe { rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, !0u32, 10, &mut next) });
        assert_eq!(cs[5].typ, CAP_NULL);
        // No MINT right.
        cs[4] = ep(!CAP_RIGHT_MINT, 0x3_0000, 0);
        assert!(!unsafe { rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, !0u32, 10, &mut next) });
        assert_eq!(cs[5].typ, CAP_NULL);
        // Zero token.
        cs[4] = ep(!0u32, 0x3_0000, 0);
        assert!(!unsafe { rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, !0u32, 0, &mut next) });
        assert_eq!(cs[5].typ, CAP_NULL);
        // Not an endpoint.
        cs[4].typ = 2;
        assert!(!unsafe { rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, !0u32, 10, &mut next) });
        assert_eq!(cs[5].typ, CAP_NULL);
    }

    #[test]
    fn narrowing_and_granting_keep_the_token() {
        let mut cs = [NULLCAP; 8];
        cs[4] = ep(0xFF02, 0x4_0000, 0x55);
        let mut next = 0x4_0000u64;
        assert!(unsafe { rust_cap_mint(cs.as_mut_ptr(), 8, 5, 4, 0x0F02, &mut next, 0) });
        assert_eq!(cs[5].token, 0x55, "attenuation must keep identity");
        assert_eq!(cs[5].rights, 0x0F02);
        let mut other = [NULLCAP; 8];
        assert!(unsafe { rust_cap_grant_into(&cs[5], other.as_mut_ptr(), 8, 6, !0u32, &mut next) });
        assert_eq!(other[6].token, 0x55, "delegation must keep identity");
    }

    #[test]
    fn reply_mint_is_bounded_by_the_invoking_capability() {
        let mut cs = [NULLCAP; 8];
        cs[4] = ep(0x0F02, 0x5_0000, 0x10);
        let mut next = 0x5_0000u64;
        let src = cs[4];
        let ok = unsafe { rust_cap_reply_mint(&src, cs.as_mut_ptr(), 8, 6, !0u32, 0x11, &mut next) };
        assert!(ok);
        assert_eq!(cs[6].rights, 0x0F02, "a server asking for everything gets the invoker's rights");
        assert_eq!(cs[6].token, 0x11, "the token is the server's choice");
        assert_eq!(cs[6].badge, 0x5_0000, "the child of the capability the request came through");
    }

    #[test]
    fn reply_mint_refuses_an_occupied_slot_and_writes_nothing() {
        let mut cs = [NULLCAP; 8];
        cs[4] = ep(0x0F02, 0x6_0000, 0x10);
        cs[6] = ep(0x2, 0x6_0001, 0x99);
        let before = cs[6];
        let mut next = 0x6_0001u64;
        let src = cs[4];
        assert!(!unsafe { rust_cap_reply_mint(&src, cs.as_mut_ptr(), 8, 6, !0u32, 0x11, &mut next) });
        assert_eq!(cs[6].token, before.token);
        assert_eq!(cs[6].serial, before.serial);
    }

    #[test]
    fn nullify_clears_the_token() {
        let mut c = ep(0x2, 0x7_0000, 0x42);
        unsafe { nullify(&mut c) };
        assert_eq!(c.token, 0);
        assert_eq!(c.typ, CAP_NULL);
    }

    /// LIMITATIONS 1.29: ring 3 cannot copy a pipe end. A grant it asked for,
    /// a mint and a transfer each refuse one and leave the destination as it
    /// was, whatever rights the end carries (MINT included, which no installer
    /// gives today). The kernel's own grant, which fork uses and follows with
    /// a count of every end it copied, still copies one.
    #[test]
    fn ring3_cannot_copy_a_pipe_end() {
        let all = CAP_RIGHT_READ | CAP_RIGHT_MINT | 0x3f;
        let pipe = cap(CAP_PIPE, all, 4, 0, MIN_DERIVED_SERIAL);
        let mut next: u64 = MIN_DERIVED_SERIAL + 1;

        let mut dest = [cap(CAP_NULL, 0, 0, 0, 0); 8];
        assert!(!unsafe {
            rust_cap_grant_from_user(&pipe, dest.as_mut_ptr(), 8, 5, !0u32, &mut next)
        });
        assert_eq!(dest[5].typ, CAP_NULL, "a refused grant wrote the destination");
        assert_eq!(next, MIN_DERIVED_SERIAL + 1, "a refused grant spent a serial");

        let mut cs = [cap(CAP_NULL, 0, 0, 0, 0); 8];
        cs[6] = pipe;
        assert!(!unsafe { rust_cap_mint(cs.as_mut_ptr(), 8, 5, 6, !0u32, &mut next, 0) });
        assert!(!unsafe { rust_cap_transfer(cs.as_mut_ptr(), 8, 5, 6, &mut next) });
        assert_eq!(cs[5].typ, CAP_NULL, "a refused mint or transfer wrote the destination");

        // The kernel's path is unchanged: fork counts what it copies.
        assert!(unsafe { rust_cap_grant_into(&pipe, dest.as_mut_ptr(), 8, 5, !0u32, &mut next) });
        assert_eq!(dest[5].typ, CAP_PIPE);
    }

    /// The refusal is by type and only by type: every other live capability a
    /// ring-3 grant is asked for is delegated exactly as the kernel's grant
    /// would, a null source is refused, and the C value is the one pinned here.
    #[test]
    fn ring3_grant_is_the_kernel_grant_for_every_other_type() {
        assert_eq!(CAP_PIPE, 13);
        assert!(!unsafe {
            rust_cap_grant_from_user(core::ptr::null(), [cap(0, 0, 0, 0, 0); 1].as_mut_ptr(), 1, 0, !0u32, core::ptr::null_mut())
        });
        for typ in 1u32..=32 {
            if typ == CAP_PIPE {
                continue;
            }
            let src = cap(typ, 0x7, 9, 0, MIN_DERIVED_SERIAL);
            let mut a = [cap(CAP_NULL, 0, 0, 0, 0); 4];
            let mut b = [cap(CAP_NULL, 0, 0, 0, 0); 4];
            let (mut na, mut nb) = (MIN_DERIVED_SERIAL + 1, MIN_DERIVED_SERIAL + 1);
            let ua = unsafe { rust_cap_grant_from_user(&src, a.as_mut_ptr(), 4, 2, 0x5, &mut na) };
            let ub = unsafe { rust_cap_grant_into(&src, b.as_mut_ptr(), 4, 2, 0x5, &mut nb) };
            assert!(ua && ub, "type {typ}: a ring-3 grant was refused");
            assert!(
                (a[2].typ, a[2].rights, a[2].object, a[2].badge, a[2].serial, a[2].token)
                    == (b[2].typ, b[2].rights, b[2].object, b[2].badge, b[2].serial, b[2].token),
                "type {typ}: the two grants differ"
            );
        }
    }

    // ---- pipe ends a revocation removes are counted (LIMITATIONS 1.14) ----

    const R: u32 = CAP_RIGHT_READ;
    const W: u32 = CAP_RIGHT_WRITE;
    const RV: u32 = 1 << 5; // CAP_RIGHT_REVOKE

    /// The shape `do_spawn` and fork give a pipe end's holders: the spawner's
    /// root end, a forked child's derived copy, and a spawned grandchild's stdio
    /// end derived from that. Revoking the root removes all three and counts
    /// three ends of that pipe's direction; the other direction, and another
    /// pipe, are neither removed nor counted.
    #[test]
    fn global_revoke_counts_every_pipe_end_it_removes() {
        let mut a = [cap(0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0); 16];
        let mut c = [cap(0, 0, 0, 0, 0); 16];
        a[15] = cap(CAP_PIPE, W | RV, 3, 0, 0x5_0001); // spawner's writer root
        a[14] = cap(CAP_PIPE, R | RV, 3, 0, 0x5_0002); // its reader end: untouched
        b[9] = cap(CAP_PIPE, W | RV, 3, 0x5_0001, 0x5_0003); // forked child's copy
        c[15] = cap(CAP_PIPE, W, 3, 0x5_0003, 0x5_0004); // spawned stdout end
        c[14] = cap(CAP_PIPE, W, 2, 0, 0x5_0005); // another pipe: untouched
        let (mut ca, mut cb, mut cc) = (2u32, 1u32, 2u32);
        let mut tally = [0u32; 8];
        unsafe {
            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ca) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(cb) },
                CSpaceDesc { caps: c.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(cc) },
            ];
            assert!(rust_cap_revoke_global(
                a.as_mut_ptr(), 16, 15, addr_of_mut!(ca), spaces.as_ptr(), 3,
                core::ptr::null_mut(), tally.as_mut_ptr(), 8));
        }
        assert_eq!(a[15].typ, CAP_NULL);
        assert_eq!(b[9].typ, CAP_NULL, "the forked copy is in the subtree");
        assert_eq!(c[15].typ, CAP_NULL, "the spawned child's stdio end is in the subtree");
        assert_eq!(a[14].typ, CAP_PIPE, "the reader end is not the writer's descendant");
        assert_eq!(c[14].typ, CAP_PIPE, "another pipe's end is not in the subtree");
        assert_eq!(tally, [0, 0, 0, 0, 0, 0, 0, 3],
            "three writer ends of pipe 3 removed, three counted, nothing else");
    }

    /// Revoking a DERIVED end removes and counts only its own subtree: the
    /// ancestor end survives and is not counted, so the pipe's count stays at
    /// the one end that is left (S4 for pipe ends).
    #[test]
    fn revoking_a_derived_pipe_end_counts_only_its_subtree() {
        let mut a = [cap(0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0); 16];
        a[5] = cap(CAP_PIPE, R | RV, 1, 0, 0x6_0001);
        b[5] = cap(CAP_PIPE, R | RV, 1, 0x6_0001, 0x6_0002);
        b[14] = cap(CAP_PIPE, R, 1, 0x6_0002, 0x6_0003);
        let (mut ca, mut cb) = (1u32, 2u32);
        let mut tally = [0u32; 4];
        unsafe {
            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ca) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(cb) },
            ];
            assert!(rust_cap_revoke_global(
                b.as_mut_ptr(), 16, 5, addr_of_mut!(cb), spaces.as_ptr(), 2,
                core::ptr::null_mut(), tally.as_mut_ptr(), 4));
        }
        assert_eq!(a[5].typ, CAP_PIPE, "the ancestor end survives");
        assert_eq!((b[5].typ, b[14].typ), (CAP_NULL, CAP_NULL));
        assert_eq!(tally, [0, 0, 2, 0]);
    }

    /// A revoke of something that is not a pipe end counts nothing, and the
    /// single-cspace revoke counts exactly as the global one does.
    #[test]
    fn single_cspace_revoke_counts_pipe_ends_and_nothing_else() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        cs[4] = cap(1, 0x3f, 0x9000, 0, 0x7_0001);
        cs[5] = cap(1, 0x3f, 0x9000, 0x7_0001, 0x7_0002);
        cs[6] = cap(CAP_PIPE, W | RV, 0, 0, 0x7_0003);
        cs[7] = cap(CAP_PIPE, W, 0, 0x7_0003, 0x7_0004);
        let mut tally = [0u32; 2];
        unsafe {
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut(), tally.as_mut_ptr(), 2));
            assert_eq!(tally, [0, 0], "no pipe end was in that subtree");
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 6, core::ptr::null_mut(), tally.as_mut_ptr(), 2));
        }
        assert_eq!((cs[6].typ, cs[7].typ), (CAP_NULL, CAP_NULL));
        assert_eq!(tally, [0, 2]);
    }

    /// The tally is the C side's array and its length is the only bound: an end
    /// naming a pipe past the length is removed but not counted, nothing is
    /// written beyond the length (the guard cells), and a null tally counts
    /// nothing without failing the revoke.
    #[test]
    fn pipe_tally_writes_only_inside_its_length() {
        let mut cs = [cap(0, 0, 0, 0, 0); 16];
        cs[4] = cap(CAP_PIPE, W | RV, 0, 0, 0x8_0001);
        cs[5] = cap(CAP_PIPE, W, 2, 0x8_0001, 0x8_0002); // pipe 2: past len 4
        cs[6] = cap(CAP_PIPE, R, u64::MAX, 0x8_0001, 0x8_0003);
        let mut cells = [0u32; 8];
        unsafe {
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut(), cells.as_mut_ptr(), 4));
        }
        assert_eq!((cs[4].typ, cs[5].typ, cs[6].typ), (CAP_NULL, CAP_NULL, CAP_NULL),
            "every end in the subtree is removed, counted or not");
        assert_eq!(cells, [0, 1, 0, 0, 0, 0, 0, 0], "only pipe 0 is inside the tally");

        cs[4] = cap(CAP_PIPE, W | RV, 0, 0, 0x8_0004);
        unsafe {
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut(), core::ptr::null_mut(), 4));
        }
        assert_eq!(cs[4].typ, CAP_NULL);
    }
}

// ---------------------------------------------------------------------------
// Formal verification (Kani bounded model checking).
//
// Carries SECURITY.md S31: the capability algebra's authority invariants are
// proved over the whole input space rather than sampled.
// These #[kani::proof] harnesses are compiled ONLY under `cargo kani` (the
// `kani` cfg); they are invisible to the normal build, `cargo test`, clippy,
// and the kernel link. Where a unit test in the module above samples a handful
// of inputs, Kani proves the property over the ENTIRE input space (every value
// of each symbolic field), so it catches a boundary the samples miss. Run with:
// cargo kani  (from rust/)
//
// Scope: the pure / self-contained authority invariants. The capability core
// keeps no global state since the hashed generation table went (2026-10-11), so
// every harness here is a function of its own inputs.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// A freshly allocated derived serial is NEVER in the reserved primordial
    /// range and NEVER 0 — for every possible value of the kernel's monotonic
    /// serial counter, not just the boundary values the unit test samples. This
    /// is what guarantees a derived capability's serial can never be mistaken for
    /// a primordial (0xC0DE-prefixed) one or for an empty (serial-0) slot. A
    /// refusal (0) leaves the counter where it was.
    #[kani::proof]
    fn serial_never_reserved_or_zero() {
        let mut counter: u64 = kani::any();
        let before = counter;
        let s = unsafe { assign_fresh_serial(&mut counter as *mut u64) };
        if s == 0 {
            assert!(counter == before, "a refusal must not move the counter");
        } else {
            assert!(s >= MIN_DERIVED_SERIAL, "serial dipped below the derived floor");
            assert!(!serial_is_primordial(s), "a derived serial landed in the primordial range");
            assert!(counter == s, "counter must advance to exactly the returned serial");
        }
    }

    /// ONE SERIAL, ONE SLOT, the allocation half: no serial is ever issued
    /// twice. For every counter value, a serial the allocator issues is strictly
    /// greater than the counter was, and every serial issued before is at most
    /// that, so by induction over calls no two calls return the same serial. Two
    /// calls in a row are checked directly as well: the second refuses or is
    /// strictly greater. This is what a 32-bit counter that wrapped violated.
    #[kani::proof]
    fn fresh_serials_never_repeat() {
        let mut counter: u64 = kani::any();
        let before = counter;
        let s1 = unsafe { assign_fresh_serial(&mut counter as *mut u64) };
        let s2 = unsafe { assign_fresh_serial(&mut counter as *mut u64) };
        if s1 != 0 {
            assert!(s1 > before, "an issued serial must be above every serial issued before it");
        }
        if s1 != 0 && s2 != 0 {
            assert!(s2 > s1, "two issues must never return the same serial");
        }
        if s1 == 0 {
            assert!(s2 == 0, "once the allocator refuses, it keeps refusing");
        }
    }

    /// Minting can only ever REDUCE authority: the minted capability's rights are
    /// a subset of the source's, and exactly the intersection of the requested
    /// and source rights — for EVERY (source rights, requested rights) pair. No
    /// combination of requested rights can escalate beyond what the source holds.
    #[kani::proof]
    fn mint_never_escalates_rights() {
        let src_rights: u32 = kani::any();
        let req_rights: u32 = kani::any();

        // 8-slot cspace: source at slot 0, mint into slot 4 (>= KERNEL_RESERVED_CAPS
        // so the mint is not refused).
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 8];
        cs[0] = Capability { typ: 1, rights: src_rights, object: 0, badge: 0, serial: MIN_DERIVED_SERIAL, token: 0 };
        let mut next: u64 = MIN_DERIVED_SERIAL;

        let ok = unsafe {
            rust_cap_mint(cs.as_mut_ptr(), 8, 4, 0, req_rights, &mut next as *mut u64, 0)
        };
        assert!(ok, "mint of a valid source into a non-reserved slot must succeed");

        let minted = cs[4].rights;
        assert!(minted & !src_rights == 0, "minted rights must be a subset of the source's");
        assert!(minted == (req_rights & src_rights), "minted rights must be requested AND source");
    }

    /// Build a 3-capability derivation chain (parent -> child -> grandchild) in
    /// one cspace, with caller-chosen serials.
    fn chain(p: u64, c: u64, g: u64) -> [Capability; 3] {
        [
            Capability { typ: 1, rights: 0x3f, object: 0, badge: 0, serial: p, token: 0 },
            Capability { typ: 1, rights: 0x3f, object: 0, badge: p, serial: c, token: 0 },
            Capability { typ: 1, rights: 0x3f, object: 0, badge: c, serial: g, token: 0 },
        ]
    }

    /// AUDIT A1, the core invariant, proved over the ENTIRE serial space:
    /// revoking a *derived* capability never nulls its ancestors. For every
    /// distinct (parent, child, grandchild) serial triple, revoking the
    /// grandchild's subtree leaves the parent and the child intact and usable,
    /// and removes exactly the grandchild.
    ///
    /// This is the property the old equivalence-set matcher violated: it matched
    /// the target's `badge` against other caps' `serial`, so revoking a child
    /// also nulled its parent. A unit test samples a few serials; this covers all
    /// of them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_descendant_never_nulls_ancestors() {
        let p: u64 = kani::any();
        let c: u64 = kani::any();
        let g: u64 = kani::any();
        // Serials are unique and non-zero by construction (assign_fresh_serial).
        kani::assume(p != 0 && c != 0 && g != 0);
        kani::assume(p != c && c != g && p != g);

        let mut cs = chain(p, c, g);
        let desc = CSpaceDesc {
            caps: cs.as_mut_ptr(),
            size: 3,
            caps_in_use: core::ptr::null_mut(),
        };
        // Revoke the LEAF (grandchild) subtree.
        unsafe { revoke_subtree(&desc as *const CSpaceDesc, 1, g, 0, PipeTally::NONE) };

        assert!(cs[0].typ != CAP_NULL, "revoking a descendant must not null the parent");
        assert!(cs[0].serial == p, "the parent must be left byte-for-byte intact");
        assert!(cs[1].typ != CAP_NULL, "revoking a descendant must not null its own parent");
        assert!(cs[1].serial == c, "the intermediate cap must be left intact");
        assert!(cs[2].typ == CAP_NULL, "the revoked capability itself must be nulled");
    }

    /// ROADMAP 3.5: lookup refuses any request for rights the capability does
    /// not hold, for EVERY (held, requested) pair -- 2^64 combinations, where
    /// the unit tests sample a handful.
    ///
    /// This is the monotonicity the whole capability graph rests on: every gate
    /// in the kernel is `cap_lookup(slot, needed)`, so if lookup could ever
    /// return a capability missing a requested right, every gate above it would
    /// be decorative. The property is stated as an equivalence, not an
    /// implication, so a lookup that refused too MUCH would fail it too -- a
    /// predicate that returns null always satisfies "never grants what it should
    /// not", and that mutation is what killed the resume-guard's first shape.
    #[kani::proof]
    fn lookup_grants_exactly_the_rights_held() {
        let held: u32 = kani::any();
        let want: u32 = kani::any();

        let mut cs = [Capability {
            typ: 1, rights: held, object: 0, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: 0,
        }; 1];

        let got = unsafe { rust_cap_lookup(cs.as_mut_ptr(), 1, 0, want) };
        let sufficient = (held & want) == want;
        assert!(
            got.is_null() != sufficient,
            "lookup must succeed exactly when the capability holds every requested right"
        );
    }

    /// ROADMAP 3.5: an EMPTY slot is never a capability, whatever is asked of
    /// it -- including the degenerate `required_rights == 0`, which is the case
    /// a "does it hold these rights" check answers vacuously. A caller asking
    /// for no particular rights is asking "is there a capability here", and a
    /// null slot must answer no.
    #[kani::proof]
    fn lookup_never_returns_an_empty_slot() {
        let want: u32 = kani::any();
        let rights: u32 = kani::any();
        let mut cs = [Capability {
            typ: CAP_NULL, rights, object: 0, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: 0,
        }; 1];
        assert!(
            unsafe { rust_cap_lookup(cs.as_mut_ptr(), 1, 0, want) }.is_null(),
            "an empty slot must never satisfy a lookup"
        );
    }

    /// ROADMAP 3.5: lookup is bounded by the cspace it is given, for every slot
    /// index -- including ones past `cspace_size` and past `CNODE_SIZE`. An
    /// out-of-range slot is a read of whatever follows the cspace in memory,
    /// which is how a "capability" gets fabricated out of adjacent kernel state.
    #[kani::proof]
    fn lookup_refuses_every_out_of_range_slot() {
        let slot: u32 = kani::any();
        kani::assume(slot >= 4);   // the array below is 4 entries

        let mut cs = [Capability {
            typ: 1, rights: !0u32, object: 0, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: 0,
        }; 4];
        assert!(
            unsafe { rust_cap_lookup(cs.as_mut_ptr(), 4, slot, 0) }.is_null(),
            "a slot outside the cspace must never resolve"
        );
    }

    /// ROADMAP 3.5: GRANT never widens, for every (source rights, requested)
    /// pair. Grant is the cross-cspace delegation path -- the one that hands
    /// authority to a DIFFERENT task -- so this is the same algebraic property
    /// as `mint_never_escalates_rights`, on the operation where a mistake leaves
    /// the extra authority in someone else's hands.
    #[kani::proof]
    fn grant_never_escalates_rights() {
        let src_rights: u32 = kani::any();
        let req_rights: u32 = kani::any();

        let src = Capability {
            typ: 1, rights: src_rights, object: 7, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: 0,
        };
        let mut dest = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 8];
        let mut next: u64 = MIN_DERIVED_SERIAL;

        let ok = unsafe {
            rust_cap_grant_into(&src as *const Capability, dest.as_mut_ptr(), 8, 5,
                                req_rights, &mut next as *mut u64)
        };
        assert!(ok, "granting a live capability into an in-range slot must succeed");
        assert!(dest[5].rights & !src_rights == 0, "granted rights must be a subset of the source's");
        assert!(dest[5].rights == (req_rights & src_rights), "granted rights must be requested AND source");
    }

    /// ROADMAP 3.5: GRANT keeps the derivation tree well-formed, for every
    /// source serial. The grantee records the grantor as its parent and takes a
    /// fresh serial of its own, which is what makes a later revoke of the
    /// grantor sweep the grantee -- and what stops the graph acquiring a cycle,
    /// since a fresh serial is strictly above the primordial floor and cannot
    /// equal a parent that already exists.
    #[kani::proof]
    fn grant_records_its_parent_and_takes_a_fresh_serial() {
        let parent_serial: u64 = kani::any();
        kani::assume(parent_serial != 0);

        let src = Capability {
            typ: 3, rights: 0x3f, object: 9, badge: 0,
            serial: parent_serial, token: 0,
        };
        let mut dest = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 4];
        let mut next: u64 = kani::any();
        // The one counter value with no serial left to issue refuses, which
        // `serial_never_reserved_or_zero` covers; every other value grants.
        kani::assume(next != u64::MAX);

        let ok = unsafe {
            rust_cap_grant_into(&src as *const Capability, dest.as_mut_ptr(), 4, 2,
                                !0u32, &mut next as *mut u64)
        };
        assert!(ok);
        assert!(dest[2].badge == parent_serial, "the grantee must record its grantor as parent");
        assert!(dest[2].serial >= MIN_DERIVED_SERIAL, "the grantee's serial must be a derived one");
        assert!(dest[2].serial != 0, "a serial-0 capability is invalid at lookup");
        assert!(dest[2].object == src.object, "grant must name the same object");
        assert!(dest[2].typ == src.typ, "grant must not change the capability's type");
    }

    /// ROADMAP 3.5: authority cannot be fabricated from nothing. Granting from
    /// an EMPTY source, or one whose serial is 0 (the lookup-invalid state a
    /// revoked slot is left in), must refuse and must leave the destination
    /// untouched -- for every rights value the caller asks for.
    #[kani::proof]
    fn grant_from_an_invalid_source_refuses_and_writes_nothing() {
        let req_rights: u32 = kani::any();
        let typ: u32 = kani::any();
        let serial: u64 = kani::any();
        // Either the source is empty, or its serial is the invalid 0.
        kani::assume(typ == CAP_NULL || serial == 0);

        let src = Capability { typ, rights: !0u32, object: 1, badge: 0, serial, token: 0 };
        let mut dest = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 2];
        let mut next: u64 = MIN_DERIVED_SERIAL;

        let ok = unsafe {
            rust_cap_grant_into(&src as *const Capability, dest.as_mut_ptr(), 2, 1,
                                req_rights, &mut next as *mut u64)
        };
        assert!(!ok, "grant from an invalid source must refuse");
        assert!(dest[1].typ == CAP_NULL, "a refused grant must write nothing");
        assert!(dest[1].rights == 0, "a refused grant must leave no rights behind");
    }

    /// ROADMAP 3.5: grant is bounded by the destination cspace, for every slot
    /// index. Same class as the lookup bound: an out-of-range write is a write
    /// into whatever follows the grantee's cspace.
    #[kani::proof]
    fn grant_refuses_every_out_of_range_slot() {
        let slot: u32 = kani::any();
        kani::assume(slot >= 4);

        let src = Capability {
            typ: 1, rights: !0u32, object: 0, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: 0,
        };
        let mut dest = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 4];
        let mut next: u64 = MIN_DERIVED_SERIAL;
        assert!(
            !unsafe {
                rust_cap_grant_into(&src as *const Capability, dest.as_mut_ptr(), 4, slot,
                                    !0u32, &mut next as *mut u64)
            },
            "a grant outside the destination cspace must refuse"
        );
    }

    /// The other half: revocation is COMPLETE downward. Revoking the root of a
    /// derivation chain nulls every descendant — the child and the grandchild —
    /// for every distinct serial triple, so no derived authority can outlive its
    /// ancestor. Together with the proof above this pins revocation to exactly
    /// the target's subtree: no more (no ancestors) and no less (all descendants).
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_root_nulls_every_descendant() {
        let p: u64 = kani::any();
        let c: u64 = kani::any();
        let g: u64 = kani::any();
        kani::assume(p != 0 && c != 0 && g != 0);
        kani::assume(p != c && c != g && p != g);

        let mut cs = chain(p, c, g);
        let desc = CSpaceDesc {
            caps: cs.as_mut_ptr(),
            size: 3,
            caps_in_use: core::ptr::null_mut(),
        };
        unsafe { revoke_subtree(&desc as *const CSpaceDesc, 1, p, 0, PipeTally::NONE) };

        assert!(cs[0].typ == CAP_NULL, "the revoked root must be nulled");
        assert!(cs[1].typ == CAP_NULL, "a direct child must be revoked with its parent");
        assert!(cs[2].typ == CAP_NULL, "a grandchild must be revoked transitively");
    }

    /// Revocation is SYSTEM-WIDE, not per-cspace (S3, S4): rust/KANI.md named a
    /// model across several cspaces as the next step, and this is it. A root in
    /// cspace A is granted into cspace B, and that child is granted back into A.
    /// Revoking the root nulls the child in B and the grandchild back in A, and
    /// spares an independent capability in B on the SAME object, for every
    /// distinct serial quadruple. The peer is what separates "revoke the subtree"
    /// from "revoke everything naming the object", the [I-3] defect.
    #[kani::proof]
    #[kani::unwind(8)]
    fn revoke_reaches_every_cspace_and_spares_a_peer() {
        let (p, c, g, q): (u64, u64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(p != 0 && c != 0 && g != 0 && q != 0);
        kani::assume(p != c && p != g && p != q && c != g && c != q && g != q);
        let obj: u64 = 7;
        let cap = |badge: u64, serial: u64| Capability {
            typ: 1, rights: 0x3f, object: obj, badge, serial, token: 0,
        };
        let mut a = [cap(0, p), cap(c, g)];
        let mut b = [cap(p, c), cap(0, q)];
        let d = [
            CSpaceDesc { caps: a.as_mut_ptr(), size: 2, caps_in_use: core::ptr::null_mut() },
            CSpaceDesc { caps: b.as_mut_ptr(), size: 2, caps_in_use: core::ptr::null_mut() },
        ];
        unsafe { revoke_subtree(d.as_ptr(), 2, p, obj, PipeTally::NONE) };

        assert!(a[0].typ == CAP_NULL, "the revoked root must be nulled");
        assert!(b[0].typ == CAP_NULL, "a child granted into another cspace must be revoked");
        assert!(a[1].typ == CAP_NULL, "a grandchild granted back must be revoked");
        assert!(b[1].typ != CAP_NULL && b[1].serial == q, "an independent peer on the same object must survive");
    }

    /// ONE SERIAL, ONE SLOT, the revocation half: after a system-wide revoke,
    /// NO slot anywhere still holds the revoked serial, whatever the cspaces held
    /// before, including a second slot carrying the same serial, which the
    /// allocator never produces but which this does not assume away. This is
    /// what lets lookup trust a capability for being in its slot, and lets a
    /// snapshot be re-checked by its slot and serial, with no generation record:
    /// the revoke empties every place the serial was.
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_leaves_no_slot_holding_the_serial() {
        let mut a = [Capability { typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 2];
        let mut b = [Capability { typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0 }; 2];
        for c in a.iter_mut().chain(b.iter_mut()) {
            *c = Capability {
                typ: kani::any(), rights: kani::any(), object: kani::any(),
                badge: kani::any(), serial: kani::any(), token: kani::any(),
            };
            // A slot never carries the revoke's in-flight marks.
            kani::assume(c.typ != CAP_MARK_NEW && c.typ != CAP_MARK_DONE);
        }
        // The target is a live, non-primordial capability in slot 1 of `a`
        // (slot 1 is reserved, so the primordial exemption is the one to rule
        // out; any other target is the same sweep).
        kani::assume(a[1].typ != CAP_NULL && a[1].serial != 0);
        kani::assume(!serial_is_primordial(a[1].serial));
        let target = a[1].serial;

        let pa = a.as_mut_ptr();
        let pb = b.as_mut_ptr();
        let spaces = [
            CSpaceDesc { caps: pa, size: 2, caps_in_use: core::ptr::null_mut() },
            CSpaceDesc { caps: pb, size: 2, caps_in_use: core::ptr::null_mut() },
        ];
        let ok = unsafe {
            rust_cap_revoke_global(pa, 2, 1, core::ptr::null_mut(), spaces.as_ptr(), 2,
                                   core::ptr::null_mut(), core::ptr::null_mut(), 0)
        };
        assert!(ok, "revoking a live, non-primordial capability must succeed");
        for i in 0..2 {
            unsafe {
                let ca = &*pa.add(i);
                let cb = &*pb.add(i);
                assert!(ca.typ == CAP_NULL || ca.serial != target, "a slot in `a` still holds the revoked serial");
                assert!(cb.typ == CAP_NULL || cb.serial != target, "a slot in `b` still holds the revoked serial");
            }
        }
    }

    /// LIMITATIONS 1.14: a revocation counts exactly the pipe ends it removes.
    /// For every content of two two-slot cspaces and every live target, the
    /// tally cell of each pipe and direction rises by exactly the number of
    /// ends of that pipe and direction that were in a slot before the revoke
    /// and are gone after it, and nothing is written past the tally's length.
    /// `cap_revoke` subtracts these counts from the pipe table: one too many
    /// frees a pipe while an end still names it (the #553 hazard), one too few
    /// leaves its peer waiting for an EOF that never comes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_counts_exactly_the_pipe_ends_it_removes() {
        let empty = Capability { typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0 };
        let mut a = [empty; 2];
        let mut b = [empty; 2];
        for c in a.iter_mut().chain(b.iter_mut()) {
            *c = Capability {
                typ: kani::any(), rights: kani::any(), object: kani::any(),
                badge: kani::any(), serial: kani::any(), token: kani::any(),
            };
            kani::assume(c.typ != CAP_MARK_NEW && c.typ != CAP_MARK_DONE);
            // Pipes 0 and 1 are inside the tally; pipe 2 is past its end.
            kani::assume(c.object < 3);
        }
        kani::assume(a[1].typ != CAP_NULL && a[1].serial != 0);
        kani::assume(!serial_is_primordial(a[1].serial));
        let (a0, b0) = (a, b);

        // Four cells for pipes 0 and 1; the last two are guards.
        let mut cells = [0u32; 6];
        let pa = a.as_mut_ptr();
        let pb = b.as_mut_ptr();
        let spaces = [
            CSpaceDesc { caps: pa, size: 2, caps_in_use: core::ptr::null_mut() },
            CSpaceDesc { caps: pb, size: 2, caps_in_use: core::ptr::null_mut() },
        ];
        let ok = unsafe {
            rust_cap_revoke_global(pa, 2, 1, core::ptr::null_mut(), spaces.as_ptr(), 2,
                                   core::ptr::null_mut(), cells.as_mut_ptr(), 4)
        };
        assert!(ok, "revoking a live, non-primordial capability must succeed");

        let removed = |pipe: u64, writer: bool| -> u32 {
            let mut n = 0u32;
            for i in 0..2 {
                for (before, after) in [(a0[i], unsafe { *pa.add(i) }), (b0[i], unsafe { *pb.add(i) })] {
                    if before.typ == CAP_PIPE && before.object == pipe
                        && ((before.rights & CAP_RIGHT_WRITE) != 0) == writer
                        && after.typ == CAP_NULL
                    {
                        n += 1;
                    }
                }
            }
            n
        };
        assert!(cells[0] == removed(0, false), "pipe 0's reader ends miscounted");
        assert!(cells[1] == removed(0, true), "pipe 0's writer ends miscounted");
        assert!(cells[2] == removed(1, false), "pipe 1's reader ends miscounted");
        assert!(cells[3] == removed(1, true), "pipe 1's writer ends miscounted");
        assert!(cells[4] == 0 && cells[5] == 0, "a count was written past the tally");
    }

    /// A reply-mint never widens: for EVERY (invoker rights, requested rights,
    /// token) triple, the child's rights are a subset of the capability the
    /// request came through, never include receive, name the same
    /// endpoint, and record that capability as their parent. This is what lets a
    /// server hold no mint authority of its own: whatever it asks for, it can only
    /// narrow what the caller already had.
    #[kani::proof]
    fn reply_mint_never_escalates_and_never_receives() {
        let src_rights: u32 = kani::any();
        let req_rights: u32 = kani::any();
        let token: u64 = kani::any();
        let src_token: u64 = kani::any();
        kani::assume(token != 0);

        let src = Capability {
            typ: CAP_ENDPOINT, rights: src_rights, object: 7, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: src_token,
        };
        let mut dest = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 8];
        let mut next: u64 = MIN_DERIVED_SERIAL;

        let ok = unsafe {
            rust_cap_reply_mint(&src as *const Capability, dest.as_mut_ptr(), 8, 5,
                                req_rights, token, &mut next as *mut u64)
        };
        assert!(ok, "a reply-mint from a live endpoint into an empty slot must succeed");
        assert!(dest[5].rights & !src_rights == 0, "reply-mint must not exceed the invoker's rights");
        assert!(dest[5].rights & TOKEN_STRIPPED_RIGHTS == 0, "a tokened capability never receives");
        assert!(dest[5].rights == (req_rights & src_rights & !TOKEN_STRIPPED_RIGHTS));
        assert!(dest[5].token == token, "the child carries the server's token");
        assert!(dest[5].object == src.object, "the child names the same endpoint");
        assert!(dest[5].badge == src.serial, "the child's parent is the invoking capability");
        assert!(dest[5].typ == CAP_ENDPOINT);
    }

    /// A token is minted only from an untokened endpoint capability that holds
    /// MINT, for EVERY source (type, rights, token). If this could succeed from a
    /// tokened source, a client could re-point its capability at another object.
    #[kani::proof]
    fn mint_token_only_from_an_untokened_minter() {
        let typ: u32 = kani::any();
        let src_rights: u32 = kani::any();
        let src_token: u64 = kani::any();
        let req_rights: u32 = kani::any();
        let token: u64 = kani::any();

        let mut cs = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 8];
        cs[4] = Capability {
            typ, rights: src_rights, object: 3, badge: 0,
            serial: MIN_DERIVED_SERIAL, token: src_token,
        };
        let mut next: u64 = MIN_DERIVED_SERIAL;

        let ok = unsafe {
            rust_cap_mint_token(cs.as_mut_ptr(), 8, 5, 4, req_rights, token, &mut next as *mut u64)
        };
        if ok {
            assert!(typ == CAP_ENDPOINT, "only an endpoint can mint a token");
            assert!(src_rights & CAP_RIGHT_MINT != 0, "minting a token needs MINT");
            assert!(src_token == 0, "a tokened capability can never mint a token");
            assert!(token != 0);
            assert!(cs[5].token == token);
            assert!(cs[5].rights & !src_rights == 0, "a minted token cannot widen");
            assert!(cs[5].rights & TOKEN_STRIPPED_RIGHTS == 0);
        } else {
            assert!(cs[5].typ == CAP_NULL && cs[5].token == 0, "a refusal writes nothing");
        }
    }

    /// Narrowing keeps identity: for EVERY token and rights pair, a minted copy
    /// carries its source's token. A copy that dropped it would be a capability
    /// the server can no longer tell apart from an untokened one; one that could
    /// change it is the re-pointing attack `mint_token_only_from_an_untokened_minter`
    /// rules out on the other path.
    #[kani::proof]
    fn mint_keeps_the_token() {
        let token: u64 = kani::any();
        let src_rights: u32 = kani::any();
        let req_rights: u32 = kani::any();

        let mut cs = [Capability {
            typ: CAP_NULL, rights: 0, object: 0, badge: 0, serial: 0, token: 0,
        }; 8];
        cs[0] = Capability {
            typ: CAP_ENDPOINT, rights: src_rights, object: 0, badge: 0,
            serial: MIN_DERIVED_SERIAL, token,
        };
        let mut next: u64 = MIN_DERIVED_SERIAL;
        let ok = unsafe { rust_cap_mint(cs.as_mut_ptr(), 8, 4, 0, req_rights, &mut next as *mut u64, 0) };
        assert!(ok);
        assert!(cs[4].token == token, "a narrowed copy names the same thing");
    }
}
