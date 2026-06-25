use core::ptr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub typ: u32,
    pub rights: u32,
    pub object: u64,
    pub badge: u32,
    pub serial: u32,
    pub generation: u32,
}

pub const CAP_NULL: u32 = 0;

const CNODE_SIZE: u32 = 256;
const KERNEL_RESERVED_CAPS: u32 = 4;


const MIN_DERIVED_SERIAL: u32 = 0x00010000;





const LINEAGE_SLOTS: usize = 4096;
static mut LINEAGE_GEN: [u32; LINEAGE_SLOTS] = [0u32; LINEAGE_SLOTS];



#[inline]
fn lineage_idx(obj: u64) -> usize {
    let mut x = obj;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) & (LINEAGE_SLOTS - 1)
}

#[inline]
unsafe fn bump_lineage(obj: u64) -> u32 {
    if obj == 0 { return 0; }
    let idx = lineage_idx(obj);
    let g = LINEAGE_GEN[idx].wrapping_add(1);
    LINEAGE_GEN[idx] = if g == 0 { 1 } else { g };
    LINEAGE_GEN[idx]
}

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
    if cap.object != 0 {
        let cg = LINEAGE_GEN[lineage_idx(cap.object)];
        if cg != 0 && cap.generation != 0 && cap.generation != cg {
            return ptr::null_mut();
        }
    }
    cap
}

#[inline]
unsafe fn assign_fresh_serial(next_serial: *mut u32) -> u32 {
    if next_serial.is_null() {
        
        return 0xC0DEFFFFu32;
    }
    let cur = *next_serial;
    
    
    let base = if cur < MIN_DERIVED_SERIAL { MIN_DERIVED_SERIAL } else { cur };
    let fresh = base.wrapping_add(1);
    let fresh = if fresh < MIN_DERIVED_SERIAL || fresh == 0 { MIN_DERIVED_SERIAL } else { fresh };
    *next_serial = fresh;
    fresh
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_mint(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    new_rights: u32,
    next_serial: *mut u32,
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

    let dest = &mut *cspace.add(dest_slot as usize);

    
    
    let parent_serial = src.serial;

    let fresh = assign_fresh_serial(next_serial);

    
    let effective_rights = new_rights & src.rights;

    *dest = Capability {
        typ: src.typ,
        rights: effective_rights,
        object: src.object,
        badge: parent_serial,
        serial: fresh,
        generation: src.generation,
    };
    if src.object != 0 {
        let idx = lineage_idx(src.object);
        if LINEAGE_GEN[idx] < src.generation { LINEAGE_GEN[idx] = src.generation; }
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_transfer(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u32,
) -> bool {
    rust_cap_mint(cspace, cspace_size, dest_slot, src_slot, !0u32, next_serial, 0)
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_move(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u32,
) -> bool {
    if rust_cap_transfer(cspace, cspace_size, dest_slot, src_slot, next_serial) {
        return rust_cap_revoke(cspace, cspace_size, src_slot, next_serial);
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    _next_serial: *mut u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return false;
    }

    
    
    
    
    
    let is_primordial_root = slot < KERNEL_RESERVED_CAPS &&
        (*cspace.add(slot as usize)).serial != 0 &&
        ((*cspace.add(slot as usize)).serial & 0xFFFF0000) == 0xC0DE0000;

    if is_primordial_root {
        return false;
    }

    let target = &mut *cspace.add(slot as usize);
    if target.typ == CAP_NULL {
        return true; 
    }

    let target_serial = target.serial;
    let target_badge = target.badge;
    let target_obj = target.object;

    
    target.typ = CAP_NULL;
    target.rights = 0;
    target.object = 0;
    target.badge = 0;
    target.serial = 0;
    target.generation = 0;

    if target_obj != 0 { let _ = bump_lineage(target_obj); }

    
    
    
    let limit = if cspace_size > CNODE_SIZE { CNODE_SIZE } else { cspace_size };
    for i in 0..limit {
        if i == slot {
            continue;
        }
        let c = &mut *cspace.add(i as usize);
        if c.typ == CAP_NULL {
            continue;
        }

        let matches_lineage =
            (target_serial != 0 && (c.serial == target_serial || c.badge == target_serial)) ||
            (target_badge != 0 && (c.serial == target_badge || c.badge == target_badge)) ||
            (target_obj != 0 && c.object == target_obj);

        if matches_lineage {
            c.typ = CAP_NULL;
            c.rights = 0;
            c.object = 0;
            c.badge = 0;
            c.serial = 0;
            c.generation = 0;
        }
    }

    true
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_cross_task_revoke(
    all_task_cspaces: *mut Capability,
    max_tasks: i32,
    cspace_elems: i32,
    target_serial: u32,
    target_badge: u32,
    target_obj: u64,
    caps_in_use_array: *mut i32,
) {
    if all_task_cspaces.is_null() || max_tasks <= 0 || cspace_elems <= 0 {
        return;
    }

    let total = (max_tasks as usize) * (cspace_elems as usize);
    for i in 0..total {
        let cap = unsafe { &mut *all_task_cspaces.add(i) };
        if cap.typ == CAP_NULL {
            continue;
        }
        let matches =
            (target_serial != 0 && (cap.serial == target_serial || cap.badge == target_serial)) ||
            (target_badge != 0 && (cap.serial == target_badge || cap.badge == target_badge)) ||
            (target_obj != 0 && cap.object == target_obj);

        if matches {
            if !caps_in_use_array.is_null() {
                let tid = i / (cspace_elems as usize);
                unsafe {
                    if *caps_in_use_array.add(tid) > 0 {
                        *caps_in_use_array.add(tid) -= 1;
                    }
                }
            }
            if cap.object != 0 { let _ = bump_lineage(cap.object); }
            cap.typ = CAP_NULL;
            cap.rights = 0;
            cap.object = 0;
            cap.badge = 0;
            cap.serial = 0;
            cap.generation = 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_by_values(cspace:*mut Capability,cspace_size:u32,target_serial:u32,target_badge:u32,target_obj:u64)->bool{
 if cspace.is_null(){return false;}
 let limit=if cspace_size>CNODE_SIZE{CNODE_SIZE}else{cspace_size};
 for i in 0..limit{
  let c=&mut *cspace.add(i as usize);
  if c.typ==CAP_NULL{continue;}
  let m=(target_serial!=0&&(c.serial==target_serial||c.badge==target_serial))||(target_badge!=0&&(c.serial==target_badge||c.badge==target_badge))||(target_obj!=0&&c.object==target_obj);
  if m{
   if c.object != 0 { let _ = bump_lineage(c.object); }
   c.typ=CAP_NULL;c.rights=0;c.object=0;c.badge=0;c.serial=0;c.generation=0;
  }
 }
 true
}

#[no_mangle]
pub unsafe extern "C" fn rust_lineage_bump(obj: u64) -> u32 { bump_lineage(obj) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_and_mint_basic() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 42, badge: 0, serial: 0x1000, generation: 0 };

        let mut next = 0x1001u32;

        unsafe {
            let ok = rust_cap_mint(
                cspace.as_mut_ptr(),
                16,
                5,
                0,
                0x3,
                &mut next as *mut u32,
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
            assert_eq!(c5.generation, 0);
        }
    }

    #[test]
    fn test_revoke_clears_and_serial_is_fresh() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 99, badge: 0, serial: 0x2000, generation: 1 };

        let mut next = 0x2001u32;
        unsafe {
            let mint_ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 6, 0, 0x7, &mut next, 0);
            assert!(mint_ok);
            let child_before = *cspace.as_ptr().add(6);
            assert_eq!(child_before.badge, 0x2000);
            assert_eq!(child_before.generation, 1);

            
            let rev_ok = rust_cap_revoke(cspace.as_mut_ptr(), 16, 0, core::ptr::null_mut());
            assert!(rev_ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 6, 0x1);
            assert!(looked.is_null(), "derived cap must be revoked together with parent (badge lineage)");
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 0, 0).is_null());
        }
    }

    #[test]
    fn test_lineage_no_collision_on_low_bits() {
        
        
        
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        unsafe {
            let ga = bump_lineage(0x1001);
            let gb = bump_lineage(0x1101);
            cs[4] = Capability { typ: 1, rights: 0x3f, object: 0x1001, badge: 0, serial: 0x100, generation: ga };
            cs[5] = Capability { typ: 1, rights: 0x3f, object: 0x1101, badge: 0, serial: 0x200, generation: gb };

            
            let _ = bump_lineage(0x1001);

            
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 4, 0x1).is_null(),
                "object 0x1001 should be stale after its lineage bump");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "object 0x1101 must NOT be revoked by a bump targeting 0x1001");
        }
    }

    #[test]
    fn test_strict_rights_and_no_escalation() {
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 5, rights: 0b0011, object: 7, badge: 0, serial: 0x3000, generation: 0 };

        let mut next = 0x3001u32;
        unsafe {
            
            let ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 4, 0, 0xFFFF, &mut next, 0);
            assert!(ok);
            let child = &*rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0);
            
            assert_eq!(child.rights, 0b0011);
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0b0100).is_null());
        }
    }
}
