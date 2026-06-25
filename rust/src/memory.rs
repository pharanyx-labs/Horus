pub const USER_PHYS_PAGES: u32 = 16384;
pub const USER_PHYS_BASE: u32 = 0x01000000;
pub const PAGE_SIZE: u32 = 4096;

#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_inc(phys: u32, refcounts: *mut u16, n_pages: u32) -> u16 {
    if refcounts.is_null() || n_pages == 0 || n_pages > USER_PHYS_PAGES {
        return 0;
    }
    if phys < USER_PHYS_BASE {
        return 0;
    }
    let idx32 = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if idx32 >= n_pages {
        return 0;
    }
    let idx = idx32 as usize;
    let cur = *refcounts.add(idx);
    let next = cur.saturating_add(1);
    *refcounts.add(idx) = next;
    next
}

#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_dec(phys: u32, refcounts: *mut u16, n_pages: u32) -> i32 {
    if refcounts.is_null() || n_pages == 0 || n_pages > USER_PHYS_PAGES {
        return -1;
    }
    if phys < USER_PHYS_BASE {
        return -1;
    }
    let idx32 = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if idx32 >= n_pages {
        return -1;
    }
    let idx = idx32 as usize;
    let cur = *refcounts.add(idx);
    if cur == 0 {
        return -2;
    }
    let next = cur - 1;
    *refcounts.add(idx) = next;
    next as i32
}

#[no_mangle]
pub unsafe extern "C" fn rust_page_is_valid_user_phys(phys: u32, n_pages: u32) -> bool {
    if n_pages == 0 || n_pages > USER_PHYS_PAGES {
        return false;
    }
    if phys < USER_PHYS_BASE {
        return false;
    }
    let idx = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    idx < n_pages
}

#[no_mangle]
pub unsafe extern "C" fn rust_alloc_user_physical_page(
    free_stack: *mut u32,
    free_count: *mut i32,
    n_pages: u32,
) -> u32 {
    if free_stack.is_null() || free_count.is_null() || n_pages == 0 || n_pages > USER_PHYS_PAGES {
        return 0;
    }
    let cnt = *free_count;
    if cnt <= 0 {
        return 0;
    }
    let new_cnt = cnt - 1;
    let phys = *free_stack.add(new_cnt as usize);
    if !rust_page_is_valid_user_phys(phys, n_pages) {
        return 0;
    }
    *free_count = new_cnt;
    phys
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_user_physical_page(
    phys: u32,
    free_stack: *mut u32,
    free_count: *mut i32,
    n_pages: u32,
) -> bool {
    if free_stack.is_null() || free_count.is_null() || n_pages == 0 || n_pages > USER_PHYS_PAGES {
        return false;
    }
    if !rust_page_is_valid_user_phys(phys, n_pages) {
        return false;
    }
    let cnt = *free_count;
    if cnt < 0 || (cnt as u32) >= n_pages {
        return false;
    }
    *free_stack.add(cnt as usize) = phys;
    *free_count = cnt + 1;
    true
}


