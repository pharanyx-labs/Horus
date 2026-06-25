-------------------------- MODULE paging_isolation --------------------------
EXTENDS Naturals

CONSTANTS MAX_TASKS, PAGE_SIZE, USER_BASE, USER_MAX, KERNEL_HIGH

VARIABLES pml4s, page_tables, task_cr3

PTE == [paddr: Nat, flags: Nat]

Init ==
    /\ pml4s = [t \in 1..MAX_TASKS |-> [i \in 0..511 |-> 0]]
    /\ page_tables = [i \in 0..1023 |-> 0]
    /\ task_cr3 = [t \in 1..MAX_TASKS |-> 0]

CreateUserPML4(tid, kbase) ==
    /\ task_cr3' = [task_cr3 EXCEPT ![tid] = kbase]
    /\ pml4s' = [pml4s EXCEPT ![tid][0] = 1, ![tid][510] = kbase, ![tid][256] = kbase ]
    /\ UNCHANGED page_tables

MapUserPage(tid, vaddr, paddr) ==
    /\ vaddr >= USER_BASE /\ vaddr < USER_MAX
    /\ paddr < KERNEL_HIGH
    /\ UNCHANGED <<pml4s, task_cr3>>
    /\ page_tables' = [page_tables EXCEPT ![ (vaddr \div PAGE_SIZE) % 1024 ] = paddr + 7 ]

DemandFault(tid, vaddr, is_write) ==
    /\ vaddr >= USER_BASE /\ vaddr < USER_MAX
    /\ MapUserPage(tid, vaddr, 0x200000)

Inv ==
    \A t \in 1..MAX_TASKS, i \in 256..511 :
        pml4s[t][i] # 0 => (pml4s[t][i] % 4) = 0
    \A t \in 1..MAX_TASKS :
        task_cr3[t] # 0 => pml4s[t][510] # 0

Next ==
    \/ \E t \in 1..MAX_TASKS, v,p \in Nat : MapUserPage(t, v, p)
    \/ \E t \in 1..MAX_TASKS : DemandFault(t, USER_BASE, FALSE)

Spec == Init /\ [][Next]_<<pml4s, page_tables, task_cr3>>

=============================================================================