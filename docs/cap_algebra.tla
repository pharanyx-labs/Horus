-------------------------- MODULE cap_algebra --------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MAX_LINEAGES, CNODE_SIZE, MAX_TASKS, KERNEL_RESERVED

VARIABLES lineages, cspaces, next_lineage, next_serial

Cap == [type: Nat, rights: Nat, object: Nat, badge: Nat, serial: Nat, generation: Nat]

Init ==
    /\ lineages = [i \in 1..MAX_LINEAGES |-> [object_id |-> 0, generation |-> 0, refcount |-> 0, valid |-> FALSE]]
    /\ cspaces = [t \in 1..MAX_TASKS |-> [s \in 1..CNODE_SIZE |-> [type |-> 0, rights |-> 0, object |-> 0, badge |-> 0, serial |-> 0, generation |-> 0]]]
    /\ next_lineage = 1
    /\ next_serial = 0x10000

FreshSerial ==
    LET s == IF next_serial < 0x10000 THEN 0x10000 ELSE next_serial + 1 IN
    IF s = 0 THEN 0x10000 ELSE s

RegisterLineage(obj) ==
    /\ next_lineage <= MAX_LINEAGES
    /\ lineages' = [lineages EXCEPT ![next_lineage] = [object_id |-> obj, generation |-> 1, refcount |-> 1, valid |-> TRUE]]
    /\ next_lineage' = next_lineage + 1
    /\ UNCHANGED <<cspaces, next_serial>>

BumpGen(obj) ==
    \E i \in 1..MAX_LINEAGES :
        /\ lineages[i].valid
        /\ (lineages[i].object_id = obj \/ lineages[i].object_id = 0)
        /\ lineages' = [lineages EXCEPT ![i].generation = lineages[i].generation + 1, ![i].refcount = 0]
        /\ UNCHANGED <<cspaces, next_lineage, next_serial>>

Mint(src_task, src_slot, dst_task, dst_slot, new_rights) ==
    /\ src_slot < CNODE_SIZE /\ dst_slot < CNODE_SIZE /\ dst_slot >= KERNEL_RESERVED
    /\ LET src == cspaces[src_task][src_slot]
           dst == cspaces[dst_task][dst_slot]
           eff == new_rights /\ src.rights
           fs == FreshSerial
           g == src.generation
       IN
       /\ src.type # 0 /\ src.serial # 0
       /\ dst.type = 0
       /\ cspaces' = [cspaces EXCEPT ![dst_task][dst_slot] =
            [type |-> src.type, rights |-> eff, object |-> src.object,
             badge |-> src.serial, serial |-> fs, generation |-> g ]]
       /\ next_serial' = fs
       /\ UNCHANGED <<lineages, next_lineage>>

Revoke(task, slot) ==
    /\ slot < CNODE_SIZE
    /\ LET tgt == cspaces[task][slot]
           ts == tgt.serial
           tb == tgt.badge
           to == tgt.object
       IN
       /\ tgt.type # 0
       /\ cspaces' = [cspaces EXCEPT ![task][slot] =
            [type |-> 0, rights |-> 0, object |-> 0, badge |-> 0, serial |-> 0, generation |-> 0 ],
                      ![t \in 1..MAX_TASKS |-> [s \in 1..CNODE_SIZE |-> IF
                         (cspaces[t][s].serial = ts \/ cspaces[t][s].badge = ts \/
                          cspaces[t][s].serial = tb \/ cspaces[t][s].badge = tb \/
                          (to # 0 /\ cspaces[t][s].object = to))
                         THEN [type |-> 0, rights |-> 0, object |-> 0, badge |-> 0, serial |-> 0, generation |-> 0]
                         ELSE cspaces[t][s] ]]]
       /\ BumpGen(to)
       /\ UNCHANGED <<next_lineage, next_serial>>

Transfer(src_task, src_slot, dst_task, dst_slot) ==
    Mint(src_task, src_slot, dst_task, dst_slot, 0xFFFFFFFF)

ValidateLookup(task, slot, req_rights) ==
    LET c == cspaces[task][slot]
        idx == IF c.object < MAX_LINEAGES THEN c.object ELSE 1
        lin_gen == IF lineages[idx].valid THEN lineages[idx].generation ELSE c.generation
    IN c.type # 0 /\ c.serial # 0 /\ (c.rights /\ req_rights) = req_rights /\ c.generation = lin_gen

NoEscalation ==
    \A t \in 1..MAX_TASKS, s \in 1..CNODE_SIZE :
        LET c == cspaces[t][s] IN c.type # 0 => c.rights <= 0xFFFFFFFF

Inv ==
    /\ \A t \in 1..MAX_TASKS, s \in 1..CNODE_SIZE : cspaces[t][s].type # 0 => ValidateLookup(t, s, 0)
    /\ \A t \in 1..MAX_TASKS, s \in 1..CNODE_SIZE : cspaces[t][s].serial = 0 => cspaces[t][s].type = 0
    /\ NoEscalation

Next ==
    \/ \E o \in 1..100 : RegisterLineage(o)
    \/ \E lid \in 1..MAX_LINEAGES : BumpGen(0)
    \/ \E st,ss,dt,ds,r \in 0..255 : Mint(st, ss, dt, ds, r)
    \/ \E t,s \in 0..255 : Revoke(t, s)
    \/ \E st,ss,dt,ds \in 0..255 : Transfer(st, ss, dt, ds)

Spec == Init /\ [][Next]_<<lineages, cspaces, next_lineage, next_serial>>

=============================================================================
