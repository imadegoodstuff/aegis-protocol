import Cchs.Verifier

/-!
# CCHS client: ONE-MESSAGE, machine-checked

`model/cchs-client.mjs` explores, for small bounds, the rules a signer follows
so that no WOTS+ leaf ever signs two different messages (`CCHS.spec.md` §4.3).
This file proves the property for every trace of the following abstraction of
the reference client, for any number of devices and any geometry.

Modelled:

* Devices `d : Nat`, each assigned a lane `L d` (injective: no two devices share
  a lane — rule 4). A device signs only at indices of its own lane.
* A per-device, per-epoch record `floor d e`: the smallest index the device may
  still sign in epoch `e` (`highest signed + 1`; rule 1). The record is advanced
  in the same step that produces the signature — the write-ahead discipline of
  rule 2 (a client that signs first and records afterwards can crash in
  between; that is the `record-after-sign` mutant of the bounded model and is
  outside this abstraction by construction).
* `restore d`: the record of `d` is replaced by *any* value (an older backup).
  The device is then `stale` and must not sign until a recovery (rule 3).
* `recover`: new epoch. Records of the new epoch start at zero and every device
  is fresh again; keys are derived per epoch, so leaves of different epochs are
  different leaves.
* Signing takes any `idx ≥ floor d epoch` in the device's lane. The reference
  client picks `max(nextIdx, floor)`; proving the more general rule covers it.
  The chain's counter plays no role in the proof: the record alone protects the
  leaf, which is exactly why a lost record is fatal and must be handled by
  recovery.

Not modelled: the recovery leaf (its message is a pure function of
`(epoch, recNonce)` by key derivation, §4.3 rule 6, not a transition-system
fact), and several chains (one key tree per chain by derivation, §3).

Theorem `one_message`: along any trace, two signatures over the same leaf
`(epoch, idx)` are the same signature — in particular they carry the same
message.
-/

namespace Cchs.Client

open Cchs

/-- A signature the client produced: device, epoch, index, message. -/
structure Signed where
  dev : Nat
  epoch : Nat
  idx : Nat
  msg : Nat
  deriving DecidableEq, Repr

structure CState where
  epoch : Nat
  floor : Nat → Nat → Nat   -- device → epoch → next index the device may sign
  stale : Nat → Bool        -- restored from a backup since the last recovery
  sigs : List Signed        -- every signature ever produced

variable (P : Params) (L : Nat → Nat)

def initial : CState := { epoch := 0, floor := fun _ _ => 0, stale := fun _ => false, sigs := [] }

inductive Step : CState → CState → Prop
  | sign {s} (d idx msg : Nat)
      (hstale : s.stale d = false)
      (hfloor : s.floor d s.epoch ≤ idx)
      (hlane : lane P idx = L d) :
      Step s { s with
        floor := fun d' e => if d' = d ∧ e = s.epoch then idx + 1 else s.floor d' e,
        sigs := ⟨d, s.epoch, idx, msg⟩ :: s.sigs }
  | restore {s} (d : Nat) (old : Nat → Nat) :
      Step s { s with
        floor := fun d' e => if d' = d then old e else s.floor d' e,
        stale := fun d' => if d' = d then true else s.stale d' }
  | recover {s} :
      Step s { s with epoch := s.epoch + 1, stale := fun _ => false }

inductive Reachable : CState → Prop
  | init : Reachable initial
  | step {s s'} : Reachable s → Step P L s s' → Reachable s'

/-- The invariant carried through every trace. -/
structure Inv (s : CState) : Prop where
  lanes : ∀ g ∈ s.sigs, lane P g.idx = L g.dev
  epochs : ∀ g ∈ s.sigs, g.epoch ≤ s.epoch
  below : ∀ g ∈ s.sigs, g.epoch = s.epoch → s.stale g.dev = true ∨ g.idx < s.floor g.dev g.epoch
  unique : ∀ g ∈ s.sigs, ∀ g' ∈ s.sigs, g.epoch = g'.epoch → g.idx = g'.idx → g = g'

theorem inv_initial : Inv P L initial := by
  constructor <;> simp [initial]

theorem inv_step (hL : ∀ a b, L a = L b → a = b) {s s' : CState} (inv : Inv P L s) (st : Step P L s s') :
    Inv P L s' := by
  cases st with
  | sign d idx msg hstale hfloor hlane =>
    -- a new signature at (s.epoch, idx) by d
    have fresh : ∀ g ∈ s.sigs, g.epoch = s.epoch → g.idx = idx → False := by
      intro g hg he hi
      by_cases hd : g.dev = d
      · rcases inv.below g hg he with hst | hlt
        · rw [hd, hstale] at hst; cases hst
        · rw [hd, he, hi] at hlt; omega
      · apply hd
        apply hL
        rw [← inv.lanes g hg, hi, hlane]
    constructor
    · intro g hg
      simp only [List.mem_cons] at hg
      rcases hg with rfl | hg
      · exact hlane
      · exact inv.lanes g hg
    · intro g hg
      simp only [List.mem_cons] at hg
      rcases hg with rfl | hg
      · exact Nat.le_refl _
      · exact inv.epochs g hg
    · intro g hg he
      simp only [List.mem_cons] at hg
      simp only at he
      rcases hg with rfl | hg
      · right; simp
      · rcases inv.below g hg he with hst | hlt
        · left; exact hst
        · right
          simp only
          split
          · rename_i hc; rw [hc.1, he] at hlt; omega
          · exact hlt
    · intro g hg g' hg' he hi
      simp only [List.mem_cons] at hg hg'
      rcases hg with rfl | hg <;> rcases hg' with rfl | hg'
      · rfl
      · exact absurd (fresh g' hg' he.symm hi.symm) id
      · exact absurd (fresh g hg he hi) id
      · exact inv.unique g hg g' hg' he hi
  | restore d old =>
    constructor
    · exact inv.lanes
    · exact inv.epochs
    · intro g hg he
      simp only
      by_cases hd : g.dev = d
      · left; rw [if_pos hd]
      · rw [if_neg hd, if_neg hd]
        exact inv.below g hg he
    · exact inv.unique
  | recover =>
    constructor
    · exact inv.lanes
    · intro g hg; exact Nat.le_succ_of_le (inv.epochs g hg)
    · intro g hg he
      have := inv.epochs g hg
      simp only at he
      omega
    · exact inv.unique

theorem inv_reachable (hL : ∀ a b, L a = L b → a = b) {s : CState} (hs : Reachable P L s) : Inv P L s := by
  induction hs with
  | init => exact inv_initial P L
  | step _ st ih => exact inv_step P L hL ih st

/-- ONE-MESSAGE: two signatures over one leaf are one signature. -/
theorem one_message (hL : ∀ a b, L a = L b → a = b) {s : CState} (hs : Reachable P L s)
    {g g' : Signed} (hg : g ∈ s.sigs) (hg' : g' ∈ s.sigs)
    (he : g.epoch = g'.epoch) (hi : g.idx = g'.idx) : g.msg = g'.msg := by
  have := (inv_reachable P L hL hs).unique g hg g' hg' he hi
  rw [this]

end Cchs.Client
