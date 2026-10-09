/-!
# CCHS verifier: machine-checked transition invariants

This file states the CCHS account verifier (`CCHS.spec.md` §5, §8) as a
transition system over an *abstract hash world* and proves the invariants that
`model/cchs-state.mjs` checks by bounded exploration — here for every
parameter choice and every reachable state, not just small bounds.

What is abstracted, and how:

* A signature object remembers what it was made over (`Sig`). Recomputing a
  root from a signature over the inputs it was made for yields the genuine
  root; over any other inputs it yields `Root.garbage`.
* `Root.matches garbage _ = false` is the hash assumption: a value recomputed
  from a signature over the wrong inputs never equals a genuine root
  (second-preimage resistance of the chaining and tree hashes). Nothing about
  SHA-256 or keccak is proven here; the theorems are about everything *except*
  the hash.
* `Sig.leaked` marks a signature forged with bottom-layer keys that the
  two-message exposure of WOTS+ (§4.3) may hand to an adversary. Such keys only
  exist for subtrees whose leaves are all behind the lane's `nextIdx`; theorem
  `leaked_rejected` shows the index check alone rejects them. A forged top layer
  is excluded by construction (`recomputeTop` requires `¬leaked`): the layer-1
  key signs one message per subtree, so it is never exposed twice.

Parameters are general: `T` leaves per bottom subtree and `K` subtrees per
lane, both positive. The reference contracts have `T = 2^10`, `K = 2^6`
(16 lanes); the bounded model has `T = 2`, `K = 2`.

Proven (names match `CCHS.spec.md` §6):

* `C4`  `cache_genuine`: every cache entry of epoch `e` at tree `t` is the
  owner's genuine bottom root for `(e, t)`.
* `cache_once`: a cache entry never changes once written.
* `NF`/`C3` `accept_inputs`: an accepted signature was made in the current
  epoch over exactly the accepted `(idx, lane nonce, target)`.
* `C5`  `nextIdx_mono`, `accept_sets_nextIdx`, `no_double_accept`: the lane
  counter never decreases, an acceptance at `idx` sets it to `idx + 1`, and no
  `(epoch, idx)` is accepted twice along any execution.
* `LI`  `lane_independence`: an acceptance in lane `l` leaves the verifier's
  verdict on *every* submission for another lane unchanged. This is what lets
  devices owning distinct lanes sign concurrently without coordination.
-/

namespace Cchs

/-- Abstract roots. -/
inductive Root
  | bottom (epoch tree : Nat)
  | top (epoch : Nat)
  | garbage
  deriving DecidableEq, Repr

/-- Equality of roots as the verifier sees it. `garbage` matches nothing, not
even itself: it stands for a fresh value. -/
def Root.matches : Root → Root → Bool
  | .bottom e t, .bottom e' t' => e == e' && t == t'
  | .top e, .top e' => e == e'
  | _, _ => false

@[simp] theorem Root.matches_garbage_left (r : Root) : Root.matches .garbage r = false := by
  cases r <;> rfl

@[simp] theorem Root.matches_garbage_right (r : Root) : Root.matches r .garbage = false := by
  cases r <;> rfl

theorem Root.matches_bottom_iff (e t e' t' : Nat) :
    Root.matches (.bottom e t) (.bottom e' t') = true ↔ e = e' ∧ t = t' := by
  simp [Root.matches]

theorem Root.matches_top_iff (e e' : Nat) : Root.matches (.top e) (.top e') = true ↔ e = e' := by
  simp [Root.matches]

/-- A layer-0 signature object: what the owner (or a forger) committed to. -/
structure Sig where
  epoch : Nat
  idx : Nat
  nonce : Nat
  target : Nat
  withTop : Bool
  leaked : Bool
  deriving DecidableEq, Repr

/-- Tree geometry. `T` leaves per bottom subtree, `K` subtrees per lane. -/
structure Params where
  T : Nat
  K : Nat
  cap : Nat
  hT : 0 < T
  hK : 0 < K

variable (P : Params)

def tree (idx : Nat) : Nat := idx / P.T
def lane (idx : Nat) : Nat := idx / (P.T * P.K)

/-- Lanes are unions of whole subtrees: equal trees lie in equal lanes. -/
theorem lane_eq_of_tree_eq {a b : Nat} (h : tree P a = tree P b) : lane P a = lane P b := by
  unfold tree at h
  unfold lane
  rw [← Nat.div_div_eq_div_mul, ← Nat.div_div_eq_div_mul, h]

theorem tree_ne_of_lane_ne {a b : Nat} (h : lane P a ≠ lane P b) : tree P a ≠ tree P b :=
  fun ht => h (lane_eq_of_tree_eq P ht)

/-- Verifier state. Lane counters and the cache are keyed by epoch, so a
recovery (epoch bump) reads fresh zeroed slots without touching storage. -/
structure State where
  epoch : Nat
  nextIdx : Nat → Nat → Nat        -- epoch → lane → next index (stored; fresh = 0)
  nonce : Nat → Nat → Nat          -- epoch → lane → nonce
  cache : Nat → Nat → Option Root  -- epoch → tree → cached bottom root

/-- A submission: a signature object, and the inputs the submitter claims. -/
structure Tx where
  sig : Sig
  idx : Nat
  target : Nat
  first : Bool                     -- executeFirst (carries a top layer)

inductive Verdict
  | accept (r0 : Root) (register : Bool)
  | reject
  deriving DecidableEq, Repr

def sameInputs (sig : Sig) (nonce idx target : Nat) : Bool :=
  sig.idx == idx && sig.nonce == nonce && sig.target == target

theorem sameInputs_iff (sig : Sig) (nonce idx target : Nat) :
    sameInputs sig nonce idx target = true ↔ sig.idx = idx ∧ sig.nonce = nonce ∧ sig.target = target := by
  simp [sameInputs, and_assoc]

/-- The bottom root a verifier recomputes from `sig` over the given inputs. -/
def recomputeBottom (sig : Sig) (nonce idx target t : Nat) : Root :=
  if sameInputs sig nonce idx target then .bottom sig.epoch t else .garbage

/-- The top root a verifier recomputes from the top layer carried by `sig`. -/
def recomputeTop (sig : Sig) (nonce idx target : Nat) : Root :=
  if sig.withTop && sameInputs sig nonce idx target && !sig.leaked then .top sig.epoch else .garbage

/-- `execute` / `executeFirst` (CCHS.spec.md §5). -/
def verify (s : State) (tx : Tx) : Verdict :=
  if P.cap ≤ tx.idx then .reject
  else if tx.idx < s.nextIdx s.epoch (lane P tx.idx) then .reject
  else
    let t := tree P tx.idx
    let n := s.nonce s.epoch (lane P tx.idx)
    let r0 := recomputeBottom tx.sig n tx.idx tx.target t
    match s.cache s.epoch t with
    | some c => if Root.matches c r0 then .accept r0 false else .reject
    | none =>
      if tx.first then
        if Root.matches (recomputeTop tx.sig n tx.idx tx.target) (.top s.epoch) then .accept r0 true
        else .reject
      else .reject

/-- State after an acceptance: the lane's counter and nonce move, and the
subtree root is registered when the top layer was checked. -/
def apply (s : State) (tx : Tx) (r0 : Root) (register : Bool) : State :=
  { s with
    nextIdx := fun e l => if e = s.epoch ∧ l = lane P tx.idx then tx.idx + 1 else s.nextIdx e l
    nonce := fun e l => if e = s.epoch ∧ l = lane P tx.idx then s.nonce e l + 1 else s.nonce e l
    cache := fun e t => if register ∧ e = s.epoch ∧ t = tree P tx.idx then some r0 else s.cache e t }

/-- `recover` (§8): new epoch; every lane and the cache read fresh. -/
def recover (s : State) : State := { s with epoch := s.epoch + 1 }

def initial : State :=
  { epoch := 0, nextIdx := fun _ _ => 0, nonce := fun _ _ => 0, cache := fun _ _ => none }

inductive Step : State → State → Prop
  | exec {s tx r0 reg} : verify P s tx = .accept r0 reg → Step s (apply P s tx r0 reg)
  | recover {s} : Step s (recover s)

inductive Reachable : State → Prop
  | init : Reachable initial
  | step {s s'} : Reachable s → Step P s s' → Reachable s'

/-- Zero or more steps. -/
inductive Steps : State → State → Prop
  | refl {s} : Steps s s
  | tail {s s' s''} : Steps s s' → Step P s' s'' → Steps s s''

/-! ## Reading off what an acceptance implies -/

theorem accept_index {s : State} {tx : Tx} {r0 : Root} {reg : Bool}
    (h : verify P s tx = .accept r0 reg) :
    tx.idx < P.cap ∧ s.nextIdx s.epoch (lane P tx.idx) ≤ tx.idx := by
  unfold verify at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · omega

/-- Shape of an acceptance: either the cached root matched the recomputed bottom
root, or there was no cache entry, `first` was set and the recomputed top root
matched the account root. In both cases `r0` is the recomputed bottom root. -/
theorem accept_cases {s : State} {tx : Tx} {r0 : Root} {reg : Bool}
    (h : verify P s tx = .accept r0 reg) :
    r0 = recomputeBottom tx.sig (s.nonce s.epoch (lane P tx.idx)) tx.idx tx.target (tree P tx.idx) ∧
    ((reg = false ∧ ∃ c, s.cache s.epoch (tree P tx.idx) = some c ∧ Root.matches c r0 = true) ∨
     (reg = true ∧ s.cache s.epoch (tree P tx.idx) = none ∧ tx.first = true ∧
      Root.matches (recomputeTop tx.sig (s.nonce s.epoch (lane P tx.idx)) tx.idx tx.target) (.top s.epoch) = true)) := by
  unfold verify at h
  split at h
  · exact absurd h (by simp)
  split at h
  · exact absurd h (by simp)
  simp only at h
  split at h
  · rename_i c hc
    split at h
    · rename_i hm
      cases h
      exact ⟨rfl, Or.inl ⟨rfl, c, hc, hm⟩⟩
    · exact absurd h (by simp)
  · rename_i hc
    split at h
    · rename_i hf
      split at h
      · rename_i hm
        cases h
        exact ⟨rfl, Or.inr ⟨rfl, hc, hf, hm⟩⟩
      · exact absurd h (by simp)
    · exact absurd h (by simp)

/-! ## C4: the cache only ever holds genuine roots of its epoch -/

def CacheGenuine (s : State) : Prop :=
  ∀ e t r, s.cache e t = some r → r = .bottom e t

theorem recomputeTop_matches {sig : Sig} {n idx target e : Nat}
    (h : Root.matches (recomputeTop sig n idx target) (.top e) = true) :
    sig.epoch = e ∧ sameInputs sig n idx target = true ∧ sig.withTop = true ∧ sig.leaked = false := by
  unfold recomputeTop at h
  split at h
  · rename_i hc
    rw [Root.matches_top_iff] at h
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at hc
    exact ⟨h, hc.1.2, hc.1.1, hc.2⟩
  · simp at h

theorem recomputeBottom_matches_genuine {sig : Sig} {n idx target t e t' : Nat}
    (h : Root.matches (.bottom e t') (recomputeBottom sig n idx target t) = true) :
    sig.epoch = e ∧ t = t' ∧ sameInputs sig n idx target = true := by
  unfold recomputeBottom at h
  split at h
  · rename_i hc
    rw [Root.matches_bottom_iff] at h
    exact ⟨h.1.symm, h.2.symm, hc⟩
  · simp at h

theorem accept_r0 {s : State} {tx : Tx} {r0 : Root} {reg : Bool} (inv : CacheGenuine s)
    (h : verify P s tx = .accept r0 reg) :
    r0 = .bottom s.epoch (tree P tx.idx) ∧ tx.sig.epoch = s.epoch ∧
    sameInputs tx.sig (s.nonce s.epoch (lane P tx.idx)) tx.idx tx.target = true := by
  obtain ⟨hr0, hcase⟩ := accept_cases P h
  rcases hcase with ⟨_, c, hc, hm⟩ | ⟨_, _, _, hm⟩
  · have hcg := inv _ _ _ hc
    subst hcg
    rw [hr0] at hm
    obtain ⟨he, _, hs⟩ := recomputeBottom_matches_genuine hm
    refine ⟨?_, he, hs⟩
    rw [hr0]
    unfold recomputeBottom
    rw [if_pos hs, he]
  · obtain ⟨he, hs, _, _⟩ := recomputeTop_matches hm
    refine ⟨?_, he, hs⟩
    rw [hr0]
    unfold recomputeBottom
    rw [if_pos hs, he]

theorem step_cacheGenuine {s s' : State} (inv : CacheGenuine s) (st : Step P s s') : CacheGenuine s' := by
  cases st with
  | exec h =>
    rename_i tx r0 reg
    intro e t r hr
    simp only [apply] at hr
    split at hr
    · rename_i hc
      obtain ⟨_, he, ht⟩ := hc
      cases hr
      rw [(accept_r0 P inv h).1, he, ht]
    · exact inv e t r hr
  | recover => exact inv

theorem cache_genuine {s : State} (hs : Reachable P s) : CacheGenuine s := by
  induction hs with
  | init => intro e t r h; simp [initial] at h
  | step _ st ih => exact step_cacheGenuine P ih st

/-! ## Cache entries are written once -/

theorem cache_once {s s' : State} (st : Step P s s') {e t : Nat} {r : Root}
    (h : s.cache e t = some r) : s'.cache e t = some r := by
  cases st with
  | exec hv =>
    rename_i tx r0 reg
    simp only [apply]
    split
    · rename_i hc
      obtain ⟨hreg, he, ht⟩ := hc
      obtain ⟨_, hcase⟩ := accept_cases P hv
      rcases hcase with ⟨hr, _⟩ | ⟨_, hnone, _⟩
      · subst hreg; cases hr
      · subst he ht; rw [h] at hnone; cases hnone
    · exact h
  | recover => exact h

/-! ## NF / C3: what an accepted signature was made over -/

theorem accept_inputs {s : State} {tx : Tx} {r0 : Root} {reg : Bool} (hs : Reachable P s)
    (h : verify P s tx = .accept r0 reg) :
    tx.sig.epoch = s.epoch ∧ tx.sig.idx = tx.idx ∧
    tx.sig.nonce = s.nonce s.epoch (lane P tx.idx) ∧ tx.sig.target = tx.target := by
  obtain ⟨_, he, hs'⟩ := accept_r0 P (cache_genuine P hs) h
  rw [sameInputs_iff] at hs'
  exact ⟨he, hs'.1, hs'.2.1, hs'.2.2⟩

/-- A top layer only registers a subtree when it is the owner's (not leaked). -/
theorem register_not_leaked {s : State} {tx : Tx} {r0 : Root}
    (h : verify P s tx = .accept r0 true) : tx.sig.leaked = false ∧ tx.sig.withTop = true := by
  obtain ⟨_, hcase⟩ := accept_cases P h
  rcases hcase with ⟨hr, _⟩ | ⟨_, _, _, hm⟩
  · cases hr
  · obtain ⟨_, _, hw, hl⟩ := recomputeTop_matches hm
    exact ⟨hl, hw⟩

/-- Exposure hypothesis of §4.3: bottom keys can only be exposed for subtrees
whose every leaf is behind the lane's counter. Under it, the index check alone
rejects every submission at such a leaf, leaked signature or not. -/
theorem leaked_rejected {s : State} {tx : Tx}
    (habandoned : ∀ i, tree P i = tree P tx.idx → i < s.nextIdx s.epoch (lane P i)) :
    verify P s tx = .reject := by
  have := habandoned tx.idx rfl
  unfold verify
  split
  · rfl
  · simp only [this, if_true]

/-! ## C5: lane counters -/

theorem nextIdx_mono {s s' : State} (st : Step P s s') (e l : Nat) :
    s.nextIdx e l ≤ s'.nextIdx e l := by
  cases st with
  | exec h =>
    rename_i tx r0 reg
    simp only [apply]
    split
    · rename_i hc
      obtain ⟨he, hl⟩ := hc
      subst he hl
      have := (accept_index P h).2
      omega
    · exact Nat.le_refl _
  | recover => exact Nat.le_refl _

theorem steps_nextIdx_mono {s s' : State} (st : Steps P s s') (e l : Nat) :
    s.nextIdx e l ≤ s'.nextIdx e l := by
  induction st with
  | refl => exact Nat.le_refl _
  | tail _ st ih => exact Nat.le_trans ih (nextIdx_mono P st e l)

theorem accept_sets_nextIdx {s : State} {tx : Tx} {r0 : Root} {reg : Bool}
    (_ : verify P s tx = .accept r0 reg) :
    (apply P s tx r0 reg).nextIdx s.epoch (lane P tx.idx) = tx.idx + 1 := by
  simp [apply]

theorem epoch_mono {s s' : State} (st : Step P s s') : s.epoch ≤ s'.epoch := by
  cases st with
  | exec _ => exact Nat.le_refl _
  | recover => exact Nat.le_succ _

/-- No `(epoch, idx)` is accepted twice: after an acceptance at `idx`, every
later state of the same epoch rejects every submission at `idx`, whatever
signature, target or `first` flag it carries. -/
theorem no_double_accept {s s'' : State} {tx tx' : Tx} {r0 : Root} {reg : Bool}
    (h : verify P s tx = .accept r0 reg)
    (later : Steps P (apply P s tx r0 reg) s'')
    (hepoch : s''.epoch = s.epoch) (hidx : tx'.idx = tx.idx) :
    verify P s'' tx' = .reject := by
  have hmono := steps_nextIdx_mono P later s.epoch (lane P tx.idx)
  rw [accept_sets_nextIdx P h] at hmono
  unfold verify
  split
  · rfl
  · rw [if_pos]
    rw [hidx, hepoch]
    omega

/-! ## LI: lane independence -/

/-- An acceptance in one lane changes the verdict on no submission for another
lane — in either direction, since the verdicts are equal. The statement does
not even need the acceptance hypothesis: the state update of lane `l` is
invisible to every read a submission for another lane performs. -/
theorem lane_independence (s : State) (tx : Tx) (r0 : Root) (reg : Bool)
    (probe : Tx) (hl : lane P probe.idx ≠ lane P tx.idx) :
    verify P (apply P s tx r0 reg) probe = verify P s probe := by
  have ht := tree_ne_of_lane_ne P hl
  have hnext : (apply P s tx r0 reg).nextIdx s.epoch (lane P probe.idx) = s.nextIdx s.epoch (lane P probe.idx) := by
    simp only [apply]; rw [if_neg]; intro hc; exact hl hc.2
  have hnonce : (apply P s tx r0 reg).nonce s.epoch (lane P probe.idx) = s.nonce s.epoch (lane P probe.idx) := by
    simp only [apply]; rw [if_neg]; intro hc; exact hl hc.2
  have hcache : (apply P s tx r0 reg).cache s.epoch (tree P probe.idx) = s.cache s.epoch (tree P probe.idx) := by
    simp only [apply]; rw [if_neg]; intro hc; exact ht hc.2.2
  have hep : (apply P s tx r0 reg).epoch = s.epoch := rfl
  unfold verify
  simp only [hep, hnext, hnonce, hcache]

end Cchs
