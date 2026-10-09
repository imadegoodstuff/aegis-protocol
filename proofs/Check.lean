import Cchs

/-!
Prints the axioms each main theorem depends on. CI fails if anything beyond
Lean's three standard axioms (`propext`, `Classical.choice`, `Quot.sound`)
shows up — in particular `sorryAx`.

    lake env lean Check.lean
-/

#print axioms Cchs.cache_genuine
#print axioms Cchs.cache_once
#print axioms Cchs.accept_inputs
#print axioms Cchs.register_not_leaked
#print axioms Cchs.leaked_rejected
#print axioms Cchs.nextIdx_mono
#print axioms Cchs.no_double_accept
#print axioms Cchs.lane_independence
#print axioms Cchs.Client.one_message
