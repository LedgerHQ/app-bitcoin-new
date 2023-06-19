"""
Miniscript satisfaction.

This module contains logic for "signing for" a Miniscript (constructing a valid witness
that meets the conditions set by the Script) and analysis of such satisfaction(s) (eg the
maximum cost in a given resource).
This is currently focused on non-malleable satisfaction. We take shortcuts to not care about
non-canonical (dis)satisfactions.
"""


def add_optional(a, b):
    """Add two numbers that may be None together."""
    if a is None or b is None:
        return None
    return a + b


def max_optional(a, b):
    """Return the maximum of two numbers that may be None."""
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


class SatisfactionMaterial:
    """Data that may be needed in order to satisfy a Minsicript fragment."""

    def __init__(
        self, preimages={}, signatures={}, max_sequence=2 ** 32, max_lock_time=2 ** 32
    ):
        """
        :param preimages: Mapping from a hash (as bytes), to its 32-bytes preimage.
        :param signatures: Mapping from a public key (as bytes), to a signature for this key.
        :param max_sequence: The maximum relative timelock possible (coin age).
        :param max_lock_time: The maximum absolute timelock possible (block height).
        """
        self.preimages = preimages
        self.signatures = signatures
        self.max_sequence = max_sequence
        self.max_lock_time = max_lock_time

    def clear(self):
        self.preimages.clear()
        self.signatures.clear()
        self.max_sequence = 0
        self.max_lock_time = 0

    def __repr__(self):
        return (
            f"SatisfactionMaterial(preimages: {self.preimages}, signatures: "
            f"{self.signatures}, max_sequence: {self.max_sequence}, max_lock_time: "
            f"{self.max_lock_time}"
        )


class Satisfaction:
    """All information about a satisfaction."""

    def __init__(self, witness, has_sig=False):
        assert isinstance(witness, list) or witness is None
        self.witness = witness
        self.has_sig = has_sig
        # TODO: we probably need to take into account non-canon sats, as the algorithm
        # described on the website mandates it:
        # > Iterate over all the valid satisfactions/dissatisfactions in the table above
        # > (including the non-canonical ones),

    def __add__(self, other):
        """Concatenate two satisfactions together."""
        witness = add_optional(self.witness, other.witness)
        has_sig = self.has_sig or other.has_sig
        return Satisfaction(witness, has_sig)

    def __or__(self, other):
        """Choose between two (dis)satisfactions."""
        assert isinstance(other, Satisfaction)

        # If one isn't available, return the other one.
        if self.witness is None:
            return other
        if other.witness is None:
            return self

        # > If among all valid solutions (including DONTUSE ones) more than one does not
        # > have the HASSIG marker, return DONTUSE, as this is malleable because of reason
        # > 1.
        # TODO
        # if not (self.has_sig or other.has_sig):
        # return Satisfaction.unavailable()

        # > If instead exactly one does not have the HASSIG marker, return that solution
        # > because of reason 2.
        if self.has_sig and not other.has_sig:
            return other
        if not self.has_sig and other.has_sig:
            return self

        # > Otherwise, all not-DONTUSE options are valid, so return the smallest one (in
        # > terms of witness size).
        if self.size() > other.size():
            return other

        # > If all valid solutions have the HASSIG marker, but all of them are DONTUSE, return DONTUSE-HASSIG.
        # TODO

        return self

    def unavailable():
        return Satisfaction(witness=None)

    def is_unavailable(self):
        return self.witness is None

    def size(self):
        return len(self.witness) + sum(len(elem) for elem in self.witness)

    def from_concat(sat_material, sub_a, sub_b, disjunction=False):
        """Get the satisfaction for a Miniscript whose Script corresponds to a
        concatenation of two subscripts A and B.

        :param sub_a: The sub-fragment A.
        :param sub_b: The sub-fragment B.
        :param disjunction: Whether this fragment has an 'or()' semantic.
        """
        if disjunction:
            return (sub_b.dissatisfaction() + sub_a.satisfaction(sat_material)) | (
                sub_b.satisfaction(sat_material) + sub_a.dissatisfaction()
            )
        return sub_b.satisfaction(sat_material) + sub_a.satisfaction(sat_material)

    def from_or_uneven(sat_material, sub_a, sub_b):
        """Get the satisfaction for a Miniscript which unconditionally executes a first
        sub A and only executes B if A was dissatisfied.

        :param sub_a: The sub-fragment A.
        :param sub_b: The sub-fragment B.
        """
        return sub_a.satisfaction(sat_material) | (
            sub_b.satisfaction(sat_material) + sub_a.dissatisfaction()
        )

    def from_thresh(sat_material, k, subs):
        """Get the satisfaction for a Miniscript which satisfies k of the given subs,
        and dissatisfies all the others.

        :param sat_material: The material to satisfy the challenges.
        :param k: The number of subs that need to be satisfied.
        :param subs: The list of all subs of the threshold.
        """
        # Pick the k sub-fragments to satisfy, prefering (in order):
        # 1. Fragments that don't require a signature to be satisfied
        # 2. Fragments whose satisfaction's size is smaller
        # Record the unavailable (in either way) ones as we go.
        arbitrage, unsatisfiable, undissatisfiable = [], [], []
        for sub in subs:
            sat, dissat = sub.satisfaction(sat_material), sub.dissatisfaction()
            if sat.witness is None:
                unsatisfiable.append(sub)
            elif dissat.witness is None:
                undissatisfiable.append(sub)
            else:
                arbitrage.append(
                    (int(sat.has_sig), len(sat.witness) - len(dissat.witness), sub)
                )

        # If not enough (dis)satisfactions are available, fail.
        if len(unsatisfiable) > len(subs) - k or len(undissatisfiable) > k:
            return Satisfaction.unavailable()

        # Otherwise, satisfy the k most optimal ones.
        arbitrage = sorted(arbitrage, key=lambda x: x[:2])
        optimal_sat = undissatisfiable + [a[2] for a in arbitrage] + unsatisfiable
        to_satisfy = set(optimal_sat[:k])
        return sum(
            [
                sub.satisfaction(sat_material)
                if sub in to_satisfy
                else sub.dissatisfaction()
                for sub in subs[::-1]
            ],
            start=Satisfaction(witness=[]),
        )


class ExecutionInfo:
    """Information about the execution of a Miniscript."""

    def __init__(self, stat_ops, _dyn_ops, sat_size, dissat_size):
        # The *maximum* number of *always* executed non-PUSH Script OPs to satisfy this
        # Miniscript fragment non-malleably.
        self._static_ops_count = stat_ops
        # The maximum possible number of counted-as-executed-by-interpreter OPs if this
        # fragment is executed.
        # It is only >0 for an executed multi() branch. That is, for a CHECKMULTISIG that
        # is not part of an unexecuted branch of an IF .. ENDIF.
        self._dyn_ops_count = _dyn_ops
        # The *maximum* number of stack elements to satisfy this Miniscript fragment
        # non-malleably.
        self.sat_elems = sat_size
        # The *maximum* number of stack elements to dissatisfy this Miniscript fragment
        # non-malleably.
        self.dissat_elems = dissat_size

    @property
    def ops_count(self):
        """
        The worst-case number of OPs that would be considered executed by the Script
        interpreter.
        Note it is considered alone and not necessarily coherent with the other maxima.
        """
        return self._static_ops_count + self._dyn_ops_count

    def is_dissatisfiable(self):
        """Whether the Miniscript is *non-malleably* dissatisfiable."""
        return self.dissat_elems is not None

    def set_undissatisfiable(self):
        """Set the Miniscript as being impossible to dissatisfy."""
        self.dissat_elems = None

    def from_concat(sub_a, sub_b, ops_count=0, disjunction=False):
        """Compute the execution info from a Miniscript whose Script corresponds to
        a concatenation of two subscript A and B.

        :param sub_a: The execution information of the subscript A.
        :param sub_b: The execution information of the subscript B.
        :param ops_count: The added number of static OPs added on top.
        :param disjunction: Whether this fragment has an 'or()' semantic.
        """
        # Number of static OPs is simple, they are all executed.
        static_ops = sub_a._static_ops_count + sub_b._static_ops_count + ops_count
        # Same for the dynamic ones, there is no conditional branch here.
        dyn_ops = sub_a._dyn_ops_count + sub_b._dyn_ops_count
        # If this is an 'or', only one needs to be satisfied. Pick the most expensive
        # satisfaction/dissatisfaction pair.
        # If not, both need to be anyways.
        if disjunction:
            first = add_optional(sub_a.sat_elems, sub_b.dissat_elems)
            second = add_optional(sub_a.dissat_elems, sub_b.sat_elems)
            sat_elems = max_optional(first, second)
        else:
            sat_elems = add_optional(sub_a.sat_elems, sub_b.sat_elems)
        # In any case dissatisfying the fragment requires dissatisfying both concatenated
        # subs.
        dissat_elems = add_optional(sub_a.dissat_elems, sub_b.dissat_elems)

        return ExecutionInfo(static_ops, dyn_ops, sat_elems, dissat_elems)

    def from_or_uneven(sub_a, sub_b, ops_count=0):
        """Compute the execution info from a Miniscript which always executes A and only
        executes B depending on the outcome of A's execution.

        :param sub_a: The execution information of the subscript A.
        :param sub_b: The execution information of the subscript B.
        :param ops_count: The added number of static OPs added on top.
        """
        # Number of static OPs is simple, they are all executed.
        static_ops = sub_a._static_ops_count + sub_b._static_ops_count + ops_count
        # If the first sub is non-malleably dissatisfiable, the worst case is executing
        # both. Otherwise it is necessarily satisfying only the first one.
        if sub_a.is_dissatisfiable():
            dyn_ops = sub_a._dyn_ops_count + sub_b._dyn_ops_count
        else:
            dyn_ops = sub_a._dyn_ops_count
        # Either we satisfy A, or satisfy B (and thereby dissatisfy A). Pick the most
        # expensive.
        first = sub_a.sat_elems
        second = add_optional(sub_a.dissat_elems, sub_b.sat_elems)
        sat_elems = max_optional(first, second)
        # We only take canonical dissatisfactions into account.
        dissat_elems = add_optional(sub_a.dissat_elems, sub_b.dissat_elems)

        return ExecutionInfo(static_ops, dyn_ops, sat_elems, dissat_elems)

    def from_or_even(sub_a, sub_b, ops_count):
        """Compute the execution info from a Miniscript which executes either A or B, but
        never both.

        :param sub_a: The execution information of the subscript A.
        :param sub_b: The execution information of the subscript B.
        :param ops_count: The added number of static OPs added on top.
        """
        # Number of static OPs is simple, they are all executed.
        static_ops = sub_a._static_ops_count + sub_b._static_ops_count + ops_count
        # Only one of the branch is executed, pick the most expensive one.
        dyn_ops = max(sub_a._dyn_ops_count, sub_b._dyn_ops_count)
        # Same. Also, we add a stack element used to tell which branch to take.
        sat_elems = add_optional(max_optional(sub_a.sat_elems, sub_b.sat_elems), 1)
        # Same here.
        dissat_elems = add_optional(
            max_optional(sub_a.dissat_elems, sub_b.dissat_elems), 1
        )

        return ExecutionInfo(static_ops, dyn_ops, sat_elems, dissat_elems)

    def from_andor_uneven(sub_a, sub_b, sub_c, ops_count=0):
        """Compute the execution info from a Miniscript which always executes A, and then
        executes B if A returned True else executes C. Semantic: or(and(A,B), C).

        :param sub_a: The execution information of the subscript A.
        :param sub_b: The execution information of the subscript B.
        :param sub_b: The execution information of the subscript C.
        :param ops_count: The added number of static OPs added on top.
        """
        # Number of static OPs is simple, they are all executed.
        static_ops = (
            sum(sub._static_ops_count for sub in [sub_a, sub_b, sub_c]) + ops_count
        )
        # If the first sub is non-malleably dissatisfiable, the worst case is executing
        # it and the most expensive between B and C.
        # If it isn't the worst case is then necessarily to execute A and B.
        if sub_a.is_dissatisfiable():
            dyn_ops = sub_a._dyn_ops_count + max(
                sub_b._dyn_ops_count, sub_c._dyn_ops_count
            )
        else:
            # If the first isn't non-malleably dissatisfiable, the worst case is
            # satisfying it (and necessarily satisfying the second one too)
            dyn_ops = sub_a._dyn_ops_count + sub_b._dyn_ops_count
        # Same for the number of stack elements (implicit from None here).
        first = add_optional(sub_a.sat_elems, sub_b.sat_elems)
        second = add_optional(sub_a.dissat_elems, sub_c.sat_elems)
        sat_elems = max_optional(first, second)
        # The only canonical dissatisfaction is dissatisfying A and C.
        dissat_elems = add_optional(sub_a.dissat_elems, sub_c.dissat_elems)

        return ExecutionInfo(static_ops, dyn_ops, sat_elems, dissat_elems)

    # TODO: i think it'd be possible to not have this be special-cased to 'thresh()'
    def from_thresh(k, subs):
        """Compute the execution info from a Miniscript 'thresh()' fragment. Specialized
        to this specifc fragment for now.

        :param k: The actual threshold of the 'thresh()' fragment.
        :param subs: All the possible sub scripts.
        """
        # All the OPs from the subs + n-1 * OP_ADD + 1 * OP_EQUAL
        static_ops = sum(sub._static_ops_count for sub in subs) + len(subs)
        # dyn_ops = sum(sorted([sub._dyn_ops_count for sub in subs], reverse=True)[:k])
        # All subs are executed, there is no OP_IF branch.
        dyn_ops = sum([sub._dyn_ops_count for sub in subs])

        # In order to estimate the worst case we simulate to satisfy the k subs whose
        # sat/dissat ratio is the largest, and dissatisfy the others.
        # We do so by iterating through all the subs, recording their sat-dissat "score"
        # and those that either cannot be satisfied or dissatisfied.
        arbitrage, unsatisfiable, undissatisfiable = [], [], []
        for sub in subs:
            if sub.sat_elems is None:
                unsatisfiable.append(sub)
            elif sub.dissat_elems is None:
                undissatisfiable.append(sub)
            else:
                arbitrage.append((sub.sat_elems - sub.dissat_elems, sub))
        # Of course, if too many can't be (dis)satisfied, we have a problem.
        # Otherwise, simulate satisfying first the subs that must be (no dissatisfaction)
        # then the most expensive ones, and then dissatisfy all the others.
        if len(unsatisfiable) > len(subs) - k or len(undissatisfiable) > k:
            sat_elems = None
        else:
            arbitrage = sorted(arbitrage, key=lambda x: x[0], reverse=True)
            worst_sat = undissatisfiable + [a[1] for a in arbitrage] + unsatisfiable
            sat_elems = sum(
                [sub.sat_elems for sub in worst_sat[:k]]
                + [sub.dissat_elems for sub in worst_sat[k:]]
            )
        if len(undissatisfiable) > 0:
            dissat_elems = None
        else:
            dissat_elems = sum([sub.dissat_elems for sub in subs])

        return ExecutionInfo(static_ops, dyn_ops, sat_elems, dissat_elems)

    def from_wrap(sub, ops_count, dyn=0, sat=0, dissat=0):
        """Compute the execution info from a Miniscript which always executes a subscript
        but adds some logic around.

        :param sub: The execution information of the single subscript.
        :param ops_count: The added number of static OPs added on top.
        :param dyn: The added number of dynamic OPs added on top.
        :param sat: The added number of satisfaction stack elements added on top.
        :param dissat: The added number of dissatisfcation stack elements added on top.
        """
        return ExecutionInfo(
            sub._static_ops_count + ops_count,
            sub._dyn_ops_count + dyn,
            add_optional(sub.sat_elems, sat),
            add_optional(sub.dissat_elems, dissat),
        )

    def from_wrap_dissat(sub, ops_count, dyn=0, sat=0, dissat=0):
        """Compute the execution info from a Miniscript which always executes a subscript
        but adds some logic around.

        :param sub: The execution information of the single subscript.
        :param ops_count: The added number of static OPs added on top.
        :param dyn: The added number of dynamic OPs added on top.
        :param sat: The added number of satisfaction stack elements added on top.
        :param dissat: The added number of dissatisfcation stack elements added on top.
        """
        return ExecutionInfo(
            sub._static_ops_count + ops_count,
            sub._dyn_ops_count + dyn,
            add_optional(sub.sat_elems, sat),
            dissat,
        )
