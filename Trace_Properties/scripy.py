#!/usr/bin/env python3
"""Minimal compromise sets for SRP.

    python3 scripy.py                                            every property
    python3 scripy.py auth_c2s uuks_s                            just those two
    python3 scripy.py --base srp/reuse.pv --out runs-reuse       runs the reuse.pv and outputs it in runs_reuse  folder
    python3 scripy.py --base srp/fix.pv --out  runs-fix          runs the fix.pv and outputs it in runs_fix  folder


For each property we want the smallest sets of leaked/chosen values that
already break it.  Since breaking is monotone -- give the attacker more and
it stays broken -- it is enough to walk the powerset by increasing size and
skip any set above one that has already failed.

Two phases, run back to back.  R uses the reveal capabilities only; M adds
the ones where the attacker picks the value instead of the honest party
drawing it.  M is seeded with whatever R broke: M_x simulates R_x, so an
R-set is weaker than any M-set you get by swapping members, and carrying it
over prunes all of those for free.  Only sets touching a fresh M_* capability
are actually run in phase M -- the rest were settled in phase R.

Output lands in <OUT>/{R,M}/, one .pv and one .out per configuration, plus a
minimal.txt listing the results:

    ks_server R_b
    ks_server R_a R_pwd_aft
    uuks_s HOLDS
    auth_c2s EMPTY

<OUT>/summary.txt collects the final answer, one line per property.

base.pv needs the markers (* @RESTRICTIONS@ *) and (* @QUERY@ *) and the
reveal macros spelled exactly as in CAPS below.
"""

import itertools
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

BASE = "srp/base.pv"
OUT = "runs"
PROVERIF = "proverif"
JOBS = 8          # parallel proverif processes
TIMEOUT = 1800    # per run, in seconds; overrunning counts as unknown

# capability -> (text in base.pv, what to replace it with)
CAPS = {
    "R_a": ("let reveal_a(x:bitstring) = event R_a(x).",
            "let reveal_a(x:bitstring) = event R_a(x); out(att, x)."),
    "R_b": ("let reveal_b(x:bitstring) = event R_b(x).",
            "let reveal_b(x:bitstring) = event R_b(x); out(att, x)."),
    "R_pwd": ("let reveal_pwd(x:bitstring) = event R_pwd(x).",
              "let reveal_pwd(x:bitstring) = event R_pwd(x); out(att, x)."),
    "R_v": ("let reveal_v(x:bitstring) = event R_v(x).",
            "let reveal_v(x:bitstring) = event R_v(x); out(att, x)."),
    "R_pwd_aft": ("let reveal_pwd_after(x:bitstring) = event R_pwd_after(x).",
                  "let reveal_pwd_after(x:bitstring) = event R_pwd_after(x); out(att, x)."),
    "R_v_aft": ("let reveal_v_after(x:bitstring) = event R_v_after(x).",
                "let reveal_v_after(x:bitstring) = event R_v_after(x); out(att, x)."),
    "R_Kc": ("let reveal_Kc(x':bitstring, x:bitstring) = event R_Kc(x', x).",
             "let reveal_Kc(x':bitstring, x:bitstring) = event R_Kc(x', x); out(att, x)."),
    "R_Ks": ("let reveal_Ks(x':bitstring, x:bitstring) = event R_Ks(x', x).",
             "let reveal_Ks(x':bitstring, x:bitstring) = event R_Ks(x', x); out(att, x)."),

    # M_*: the honest party reads the value off the network instead of
    # drawing it.  Watch the whitespace -- these must match base.pv exactly
    # (note the space in "new b: ").
    "M_a": ("new a:bitstring;", "in(att, a:bitstring);"),
    "M_b": ("new b: bitstring;", "in(att, b: bitstring);"),
    "M_pwd": ("new pwd:bitstring;", "in(att, pwd:bitstring);"),
    "M_salt": ("new s:bitstring;", "in(att, s:bitstring);"),
}

# Macros to splice in when a capability is *off*, overriding what base.pv
# says.  Only needed where a query mentions the event; see render().
INERT = {
    "R_Kc": "let reveal_Kc(x':bitstring, x:bitstring) = 0.",
    "R_Ks": "let reveal_Ks(x':bitstring, x:bitstring) = 0.",
}

# Holding x already gets you y, so {x, y} is really just {x}, and {x} outranks
# {y} whenever y breaks something.  Transitively closed by hand.
#
# Only two kinds of implication are declared here: the same capability held
# earlier rather than later, and choosing a value rather than being told it.
# Derivable ones are left out on purpose.  R_pwd does yield R_v -- guess the
# password, recompute the verifier from the public salt -- but a database
# breach and a password guess are separate incidents with separate defences,
# so ordering them would erase one of them from the results whenever both
# break a property.  The lattice ranks incidents, not derivable knowledge.
# R_b -> R_v is absent for the stronger reason that the escalation is the
# result of the paper, not an assumption going into the search.
IMPLIES = {
    "R_pwd": ["R_pwd_aft"],
    "R_v": ["R_v_aft"],
    # choosing a value obviously tells you what it is
    "M_a": ["R_a"],
    "M_b": ["R_b"],
    "M_pwd": ["R_pwd", "R_pwd_aft"],
}

# Combinations we refuse to generate.  {R_Kc, R_Ks} used to sit here: it is
# not an implication (K_c and K_s differ when the sessions are not partnered)
# but it broke nothing, so skipping it saved about a fifth of the search.
# That evidence was collected under the old freshness restrictions, which
# stopped a revealed session from ever accepting, so it no longer counts --
# put the pair back until a clean run says otherwise.
EXCLUDE = []


# Freshness belongs in the query, not in a restriction.  A restriction is read
# over the whole trace, so "no accept together with a reveal of that key" also
# forbids *other* sessions from completing once they have been revealed -- far
# stronger than the BR condition, which exempts only the test session and its
# partner.  As a conclusion it scopes to the key under test instead.
#
# Every property gets the clause, not just secrecy: given K the attacker
# computes M1 and M2 itself, so a key reveal breaks authentication and the UKS
# properties for a reason that says nothing about SRP.  Ak and Bk occur only
# here, so ProVerif reads them existentially -- any session holding that key
# value counts as the partner, which is what we want, since under a UKS the
# partner's A need not be the tested A.
def guarded(variables, premise, conclusion=None):
    head = conclusion + " || " if conclusion else ""
    return (f"query {variables},\n"
            f"      Ak: bitstring, Bk: bitstring;\n"
            f"  {premise}\n"
            f"    ==> ({head}event(R_Kc(Ak, K)) || event(R_Ks(Bk, K))).\n")
def guarded_v(variables, premise, conclusion=None):
    head = conclusion + " || " if conclusion else ""
    return (f"query {variables},\n"
            f"      Ak: bitstring, Bk: bitstring;\n"
            f"  {premise}.\n")
def guarded_pwd(variables, premise, conclusion=None):
    head = conclusion + " || " if conclusion else ""
    return (f"query {variables},\n"
            f"      Ak: bitstring, Bk: bitstring;\n"
            f"  {premise}.\n")


SESSION = "C: name, S: name, A: bitstring, B: bitstring, K: bitstring"
TWO_SESSIONS = ("C: name, S: name, C': name, S': name, A: bitstring, "
                "B: bitstring,\n      A': bitstring, B': bitstring, K: bitstring")
Deriv = "x:bitstring"

# name -> (restrictions, query).  ProVerif answering "is false" = broken.
# Nothing needs restrictions today; the slot stays for the guessing-resistance
# biprocess, which will.
PROPERTIES = {

    "ks_server": ("", guarded(
        SESSION,
        "event(server_accept_proof(C, S, A, B, K)) && event(honest_client(C))"
        "\n    && attacker(K)")),

    "ks_client": ("", guarded(
        SESSION,
        "event(client_accept_proof(C, S, A, B, K)) && event(honest_server(S))"
        "\n    && attacker(K)")),

    "ks_mutual": ("", guarded(
        SESSION,
        "event(client_accept_proof(C, S, A, B, K))"
        "\n    && event(server_accept_proof(C, S, A, B, K)) && attacker(K)")),

    "auth_s2c": ("", guarded(
        SESSION,
        "event(client_accept_proof(C, S, A, B, K)) && event(honest_server(S))",
        "event(server_send_proof(C, S, A, B, K))")),

    "auth_c2s": ("", guarded(
        SESSION,
        "event(server_accept_proof(C, S, A, B, K)) && event(honest_client(C))",
        "event(client_send_proof(C, S, A, B, K))")),

    "buks": ("", guarded(
        TWO_SESSIONS,
        "event(client_accept_proof(C, S, A, B, K))"
        "\n    && event(server_send_proof(C', S', A', B', K))",
        "((C = C') && (S = S'))")),
        

    "uuks_c": ("", guarded(
        TWO_SESSIONS,
        "event(client_accept_proof(C, S, A, B, K))"
        "\n    && event(server_send_proof(C', S, A', B', K))",
        "(C' = C)")),

    "uuks_s": ("", guarded(
        TWO_SESSIONS,
        "event(server_accept_proof(C, S, A, B, K))"
        "\n    && event(client_send_proof(C, S', A', B', K))",
        "(S' = S)")),
    "deriv_v": ( "", guarded_v(
        Deriv,
        "event(Verifier(x, honest))"
        "\n    && attacker(x)")),
    "deriv_pwd": ( "", guarded_pwd(
        Deriv,
        "event(Password(x))"
        "\n    && attacker(x)")),

}


def gives(caps):
    """Everything the attacker ends up with, closing under IMPLIES."""
    got = set(caps)
    for c in caps:
        got.update(IMPLIES.get(c, []))
    return got


def redundant(caps):
    """True if this set is worth nothing new, or is one we chose to skip."""
    if any(pair <= caps for pair in EXCLUDE):
        return True
    return any(y in caps for c in caps for y in IMPLIES.get(c, []))


def reduce(sets):
    """Keep only the sets nothing else already covers.

    Batching by |gives| stops one candidate hiding another, but two sets can
    still hand over exactly the same thing without being equal, and those tie
    rather than dominate.  Weakest first, so the survivor is the smaller one.
    """
    kept = []
    for s in sorted(set(sets), key=lambda s: (len(gives(s)), len(s), sorted(s))):
        if not any(gives(m) <= gives(s) for m in kept):
            kept.append(s)
    return kept


def strongest(caps):
    """The whole capability set, minus anything another member implies."""
    implied = set()
    for c in caps:
        implied.update(IMPLIES.get(c, []))
    return frozenset(c for c in caps if c not in implied)


def carry(minimal):
    """What phase R hands to phase M.

    Nothing to translate.  M_x simulates R_x, so R_x is the weaker capability
    and an R-set already dominates every set you would get by swapping some of
    its members for M counterparts.  Carrying {R_b} alone prunes {M_b},
    {M_b, X}, {R_b, X} and the rest of that cone.
    """
    return set(minimal)


def anchor(snippet):
    """Regex for `snippet`, ignoring how the .pv file spaces things out.

    Two identifiers still have to be separated, but everything around the
    punctuation is free, so "new pwd:bitstring;" also finds "new pwd: bitstring;".
    """
    words = re.findall(r"[A-Za-z_][A-Za-z_0-9]*|\S", snippet)
    out = []
    for i, w in enumerate(words):
        if i:
            # two identifiers in a row must stay apart; anything involving
            # punctuation may be spaced however the file likes
            both = w[0].isalpha() or w[0] == "_"
            out.append(r"\s+" if both and words[i - 1][-1].isalnum() else r"\s*")
        out.append(r"\b%s\b" % re.escape(w) if w[0].isalpha() or w[0] == "_"
                   else re.escape(w))
    return "".join(out)


def swap(text, snippet, replacement):
    """Replace every occurrence of `snippet`; None if there were none."""
    new, n = re.subn(anchor(snippet), lambda m: replacement, text)
    return new if n else None


def complain(cap, off, text):
    """Anchor missing: show the lines it was probably meant to match."""
    word = re.sub(r"\W.*", "", off.split()[1])          # pwd, reveal_a, ...
    hits = [f"  {i}: {l.rstrip()}" for i, l in enumerate(text.splitlines(), 1)
            if word in l]
    msg = [f"{cap}: cannot find this in {BASE}", f"  {off}"]
    if hits:
        msg += [f"lines mentioning {word!r}:"] + hits
        msg += ["fix the left-hand string in CAPS to match one of them "
                "exactly, whitespace included"]
    else:
        msg += [f"nothing in the file mentions {word!r}; drop {cap} from CAPS "
                "for this model"]
    sys.exit("\n".join(msg))


def render(base, on, restrictions, query):
    text = base
    for c in on:
        off, upon = CAPS[c]
        text = swap(text, off, upon) or complain(c, off, text)
    # The K reveals are the only ones a query looks at, so when they are off
    # their event has to go too -- base.pv still announces R_Kc even with the
    # output removed, and an announced reveal that never happened would excuse
    # a real attack under the freshness conclusion.
    for c, inert in INERT.items():
        if c not in on:
            text = swap(text, CAPS[c][0], inert) or complain(c, CAPS[c][0], text)
    for mark, val in [("(* @RESTRICTIONS@ *)", restrictions),
                      ("(* @QUERY@ *)", query)]:
        if mark not in text:
            sys.exit(f"marker {mark} missing from {BASE}")
        text = text.replace(mark, val)
    return text


def run(base, name, on, restrictions, query, outdir):
    """Generate one .pv, call ProVerif, return broken/holds/unknown."""
    tag = "-".join(sorted(on)) if on else "none"
    started = time.time()
    path = os.path.join(outdir, f"{name}__{tag}.pv")
    with open(path, "w") as f:
        f.write(render(base, on, restrictions, query))
    try:
        p = subprocess.run([PROVERIF, path], capture_output=True,
                           text=True, timeout=TIMEOUT)
        out = p.stdout + p.stderr
    except FileNotFoundError:
        sys.exit(f"{PROVERIF} not found; edit PROVERIF at the top of this file")
    except subprocess.TimeoutExpired:
        out = f"timed out after {TIMEOUT} s"
    with open(path[:-3] + ".out", "w") as f:
        f.write(out)

    if re.search(r"^RESULT .* is false\.", out, re.M):
        verdict = "broken"
    elif re.search(r"^RESULT .* is true\.", out, re.M):
        verdict = "holds"
    else:
        verdict = "unknown"
    print("  %-34s %-8s %7.1fs" % (tag, verdict, time.time() - started),
          flush=True)
    return verdict


def search(base, name, restrictions, query, caps, outdir, known=(), fresh=None):
    """Find the minimal sets among `caps` that break this property.

    known -- sets already known broken, typically carried from phase R.  They
    are not re-run, but they do prune, and smaller sets are still explored
    because M can break earlier than R did.
    fresh -- if given, only sets touching one of these capabilities are run;
    the others were decided in an earlier phase.
    """
    caps = sorted(caps)
    started = time.time()

    # If even the strongest set holds there is nothing below it to find, and
    # this one run replaces the whole sweep.
    print("  (probing the strongest set first)", flush=True)
    if run(base, name, strongest(caps), restrictions, query, outdir) != "broken":
        if known:
            print(f"  WARNING: the strongest set holds, yet {len(known)} set(s) "
                  "carried from the previous phase broke this property. "
                  "Check the model.", flush=True)
        return list(known), [], 1, {s: 0.0 for s in known}

    # Seeding with the carried sets is what stops e.g. {M_a, R_b} being
    # reported as minimal when {R_b} on its own already breaks the property.
    minimal = list(known)
    found_at = {s: 0.0 for s in known}
    unknown = []
    runs = 1                       # counting the probe above

    # Batch by how much a set *gives*, not by how many members it has.  Two
    # sets of the same cardinality can still dominate one another -- {R_a,
    # R_pwd} hands over everything {R_a, R_pwd_aft} does and more -- and a
    # batch runs in parallel, so anything inside it is invisible to the
    # pruning.  Ordering by |gives| fixes that: domination is strict inclusion,
    # so a dominating set always sits in an earlier batch.
    candidates = []
    for size in range(len(caps) + 1):
        for combo in itertools.combinations(caps, size):
            s = frozenset(combo)
            if fresh is not None and not (s & fresh):
                continue           # nothing new in it; settled last phase
            if not redundant(s):
                candidates.append(s)
    candidates.sort(key=lambda s: (len(gives(s)), len(s), sorted(s)))

    for _, batch in itertools.groupby(candidates, lambda s: len(gives(s))):
        todo = [s for s in batch
                if not any(gives(m) <= gives(s) for m in minimal)]
        if not todo:
            continue
        with ThreadPoolExecutor(JOBS) as pool:
            verdicts = list(pool.map(
                lambda s: run(base, name, s, restrictions, query, outdir), todo))
        runs += len(todo)

        now = time.time() - started
        for s, verdict in zip(todo, verdicts):
            if verdict == "broken":
                minimal.append(s)
                found_at[s] = now
            elif verdict == "unknown":
                unknown.append(s)

    return reduce(minimal), unknown, runs, found_at


def read_minimal(path):
    """Parse a minimal.txt back into {property: [set, ...]}; HOLDS gives []."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            bits = line.split()
            if len(bits) < 2:
                continue
            out.setdefault(bits[0], [])
            if bits[1] == "EMPTY":
                out[bits[0]].append(frozenset())
            elif bits[1] != "HOLDS":
                out[bits[0]].append(frozenset(bits[1:]))
    return out


def fmt(minimal):
    if not minimal:
        return "HOLDS"
    if frozenset() in minimal:
        return "BROKEN WITH NO COMPROMISE"
    ordered = sorted(minimal, key=lambda s: (len(s), sorted(s)))
    return " OR ".join("{%s}" % ", ".join(sorted(s)) for s in ordered)


def report(name, minimal, unknown, runs, found_at, elapsed, fh):
    print("-> " + name)
    if not minimal:
        print("  HOLDS -- no compromise set breaks it")
    elif frozenset() in minimal:
        print("  BROKEN WITH NO COMPROMISE -- the empty set suffices")
    else:
        for s in sorted(minimal, key=lambda s: found_at.get(s, 0.0)):
            print("  %-38s found at %8.1fs"
                  % ("{%s}" % ", ".join(sorted(s)), found_at.get(s, 0.0)))
    if unknown:
        print("  UNKNOWN (not used for pruning): "
              + " ".join("{%s}" % ", ".join(sorted(s)) for s in unknown))
    print("  %d runs, %.1fs" % (runs, elapsed))

    if not minimal:
        fh.write(f"{name} HOLDS\n")
    for s in minimal:
        fh.write("%s %s\n" % (name, " ".join(sorted(s)) if s else "EMPTY"))
    fh.flush()


def main():
    global BASE, OUT
    args = sys.argv[1:]
    for flag, var in [("--base", "BASE"), ("--out", "OUT")]:
        if flag in args:
            i = args.index(flag)
            globals()[var] = args[i + 1]
            del args[i:i + 2]

    base = open(BASE).read()
    r_caps = [c for c in CAPS if not c.startswith("M_")]
    m_caps = [c for c in CAPS if c.startswith("M_")]

    phases = [("R", r_caps)]
    if m_caps:
        phases.append(("M", sorted(CAPS)))

    todo = args or list(PROPERTIES)
    for bad in [n for n in todo if n not in PROPERTIES]:
        sys.exit(f"unknown property {bad!r}; known: {', '.join(PROPERTIES)}")

    # Clear out only the properties we are redoing, so running one of them
    # does not throw away last night's results for the other seven.
    for tag, _ in phases:
        d = os.path.join(OUT, tag)
        if not os.path.isdir(d):
            os.makedirs(d)
        path = os.path.join(d, "minimal.txt")
        old = open(path).readlines() if os.path.exists(path) else []
        with open(path, "w") as f:
            f.writelines(l for l in old
                         if l.split() and l.split()[0] not in todo)

    grand = time.time()
    for name in todo:
        restrictions, query = PROPERTIES[name]
        known = set()
        for tag, caps in phases:
            outdir = os.path.join(OUT, tag)
            carried = f", {len(known)} carried from R" if known else ""
            print(f"\n[{name}] phase {tag}  ({len(caps)} capabilities{carried})",
                  flush=True)
            t0 = time.time()
            result = search(base, name, restrictions, query, caps, outdir, known,
                            fresh=set(caps) - set(r_caps) if tag != "R" else None)
            with open(os.path.join(outdir, "minimal.txt"), "a") as fh:
                report(name, *result, time.time() - t0, fh)
            known = carry(result[0])          # seeds the next phase

    # Phase M's answer already contains the carried R-sets, so the last phase
    # to run is the combined result -- printing both would just repeat it.
    last = phases[-1][0]
    results = read_minimal(os.path.join(OUT, last, "minimal.txt"))
    width = max(len(n) for n in PROPERTIES)
    lines = [f"minimal compromise sets  ({BASE})", ""]
    for name in PROPERTIES:
        if name in results:
            lines.append("%-*s  %s" % (width, name, fmt(results[name])))
    lines += ["", "total wall time %.1fs" % (time.time() - grand)]

    text = "\n".join(lines)
    with open(os.path.join(OUT, "summary.txt"), "w") as f:
        f.write(text + "\n")
    print("\n" + text)
    print(f"\nwritten to {OUT}/summary.txt")


if __name__ == "__main__":
    main()
