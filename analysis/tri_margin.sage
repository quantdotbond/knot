# TRI margin calibration (TRI design notes Sec. 3.4).
#
# The TRI forger sees only the restriction psi|_I to a support I of size
# t = k+1+m and must find (u, v, mu != 0) with f_psi(u, v)|_I = mu * y|_I.
# Fixing u makes this linear (t equations, k+1 unknowns): solvable in
# polynomial time at m <= 0, cost ~ q^m naively for m >= 1. Structured
# Groebner attacks on the bilinear system do better than naive linearization,
# so the margin m must be calibrated experimentally, not from the counting
# argument alone. This script measures Groebner cost of the *restricted*
# forgery system as a function of m on exported instances.
#
# Instances are the dense exports of tests/export_instance (the full psi and a
# full sphere target y); restricting their rows to a pseudorandom support is
# exactly the view a tri_chord public key with that support would publish
# (TRI design notes Sec. 3.5: the factored form is information-equivalent to the
# dense slices), and y|_I is a legitimate restricted target of the weight it
# happens to have on I.
#
# usage: sage analysis/tri_margin.sage instance.txt [m_min [m_max]]
#        appends rows to results/tri_margin.csv
import sys, time, csv, os

MODE_NAMES = {0: "tensor_reference", 1: "chord_tensor",
              2: "chord_structured", 3: "chord_labeled", 4: "tri_chord"}

def load_instance(path):
    with open(path) as f:
        q, k, mode = [int(x) for x in f.readline().split()]
        flat = [int(x) for x in f.readline().split()]
        y = [int(x) for x in f.readline().split()]
    n1, n23 = 2 * k + 1, k + 1
    assert len(flat) == n1 * n23 * n23 and len(y) == n1
    psi = [[[flat[(i * n23 + j) * n23 + l] for l in range(n23)]
            for j in range(n23)] for i in range(n1)]
    return q, k, mode, psi, y

def restricted_attack(q, k, mode, psi, y, m):
    """Groebner cost of the forgery system restricted to t = k+1+m rows."""
    n1, n23 = 2 * k + 1, k + 1
    t = k + 1 + m
    assert t <= n1
    # Pseudorandom support, reproducible per (k, q, m).
    set_random_seed(1000003 * k + 1009 * m + q)
    I = sorted(sample(range(n1), t))
    w_on_I = sum(1 for i in I if y[i] != 0)
    F = GF(q)
    for patch in range(n23):  # affine patch u_patch = 1
        names = (["u%d" % j for j in range(n23)] +
                 ["v%d" % l for l in range(n23)] + ["mu", "tt"])
        R = PolynomialRing(F, names, order="degrevlex")
        g = R.gens()
        u = list(g[:n23]); v = list(g[n23:2 * n23]); mu, tt = g[-2], g[-1]
        u[patch] = R(1)
        eqs = []
        for a in I:
            e = -mu * y[a]
            for j in range(n23):
                for l in range(n23):
                    c = psi[a][j][l]
                    if c:
                        e += c * u[j] * v[l]
            eqs.append(e)
        eqs.append(mu * tt - 1)  # Rabinowitsch: mu != 0
        Ideal = R.ideal(eqs)
        t0 = time.time()
        gb = Ideal.groebner_basis()
        wall = time.time() - t0
        if 1 in gb:
            continue  # no forgery in this patch; try the next
        dim = Ideal.dimension()
        deg = Ideal.vector_space_dimension() if dim == 0 else -1
        maxdeg = max(p.degree() for p in gb)
        npts = len(Ideal.variety()) if dim == 0 and deg <= 4096 else -1
        return dict(mode=MODE_NAMES.get(mode, str(mode)), k=k, q=q, m=m, t=t,
                    w_on_support=w_on_I, patch=patch, gb_seconds=round(wall, 3),
                    ideal_dim=dim, ideal_degree=deg, gb_max_degree=maxdeg,
                    solutions=npts, gb_size=len(gb))
    return dict(mode=MODE_NAMES.get(mode, str(mode)), k=k, q=q, m=m, t=t,
                w_on_support=w_on_I, patch=-1, gb_seconds=-1, ideal_dim=-1,
                ideal_degree=-1, gb_max_degree=-1, solutions=0, gb_size=0)

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__ or "usage: sage analysis/tri_margin.sage instance.txt [m_min [m_max]]")
        sys.exit(2)
    path = args[0]
    q, k, mode, psi, y = load_instance(path)
    m_min = int(args[1]) if len(args) > 1 else 0
    m_max = int(args[2]) if len(args) > 2 else k  # m = k is the full tensor
    out = "results/tri_margin.csv"
    # Append each row as soon as it is computed: larger k can time out
    # mid-sweep and the completed margins must survive.
    for m in range(m_min, m_max + 1):
        if k + 1 + m > 2 * k + 1:
            break
        r = restricted_attack(q, k, mode, psi, y, m)
        print(r)
        write_header = not os.path.exists(out)
        with open(out, "a") as f:
            w = csv.DictWriter(f, fieldnames=list(r.keys()))
            if write_header:
                w.writeheader()
            w.writerow(r)

main()
