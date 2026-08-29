# Groebner-basis forgery experiment on exported CCTS instances.
#
# The attacker sees the public tensor psi and a sphere target y, and must find
# (u, v, mu != 0) with f_psi(u, v) = mu * y -- the bilinear system underlying
# Narayanan's Assumption 2 (ePrint 2025/624), posed as his open question on
# algebraic cryptanalysis (p. 34). We measure Groebner cost on small instances
# and compare tensor_reference vs chord_structured vs chord_labeled Lambda.
#
# Normalization: u_0 = 1 (affine patch; retried with u_1 = 1 if the ideal is
# trivial) and Rabinowitsch t*mu - 1 = 0 to force mu != 0.
#
# usage: sage analysis/groebner_attack.sage instance1.txt [instance2.txt ...]
#        appends rows to results/groebner_prelim.csv
import sys, time, csv, os

MODE_NAMES = {0: "tensor_reference", 1: "chord_tensor",
              2: "chord_structured", 3: "chord_labeled"}

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

def attack(path):
    q, k, mode, psi, y = load_instance(path)
    n1, n23 = 2 * k + 1, k + 1
    F = GF(q)
    for patch in range(n23):  # affine patch u_patch = 1
        names = (["u%d" % j for j in range(n23)] +
                 ["v%d" % l for l in range(n23)] + ["mu", "t"])
        R = PolynomialRing(F, names, order="degrevlex")
        g = R.gens()
        u = list(g[:n23]); v = list(g[n23:2 * n23]); mu, t = g[-2], g[-1]
        u[patch] = R(1)
        eqs = []
        for a in range(n1):
            e = -mu * y[a]
            for j in range(n23):
                for l in range(n23):
                    c = psi[a][j][l]
                    if c:
                        e += c * u[j] * v[l]
            eqs.append(e)
        eqs.append(mu * t - 1)
        I = R.ideal(eqs)
        t0 = time.time()
        gb = I.groebner_basis()
        wall = time.time() - t0
        if 1 in gb:
            continue  # no forgery in this patch; try the next
        dim = I.dimension()
        deg = I.vector_space_dimension() if dim == 0 else -1
        maxdeg = max(p.degree() for p in gb)
        npts = len(I.variety()) if dim == 0 and deg <= 4096 else -1
        return dict(mode=MODE_NAMES.get(mode, str(mode)), k=k, q=q, patch=patch,
                    gb_seconds=round(wall, 3), ideal_dim=dim, ideal_degree=deg,
                    gb_max_degree=maxdeg, solutions=npts, gb_size=len(gb))
    return dict(mode=MODE_NAMES.get(mode, str(mode)), k=k, q=q, patch=-1,
                gb_seconds=-1, ideal_dim=-1, ideal_degree=-1,
                gb_max_degree=-1, solutions=0, gb_size=0)

def main():
    rows = [attack(p) for p in sys.argv[1:]]
    out = "results/groebner_prelim.csv"
    write_header = not os.path.exists(out)
    with open(out, "a") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if write_header:
            w.writeheader()
        for r in rows:
            w.writerow(r)
            print(r)

main()
