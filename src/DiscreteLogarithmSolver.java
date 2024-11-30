import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class DiscreteLogarithmSolver {
    // Returns minimum x for which a^x % m = b % m.
    protected BigInteger solve(BigInteger a, BigInteger b, BigInteger p) {
        a = a.mod(p);
        b = b.mod(p);
        BigInteger k = BigInteger.ONE;
        int add = 0;
        BigInteger g;

        // Handle the case where gcd(a, p) > 1
        while (!(g = a.gcd(p)).equals(BigInteger.ONE)) {
            if (b.equals(k)) {
                return BigInteger.valueOf(add);
            }
            if (!b.mod(g).equals(BigInteger.ZERO)) {
                return BigInteger.valueOf(-1);
            }
            b = b.divide(g);
            p = p.divide(g);
            add++;
            k = k.multiply(a).divide(g).mod(p);
        }

        // Baby-step giant-step algorithm
        BigInteger n = sqrt(p).add(BigInteger.ONE);
        BigInteger an = BigInteger.ONE;
        for (BigInteger i = BigInteger.ZERO; i.compareTo(n) < 0; i = i.add(BigInteger.ONE)) {
            an = an.multiply(a).mod(p);
        }

        // Store values in a hash map for the baby steps
        Map<BigInteger, BigInteger> vals = new HashMap<>();
        for (BigInteger q = BigInteger.ZERO, cur = b; q.compareTo(n) <= 0; q = q.add(BigInteger.ONE)) {
            vals.put(cur, q);
            cur = cur.multiply(a).mod(p);
        }

        // Compute the giant steps and check for matches
        for (BigInteger j = BigInteger.ONE, cur = k; j.compareTo(n) <= 0; j = j.add(BigInteger.ONE)) {
            cur = cur.multiply(an).mod(p);
            if (vals.containsKey(cur)) {
                return n.multiply(j).subtract(vals.get(cur)).add(BigInteger.valueOf(add));
            }
        }

        return BigInteger.ZERO;
    }

    // Helper function to calculate gcd
    private static BigInteger gcd(BigInteger a, BigInteger b) {
        return a.gcd(b);
    }

    // Helper function to compute the square root of a BigInteger
    private static BigInteger sqrt(BigInteger x) {
        BigInteger r = BigInteger.ZERO;
        BigInteger bit = BigInteger.ONE.shiftLeft(x.bitLength() / 2);

        while (bit.compareTo(BigInteger.ZERO) > 0) {
            BigInteger temp = r.add(bit);
            if (temp.multiply(temp).compareTo(x) <= 0) {
                r = temp;
            }
            bit = bit.shiftRight(1);
        }

        return r;
    }
}
