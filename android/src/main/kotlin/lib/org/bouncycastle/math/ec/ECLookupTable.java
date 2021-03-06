package lib.org.bouncycastle.math.ec;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
}
