package lib.org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import lib.org.bouncycastle.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
