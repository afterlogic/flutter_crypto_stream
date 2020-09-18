package lib.com.afterlogic.pgp;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import lib.org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesApi {
    public static byte[] performCryption(byte[] fileData, String rawKey, String iv, Boolean isLast, Boolean isDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecretKeySpec skeySpec = new SecretKeySpec(Base64.decode(rawKey), "AES");
        String padding = isLast ? "PKCS5Padding" : "NoPadding";
        Cipher cipher = Cipher.getInstance("AES/CBC/" + padding);
        int mode = isDecrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE;
        cipher.init(mode, skeySpec, new IvParameterSpec(Base64.decode(iv)));
        return cipher.doFinal(fileData);
    }
}
