
package lib.com.afterlogic.pgp.algorithm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class AlgorithmSuite {

    private static AlgorithmSuite defaultAlgorithmSuite = new AlgorithmSuite(
            Arrays.asList(
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_128),
            Arrays.asList(
                    HashAlgorithmUtil.SHA512,
                    HashAlgorithmUtil.SHA384,
                    HashAlgorithmUtil.SHA256,
                    HashAlgorithmUtil.SHA224),
            Arrays.asList(
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZIP2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.UNCOMPRESSED)
    );

    private List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms;
    private List<HashAlgorithmUtil> hashAlgorithmUtils;
    private List<CompressionAlgorithm> compressionAlgorithms;

    public  AlgorithmSuite(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          List<HashAlgorithmUtil> hashAlgorithmUtils,
                          List<CompressionAlgorithm> compressionAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableList(symmetricKeyAlgorithms);
        this.hashAlgorithmUtils = Collections.unmodifiableList(hashAlgorithmUtils);
        this.compressionAlgorithms = Collections.unmodifiableList(compressionAlgorithms);
    }

    public void setSymmetricKeyAlgorithms(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms) {
        this.symmetricKeyAlgorithms = symmetricKeyAlgorithms;
    }

    public List<SymmetricKeyAlgorithm> getSymmetricKeyAlgorithms() {
        return new ArrayList<>(symmetricKeyAlgorithms);
    }

    public int[] getSymmetricKeyAlgorithmIds() {
        int[] array = new int[symmetricKeyAlgorithms.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = symmetricKeyAlgorithms.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setHashAlgorithmUtils(List<HashAlgorithmUtil> hashAlgorithmUtils) {
        this.hashAlgorithmUtils = hashAlgorithmUtils;
    }

    public List<HashAlgorithmUtil> getHashAlgorithmUtils() {
        return hashAlgorithmUtils;
    }

    public int[] getHashAlgorithmIds() {
        int[] array = new int[hashAlgorithmUtils.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = hashAlgorithmUtils.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setCompressionAlgorithms(List<CompressionAlgorithm> compressionAlgorithms) {
        this.compressionAlgorithms = compressionAlgorithms;
    }

    public List<CompressionAlgorithm> getCompressionAlgorithms() {
        return compressionAlgorithms;
    }

    public int[] getCompressionAlgorithmIds() {
        int[] array = new int[compressionAlgorithms.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = compressionAlgorithms.get(i).getAlgorithmId();
        }
        return array;
    }

    public static AlgorithmSuite getDefaultAlgorithmSuite() {
        return defaultAlgorithmSuite;
    }
}
