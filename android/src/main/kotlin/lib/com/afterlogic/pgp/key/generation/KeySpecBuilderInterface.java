
package lib.com.afterlogic.pgp.key.generation;



import lib.com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import lib.com.afterlogic.pgp.algorithm.Feature;
import lib.com.afterlogic.pgp.algorithm.HashAlgorithmUtil;
import lib.com.afterlogic.pgp.algorithm.KeyFlag;
import lib.com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;

public interface KeySpecBuilderInterface {

    WithDetailedConfiguration withKeyFlags(KeyFlag... flags);

    WithDetailedConfiguration withDefaultKeyFlags();

    KeySpec withInheritedSubPackets();

    interface WithDetailedConfiguration {

        WithPreferredSymmetricAlgorithms withDetailedConfiguration();

        KeySpec withDefaultAlgorithms();
    }

    interface WithPreferredSymmetricAlgorithms {

        WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(SymmetricKeyAlgorithm... algorithms);

        WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms();

        WithFeatures withDefaultAlgorithms();

    }

    interface WithPreferredHashAlgorithms {

        WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(HashAlgorithmUtil... algorithms);

        WithPreferredCompressionAlgorithms withDefaultHashAlgorithms();

    }

    interface WithPreferredCompressionAlgorithms {

        WithFeatures withPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms);

        WithFeatures withDefaultCompressionAlgorithms();

    }

    interface WithFeatures {

        WithFeatures withFeature(Feature feature);

        KeySpec done();
    }

}
