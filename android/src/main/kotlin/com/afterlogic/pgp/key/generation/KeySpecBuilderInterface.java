
package com.afterlogic.pgp.key.generation;



import com.afterlogic.pgp.algorithm.CompressionAlgorithm;
import com.afterlogic.pgp.algorithm.Feature;
import com.afterlogic.pgp.algorithm.HashAlgorithm;
import com.afterlogic.pgp.algorithm.KeyFlag;
import com.afterlogic.pgp.algorithm.SymmetricKeyAlgorithm;

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

        WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(HashAlgorithm... algorithms);

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
