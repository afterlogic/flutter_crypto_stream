package com.afterlogic.crypto_stream.pgp

import lib.com.afterlogic.pgp.PgpApi
import lib.com.afterlogic.pgp.PgpUtilApi
import lib.com.afterlogic.pgp.key.parsing.KeyRingReader
import lib.org.bouncycastle.jce.provider.BouncyCastleProvider
import lib.org.bouncycastle.openpgp.PGPUtil
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.Security

class PgpApiTest {
    @Test
    fun webKey() {
        try {
            val pgp = PgpApi();

            val inputStream = ByteArrayInputStream(iosEncrypt.toByteArray())
            val outputStream = ByteArrayOutputStream()
            pgp.decrypt(webPrivate, arrayOf(webPublic), password, inputStream, outputStream)

             TestResult(verify = pgp.lastVerifyResult, decrypted = true)
        } catch (e: Throwable) {
            TestResult(verify = false, decrypted = false)
        }
    }

    @Test
    fun encryptDecrypt() {
        Security.addProvider(BouncyCastleProvider())
        var result = encryptDecryptMessage("test", privateKey, publicKey, password)
        assert(result.verify && result.decrypted)

        result = encryptDecryptMessage("test\r\n", privateKey, publicKey, password)
        assert(result.verify && result.decrypted)

        result = encryptDecryptMessage("test", privateKey, otherPublicKey, password)
        assert(!result.decrypted)

        result = encryptDecryptMessage("test", privateKey, publicKey, password + "1")
        assert(!result.decrypted)
    }

    @Test
    fun clearSign() {
        var result = signVerifyMessage("test", privateKey, publicKey, password)
        assert(result.verify && result.decrypted)

        result = signVerifyMessage("test\r\n", privateKey, publicKey, password)
        assert(result.verify && result.decrypted)

        result = signVerifyMessage("test", privateKey, otherPublicKey, password)
        assert(!result.verify && result.decrypted)

        result = signVerifyMessage("test", privateKey, publicKey, password + "1")
        assert(!result.encrypted)
    }

    @Test
    fun invalidSign() {
        val message = "message!"
        val pgp = PgpApi()
        var inputStream = ByteArrayInputStream(message.toByteArray())
        var outputStream = ByteArrayOutputStream()

        pgp.encrypt(privateKey, arrayOf(publicKey), password, inputStream, outputStream)

        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()
        pgp.decrypt(privateKey, arrayOf(otherPublicKey), password, inputStream, outputStream)

        assert(message == outputStream.toByteArray().toString(Charsets.UTF_8) && !pgp.lastVerifyResult)
    }

    @Test
    fun util() {
        val pgpUtilApi = PgpUtilApi()
        val email = "test@test.com"
        val password = "123"
        val length = 2000

        val keys = pgpUtilApi.createKeys(length, email, password)
        var description = pgpUtilApi.getKeyDescription(keys[0])
        assert(pgpUtilApi.checkKeyPassword(keys[1], password))
        assert(!description.isPrivate && description.emails[0] == email && description.length - length < 100)
        description = pgpUtilApi.getKeyDescription(keys[1])
        assert(description.isPrivate && description.emails[0] == email && description.length - length < 100)
        description = pgpUtilApi.getKeyDescription(privateKey)
        print(description);
    }

    @Test
    fun symmetricallyEncryptDecrypt() {
        var result = symmetrically("test", "111", "111")
        assert(result.decrypted)
        result = symmetrically("test\r\n", "1112", "1112")
        assert(result.decrypted)
        result = symmetrically("test", "1111", "131")
        assert(!result.decrypted && result.encrypted)
    }

    @Test
    fun verifyTest() {
        val result = PgpUtilApi().checkKeyPassword(pcpgPrivate, "111")
        print(result);
    }

    @Test
    fun test() {
        val pgp = PgpApi()
        var input = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.61\n" +
                "\n" +
                "hQEMAxNtCSOy0UAlAQgAi5fWUBvgM9a+U43aNkYQyzLbbMQXQJ6VuE9TtMuOnFBs\n" +
                "1yBqFY1NrwwS0F3OrpSFvX9F4wdtqYKyBvpk/rzW7Sg0RebGbIcK/Fg5HhcmRHzv\n" +
                "1SIpD235mKrKmmF3eecKBe51Xo6RUnxh4kyq8+eFdeLIF9Llj5Jy2tCdf4K3TRF7\n" +
                "Z1pRXvEmYXEBEATshMzQE3jGGzvJ22Xvaoyb0IoXdW2iNLWS+eG1+zIBSOaB2iBm\n" +
                "RMKrjFblZt+lzDancFi59jJapv+zLPWNANrw80YvO7mTgHrY1UZXRvVAnzqu9C31\n" +
                "Pyc06hR0K8LfnU6ig2FhrlEe8nGzFdBYJ08WjaEW59J5AS6cX9I9h0UXcXJU+Q0j\n" +
                "Qc4aMHORq/c5ke5uJRwnNZ29CfnuIJKJLkNMjsqOq3eX0QCtSf0W5qOImn0y9MpZ\n" +
                "Ws+iG1pA393dN1wxtoEZPh7l3WBwVCtWT1H8M1puFO/MdfHBgpIyYnQ4WyxQDqbL\n" +
                "9SLIet9grmnFCQ==\n" +
                "=FNpW\n" +
                "-----END PGP MESSAGE-----\n";
        var output = ByteArrayOutputStream();
        val decrypted = pgp.decrypt("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: OpenPGP.js v4.5.5\n" +
                "Comment: https://openpgpjs.org\n" +
                "\n" +
                "xcMGBF7VI7oBCACXSplTP+Wad3JMoi5NfImZV6Kf/67Zb/bNxyeMLsKMpbrK\n" +
                "KvjNTj8jlVepa6axjOloEQ7uftlq2/GtaarDhEuxvEP8czJF5KFxBwv7dpkp\n" +
                "IA9HvPzB5/H5SM5BO7aM+5jD6JumqHLSLMuZOdxjN3SeVlAgVpjcu5nQmJjC\n" +
                "L2wRZBqZfQTUldei5LzsHee87DboVsqruFpSeJ+oH4sv8g6//WjrCAEBVG1w\n" +
                "Tk1R5FrtZ/B/745/sHhTOYDR6wDc0lWytb713BkOTq2mBsWPJvAxTc/PiWwi\n" +
                "OCnV48MIvu9EAB6hCjDPkue1V5rPux4l4zA4d5YcFx8UQ66XjQUqn/5lABEB\n" +
                "AAH+CQMCytDQ/+YDtfNg4xNQwHPsLsJhwaKmZ1rtfvmoImyvcfxCdJvVzsMf\n" +
                "zYlZ/jAKtg1LPneY1yJVOBWxHiDcNfjqXveOSyvxDlz24uegEwrRbALyQNOm\n" +
                "42XdkYIzdpzngYQcHlgd5sf1As5PcDefC3oUhyLd5BQmDZpeHyVIUCbT5rQZ\n" +
                "BEO4IOytqBUg1/rSGInonmXBeuYLvL6qHufql7shLkEcDnfkuVgV3ZHfju9R\n" +
                "t2esTCMvvgINC9mZ2f4UgIdlzrTJhX9ssrFLIUyljx2fyKKy8bSxiRxDcLm9\n" +
                "q1aj+bdBF7Qfmso5lBIjCX7RWjGV4qWRp9aOfhymPZtFwMzUgOIrxvMrghxB\n" +
                "KI1bsVjk8io8qX14Ma2sJDjc6pflOr1cydB8g1/06scnQtTFJKcFiCyrL0ie\n" +
                "nLz/d58QU88MCJdgISMBzuZl6Q/tEadsJXubPwrKPjWl5zbEFSH1oUwK6Gx7\n" +
                "mCCK9Ttsy9T3jj/DM+QYM1zlG7zXEc3C7sCpicYP6mvqU+EgqKpztBnWWeOf\n" +
                "zuojCKlZrd7IgE5XZhlaj6FZJVu49/ONYPZXgegGGOo90xwBINehBsupdLYB\n" +
                "lpCvthIolnQt2MY3gBuG2/wACDAJcDhRSDhjiLNUThqvsl9DmIAfMHV93Woq\n" +
                "X5nWqP4u7aod2RQ0bE3tmC5eapnJ7smAwQn+IXBmNarq6YfhILV2FRoCNg/W\n" +
                "5yTaSEH/FcojPum/6ganV/NWtrTI/qxxTq43aQbomUVbV9DqssLXERWUJNlZ\n" +
                "VP6z16cgZjI5AvpDl66xJFGKdF2EUmNfvZ5asQWANuQJL/9LcrxQtQ5Ettuh\n" +
                "8lTQFwHNCfdWoZbDb5vHuXlQdlvMOG3MXM6pd65/LWHh/VsQUsyV6S9SH1KZ\n" +
                "Kt8AsExf8+b1slUGym9WtTr6AQ9sz6MczRluLnlha292bGV2QGFmdGVybG9n\n" +
                "aWMuY29twsBzBBMBCgAdBQJe1SO6AhsvBRYCAwEABAsJCAcFFQoJCAsCHgEA\n" +
                "CgkQx0dVAPBBDws6swf9HEeCT2fa/L/OjBJgLjbwugPFGVIbtQBYmvp7o2Zi\n" +
                "gFMK6pV1CHEuJXBzHSNiZlBCI2RMqlCmAQNyFUpfhG1P/320xoLUVVpDPKyU\n" +
                "vNu+W6K9JmcdxExk65LH1jJ3KApf7Dca00teLQ8T91sV1zDITa5CynV7c4t8\n" +
                "uamfR/GhYtU5akj6xIlQC1GcQkfgmbdI+J3hnpiQGIyeVBCch3VBDSuBxLyj\n" +
                "mG1k9JaaYd4Fq+tVGJRx+7eHsiHTuCa/Lb622zqdxviq4+uHDy5xMkPe5hgv\n" +
                "jIfR0daM02yM1HxcM+3OOroN5yAV2uD4BUHDZN7Nc6GmgURNP9V+/WecS9vf\n" +
                "3Q==\n" +
                "=vtK2\n" +
                "-----END PGP PRIVATE KEY BLOCK-----", arrayOf(), "111", ByteArrayInputStream(input.toByteArray()), output)
        output
    }

    private fun symmetrically(message: String, password: String, decryptPassword: String): TestResult {
        val pgp = PgpApi()
        var inputStream = ByteArrayInputStream(message.toByteArray())
        var outputStream = ByteArrayOutputStream()
        try {
            pgp.symmetricallyEncrypt(
                    inputStream,
                    outputStream,
                    File(testFile),
                    message.toByteArray().count().toLong(),
                    password)
        } catch (e: Throwable) {
            return TestResult(verify = false, decrypted = false, encrypted = false)

        }
        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()
        try {
            pgp.symmetricallyDecrypt(inputStream, outputStream, decryptPassword)
        } catch (e: Throwable) {
            return TestResult(verify = false, decrypted = false)

        }
        return TestResult(verify = pgp.lastVerifyResult, decrypted = outputStream.toByteArray().toString(Charsets.UTF_8) == message)
    }

    private fun signVerifyMessage(message: String, privateKey: String, publicKey: String, password: String): TestResult {
        val pgp = PgpApi()
        val signed = try {
            pgp.sign(message, privateKey, password)
        } catch (e: Throwable) {
            return TestResult(verify = false, decrypted = false, encrypted = false)
        }
        val decrypted = pgp.verify(signed, arrayOf(publicKey))
        return TestResult(verify = pgp.lastVerifyResult, decrypted = decrypted == message)
    }

    private fun encryptDecryptMessage(message: String, privateKey: String, publicKey: String, password: String): TestResult {
        return try {
            val pgp = PgpApi()
            var inputStream = ByteArrayInputStream(message.toByteArray())
            var outputStream = ByteArrayOutputStream()
            try {
                pgp.encrypt(privateKey, arrayOf(publicKey), password, inputStream, outputStream)
            } catch (e: Throwable) {
                return TestResult(verify = false, decrypted = false, encrypted = false)
            }
            inputStream = ByteArrayInputStream(outputStream.toByteArray())
            outputStream = ByteArrayOutputStream()
            pgp.decrypt(privateKey, arrayOf(publicKey), password, inputStream, outputStream)

            assert(message == outputStream.toByteArray().toString(Charsets.UTF_8))
            TestResult(verify = pgp.lastVerifyResult, decrypted = true)
        } catch (e: Throwable) {
            TestResult(verify = false, decrypted = false)
        }
    }


    class TestResult(val verify: Boolean, val decrypted: Boolean, val encrypted: Boolean = true)


    companion object {
        const val testFile = "D:\\file.txt"


        const val testEncrypt = "$testFile.gpg"
        const val temp = "$testFile.temp"
        const val password = "111"
        const val privateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\n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\nkiDE\n=JfKa\n-----END PGP PRIVATE KEY BLOCK-----"
        const val publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\nxsBNBF2bSLIBCACQPD0/sROI7sdCtDxC21CLZPBM9ZBJAsqpOjuL8yYyuzyO\nypr+eS+XyI3yggq6G/fQHvY7zrDXTz+Nlr0lU7wYr93pKzbjNgmhQjWSKN47\nn20h1vXM9GIUeXlTrQB+Bv/xfGawHaWAwo5RpEB9vk8EYYzAPy8GCVCPcpYw\nO8civ6IYSdDur+yymPcc07OCSIslsIG3sG+B1N4zTcQATZLCC5QD2KZO8kDJ\nsbl3haz+IJjIsnwGHyahagpHM1YvLpsb5Bkehs7zTgmM+NEeAjLaFCsN28Vd\nMre7jxbpCP0ZSXbyn8DYWuYo8iJ19QplqRBNogpeet5Yttv0Jif9lT09ABEB\nAAHNGlRlc3QgPHRlc3RAYWZ0ZXJsb2dpYy5jb20+wsB1BBABCAAfBQJdm0iy\nBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAKCRCdhr39jokMLo1QB/9t2DEI\nEOkCgTxeDUEQfHzTfzoCnBXV7uXqQw1aqRdEW7zCCKnAR1+NxoGIa4dsd4H/\nYuNHrh9B0Uh3ywE4Y8e4JDHfj9g1G27FAHbW6VAlgeDc0qt1GFX9ib9Z+fk1\nbxfNwyBj0h4iZXlxQslMIMJqw1IcLWB0cN3xjzKTUHaNV9zd8hAUp4Tqru4B\n6rb1Xzg61RAsg4Ks+jacfzIc3lr05yGBaVn3dkcn5pKL46sPBBb3eawe5NoG\nKgoTe616y0mn6SzMU/1NG+Ul3L8lR8fi90a6zy0UIBbhWGtj8+RfLjmdKVcu\nYYz9ij6kX3PmVDK47ABA3/qFqusKmw+bate8zsBNBF2bSLIBCADXOrcU44W5\nodCPeYbxGqB5pFj4fqWnMi6vzv4DWl+Tb7gu3fneL8/pwM/0l0cMyIEZJThc\nEJ2pF8zk+hV6cwTrNTgO+VCMOcedzlJ43T5dsPtlIec3NQT573d/HE3DL7kK\nAdLOZTlJ/N26RVvluM9za1IDkhKzxCHNNK3Y+AfmgKfKu3VB4jnYVX2B9R0D\nhUOMKfVQV4uBvxTqxVWVEyu+s6EJCDufk9dVSDmbUu0dtOEprtPCqy2bU7Y9\nBvVeAakiExRF0I0QuT43JShv7iuGQYOpR0TqJCTLbXSHaWngkVsOw3PilDYa\n0v+3w8O60XEvxHFLX7x6g47tBbfkrUHzABEBAAHCwF8EGAEIAAkFAl2bSLIC\nGwwACgkQnYa9/Y6JDC7d2Qf/dIgQqcliWOkuldsfIZ+O4pufBGX4BWsb+x4O\nd2ccnt13s22190wkfq/fjd0Rfhpn/OUaL3HLjE+f/nXq6MUvWpx2ISO90AAy\nGXITp2b80Dna3GOaEJRJ1sfXQ8+i0F0iRPHSESieYL5FDoDIdo5PtJwiEysM\nU3+DR9oHgFBgd8b6LtZsgzEj5VXC7r0WJX4EaNVY9be2kO2sJIr5vJukntkj\nWRwqXezF9HKanu7vZGL6JhYpcEL9SiDxCVdZ+I6bL+zQM5+DxjfjvLpctGl3\nYNeUf2hCfeJq0+X9liefXQUwYmm2kkmuNq1zM/ZwiRz9s+yRnrBWEa1ez+lK\nLJIgxA==\n=c5ef\n-----END PGP PUBLIC KEY BLOCK-----"
        const val otherPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\nxsBNBF4HLmMBCADXOGziqvmTsyaGTusg3RO9uRGAXOHRivnzhdfr+F3VSRPW\nKsHoYQV5jMMmlvo4xSQx3GJvCJkvyT7qcD2UzansuIT2eKhfeIk8tQkpFZsT\nLoTvBIhoQPKfaTPDW8VkH7lm5uRdm+pNN/4ZHsAExrUfatX8dRshY60pta8z\nGHbLvG7hA6yWMVDNe2ICS9TbJX2RUHJHADflVBMNFqZ0tlKWcwGdo1mDEyJa\nnP9anHN9YMlUDf2SsTN6Lywla9rLaAo9bdFhI5oPO5g9ThsIgzKrOwCAWXpD\nhPZHWTc/S13RdAtqbTct8rVO2C+QDDmL9Zsk2V2vQPsXyPAgPBkCnqZrABEB\nAAHNIVRlc3RlciBOYW1lIDx0ZXN0QHByaXZhdGVtYWlsLnR2PsLAdQQQAQgA\nHwUCXgcuYwYLCQcIAwIEFQgKAgMWAgECGQECGwMCHgEACgkQo7ON4jvucn2J\nGgf8D8svo9LoG+m71ngVJqVP9Ghru4oU5NkpygK860ER6sonF0if8wh0ZTVh\nmNrCt75BBqkhv6z3dqTUDyIshsjQv7q5QOePv+LgniXENZm8oZ2UiejJCEJt\ntxoTYThXBQFQ62FOe8g2T8wDHyYFi/4dCTD0C40nuD3a3dLzE5egR3OapohN\nViFeXuPcPEQQMpDI45tgg+38kuFUAlvHHuKEZiK7EGFYrJyy5cpvADPRRLaT\nymNw6x3HNQmOKFLs6H+hxx3dBBrSpbywA6CbxIZi5WU8arv+uoVnawoYkK91\nM+/6JvWERxsnntQzh4/hmygdbNdVDDnlg3TzxfbmzZzBA87ATQReBy5jAQgA\nscIlHpi2ae/EUM26G7p7YtyWBoU15jH38m2D4irrIO+gppwsUiUfqdq8/ZwX\nzj1batozFDBOyGjNl1Yid+RJcWgyyF8Ta8GryUCuFkQ+wXbIN6Y4BRcw5gvB\n2Eu9rNWiXnSJ7h4z5X48hSwX9v7RiDY8oq/nqM5UD0a741QkVuJUqyv8BoU7\n2CdsP0nw4SiMjUuOO0XLWr7WtRzNZAmYA4kmHaoRMJzDB7tU32XW9Q8DD0Z3\nwu2ug/9Mt2whmngoQ8BCbmd3S4l0yzMAHe5KOiR89GRMNlIjas5LNZIsBBUk\nphdBwv3OkeHW8Iqpb5567wvoQWpZQOWQZw7nje4nDQARAQABwsBfBBgBCAAJ\nBQJeBy5jAhsMAAoJEKOzjeI77nJ94BsH/RPH78amCkyCBioE/39EsJldUyrw\nZOh0Hhlwrkkjz7opo/quP45L3Bg100RC/k+L+6aI768uQ+MrjtASkEjX8drw\nsMir8eKWv+87LX5r5lMz2iougMPiQPoUlxuWyuiZyV9GV5llwPjzx2loGuH9\nOip59u2gAnEE1Gc+fY3NE4WQ9Wf/LzoPBo3aZ6vDV4rVSxRMPXpIfI8mdygO\n8zB/Dxs6/eeH7ntZFcvLT24z6yxzh4LVzbs/QQR22+YRkixnWt2UPHoUzSur\niplhyDtyd6SVyhLKSI3U3QGU1wc/spRiaCbEb9THkKHB9Ys815FtO8xJc4uF\nJ3I8V7VaXTuUvhU=\n=Gg6L\n-----END PGP PUBLIC KEY BLOCK-----"
    }

    val testKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Generated by DMSOpenPGP\n" +
            "\n" +
            "mQGNBF5KZcIBDAClTKnlrd545OMuJ/qmcy00XZDRJYfG7qiK5qJHJv8tNoTU2cz9\n" +
            "bP2AkySFyAF4Xi6auKOv1SKMzAFxXfJ1IH1VXoJrFQOn+gAFWjZZGqNxxQJN1BVa\n" +
            "BY6g3M9L5a2fjHxa+poVrG50PfeLGJwOhWxuoth9A44IyrRjllfqXLOyNN6smYt7\n" +
            "wDj86g+uYgnaV9qSE99IHreR37wfLUE9QNN0tM2cswIpE4JJWkYOEhL5lJvNCW0W\n" +
            "NcSgXD/sOjI46CxZfs7NRPeP2hCgvycIg2F7ksGcXiHbLJD0F7/ejs/GTYGyGbhg\n" +
            "iQhZaXci6NenHR9tSOXak0Wub3plSG5oFWCfb5XmbcYJFXnMEwSQkh0NJZTUu9JC\n" +
            "4auxrvDH8u6Z3HPOAO+sAr2bq20s0VYPSJMubPVK7JuciH/nI0sSm3EBWygPTqbt\n" +
            "6ilMSQfCOPLDTD9YoxxVk8V05teGr9p20qfFmFENPDr/zdXhFfilVfRfLC9Cz/XD\n" +
            "u7WI/gjoPYRXw9MAEQEAAbQaVGVzdCA8dGVzdEBhZnRlcmxvZ2ljLmNvbT6JAa4E\n" +
            "EwEKABgFAl5KZcMCGwMECwkIBwYVCAIJCgsCHgEACgkQfNaRNO21bChWEAv/cUGR\n" +
            "63V3binH9k6XZdYscJjVBgcDdFfQtx1Xx/EsvB2za57uTkUBh9+ZGx5vUyU/UGv5\n" +
            "f3FZ+Z5xVGToT0K2VOjc4AqBHhdKbZze/QX2k8+krYUKHpvFk2TA3WiZAeAKpD49\n" +
            "rGPF+uWIQdqUs9tEiQdtXLe6H37OCdYPYMT/7BNea6YvdsxQdgwO3sD+S/aimaqn\n" +
            "ZowIpIvOXIuq4wqaOhzkajp8FMeAWntWFJFxJ24pteg+CiOUp5nWFDbTwF4UolkK\n" +
            "1qolOXpoP8kSjyCNP5sHZWnfJczpIiGNoOIAAWgG8PsL4e7PhlrbhywLznKv3jmm\n" +
            "JwC+d5PvdayJqIR92NsM+lX6u5CWKqmQm0vPWVYato1rpy8KUFqFUy6DuWZNp+Lk\n" +
            "UeM2ar8m0z8FS7Jyi5kXctrNNoNtt2hVYrwaSZ60312E1l404ReNVK3KdY6DRDeP\n" +
            "rfrElRBy+C4xhzqQZ9jtx5I1peuQemyeXOtRk8WgWE4k5tGp87kUVwE2g/ocuQGN\n" +
            "BF5KZcIBDAC4CqdFy9qWLietwi+O6vHZ8B1pw/+pMidW5MP4cLf0lkO1ZSwC3B9e\n" +
            "Q1pjZ3rjhGM0V0Vz5uEA+Ik9O8NtTBnjC7TvvkJ757Rqa22aDXj0NMxB9xmXfzDf\n" +
            "J+nvIm1tm7vF+HustJknXKpF0KdaLlBHxAmUcyD4EYEyfYe/M3v5ToDz2kqAuXVf\n" +
            "rIy5XqsBBy9NK6ss307bf4Q2nosFfDHcLiDjn3iTiVxpfnEUPBJSNHmqhpus68NU\n" +
            "SC7lZciq1w3Wia4XOO84QyOZib0QEzH3pJGy8R/os355Li7Kq/MTidQqDYw2I97L\n" +
            "kiOR07imlM6UFZ4ExdL0FRlU4ZiQt4Dp1Wb3MAL+y+KHjEJhWE2zRjzJJxrMBtgZ\n" +
            "O7m0clpElMkL3vB/Ckl4gcB5ck8aU15jX4cWItj7njm7MO60/ceKwGf6zRU3RiLC\n" +
            "AOQm77nSiPvNeIRWQXvMUoERaEVi/xtXsNNbWu64Iuj9F3e1nWO/pPOqorUH/ye+\n" +
            "XO3zEFFJ8nUAEQEAAYkBnwQYAQoACQUCXkplwwIbDAAKCRB81pE07bVsKGHPC/43\n" +
            "8+qGaMrvvifg2/y4mI0tDX941EJSjWkFTBRGXm1ebWHt6cKJQq7zJFkS0BtTAwZk\n" +
            "hYWXDBWYJ4upLGbUYXxJIGUkCmX+OMz9Szpc3QAVeN/tWM4RCU1O0jWkHX1fk6kh\n" +
            "KhtsBQFe1ZgxZQKGzKmfqq70yt3XuXPgxBqXsnZmoydCnn5N4wiDyfsMOja6F3B4\n" +
            "ZEZfCecqmF71rgczdA+78w9EXG/LIvthioJiQQhzrr1DRNWilwUorR+3FtYwLQmo\n" +
            "LJVUH8JjXxhKi1J3uVjJvaR5PlxwNtCPKxrOqdxZgUv3+LupzuX5Delw8zLs+Jlx\n" +
            "f1qsDjastimY1OC5G4vovg6KsgkSgA6rCVD/0oo3U+xqBldXm/c+9DEiZ7wqtFsX\n" +
            "SPYUJw7v23i8yVgb39s0qtU7kKXANhNoM54AtVZMlZxHFEqBagkIOs01HehAj/KD\n" +
            "akvAopKOH1KX7HB6BXhR/1JDIuFrvorDcqsU6L0GZp/a5cOtRefjSVgD9OcINiE=\n" +
            "=IQFl\n" +
            "-----END PGP PUBLIC KEY BLOCK-----"
    val testMessage = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "Test\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Comment: Encrypted by DMSOpenPGP\n" +
            "\n" +
            "iQG4BAABCgAiGxxUZXN0IDx0ZXN0QGFmdGVybG9naWMuY29tPgUCXkpnQQAKCRB8\n" +
            "1pE07bVsKGiSC/sEOMLlWiRXWpRZQ6q/vd7U6roFmVYVPSdQ1KoSvrkiSlv3TF9d\n" +
            "LuUC1mbZjhh37XAshbKLxU5QWYM2roH3lnMjD6j1s2IiV5IrFhQqXkckgq1jyWw+\n" +
            "Za+KGOYZqL32jOxpjgefVWXgmAw+575rTkh+s5NcTyfWRjZU5TZ4Oe8bfB+vsZ/I\n" +
            "MkQ8DosfxTg2+Mot/vy0g9q8aHboIUhRcGhJYo26ZMIOUxrHgkav8oByArehUu+b\n" +
            "08zWJA04H/7igZ1pjJd8eWWChxd7ccf1aKZOqOlPMi5Dim+R5F1rF/Y6JQpi9f28\n" +
            "THuw81w1/Qt0v5Au/RMVzhGJhe54eCpAFShY/+7EIHIH8DQ8m5UpKGJlOfysocje\n" +
            "IKYfBju+AQjSSo3p0cfUOODaXdnbeJ+Enndobp930gG/nf5sFxe9h+xwsVOCquRM\n" +
            "L5KvrrTFz0zIXWDJvWumVaq2D8T5xVhnu66E7FaHGsvaVrv9ZlQDGyeB4YtQLDQn\n" +
            "IdCur0X2/Gh8m0g=\n" +
            "=TCEa\n" +
            "-----END PGP SIGNATURE-----\n" +
            "\n" +
            "Sent with PrivateMail"

    val invalidSignature = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA256\n" +
            "\n" +
            "text\n" +
            "Best regards,\n" +
            "Vasiliy Sokolov\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: BCPG v1.61\n" +
            "\n" +
            "iQEbBAEBCgAGBQJeoEKZAAoJEOfZBoST2nlwzkoH9inf8hXgYgY3Y2aHVN1eYjGr\n" +
            "q9pqgAUVGMWCkoAOZmN2H71ypW1mIi2TGkcO82HrlfxPuRq0YHLZZhrNvFvo6KHe\n" +
            "XZOQ3x07dL2Lx37YAW+MAvzgeQ4SP42bLbIJwL1rxCx8XuuTEB+NDD/VKP4tyzik\n" +
            "15U3Xu5634fpKfVHfLP3z1Fjv1MMbnkxrUG4FMrZJC0CKSoQTlyNehCmmWgGPrEJ\n" +
            "nW43Vwaxo9qLLMhcKdiZSnYkiQ04CPn/wGXuYvDQxaJJR5GY7WurYfu1ZYcgVDNp\n" +
            "rQZb7RZqR3VRye2bUdDPa2p/uIXPdQ81gpuC5jU2wbVYjqA3Xg+K1zL5xwpAuQ==\n" +
            "=AFlz\n" +
            "-----END PGP SIGNATURE-----"
    val pcpgPrivate = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v1.61\n" +
            "\n" +
            "lQPGBF9E6lABCADDDDr3ETEPFRxWMGuuhsXRr0OyhFfqymPPgbN1rnQnsTGOOwLt\n" +
            "X6LxtcLZKDnNFYQABPD7UXwa/DFbuWrtEF672u5C5NfmRSB4/sxDNSpSZjHLnkg7\n" +
            "7pb+Cg+/U/g+rV2FIBvXEmcPwE5inBSYLJjGcnTdw4u2jlMp5/b4i5k2SB8DoFrt\n" +
            "BF03TfUVIXhcS/ouyRWRVYXAQ/PkywtKIzJPwo1/30g20btR02T1Kis2cj3P/ESp\n" +
            "n6MuA/ga4FBduzGFalsfUHDSMok8CoT702ObY3peCnb/H5joTop5WaUd6avjphT+\n" +
            "gCi+p+s+oH2Wzi6OFifyo50xI/TqTA51sWVZABEBAAH+CQMII/NDrt1JAKvgvMFW\n" +
            "Y8zhQKRepJq5wlBSu5An62Tr/8aPbS/gaP7D8o+FKS/OvIjJyrVFI7v7KSfjszfG\n" +
            "xjBpT6Au1NIXG8NdGKj4JAHcBp9n5b8NfDuZ9E/lWPtPYAIVzkqBG8SBkUq26GMr\n" +
            "8UFbxzWAnUJItFFA3N74K093qmfJdGovpFGYeoi1YZvMaMQZcA4OtbhzseucBcuQ\n" +
            "V4+Q9DCU3KcPFYyVcnX80ohfJ8uEyHcWFZBx0/R61d85JOt1fmXSs6AjK8rU7Zq0\n" +
            "lSvnuvsvDMk8CbFhP6KSVZjirgiHq2znj1iimGUtP+iZm9IBDmSOpmuuogyygZFW\n" +
            "W0IYWYePcl4EWCM1SjiYe+0EM4udtNeviunVyeY16XunL1ZQLL+B6ZgEhOtwNOGN\n" +
            "kedRksAu00YzSO0tY0vm3xrrKZouHQe8/JppKZQPtYHaUvgv0+n0s0keGHE4524z\n" +
            "HsfRv0cdZ2+mVlghiJK3pbXnmd83ugXuuNQqeIBDWLO5yrO0zaFiCY1wvS8Wc+I5\n" +
            "Tnnx/WLUu2EhUaDvvjnlq+eNtV58XtQCoTVNpP0sSoxdLTAFP4cYsn5DBFFrhdPG\n" +
            "IVEK52TFPY6qwhH6vnTrDe7qVM9iHXTlhBfl2VzROOH9VbBVG68UzmVNpQwKX4kk\n" +
            "j3phw9YIb5bnMuf6/wE1qTLZp+TKK1LKneTrPDDQMLVJFLfG1VwcowOOJzC/prlJ\n" +
            "2RVqQv7WqtKtIcA2P7dW3EgnRmtM73T9Ih62Kvntmzm67CxDzB3nhNIowpF7BADK\n" +
            "nYpP04MqpoKC7m0nEIqcxGo+ihptQ8Bw7EnKNSACNFlGtIBSPsa1VE/KJ4i1txAO\n" +
            "UF4aX8j2tfRIH1WJdRSeD6XAuYeeLNLi8lxwgMRMCIW5cQTl4QJrWvKmA6tsfhr5\n" +
            "mqthUMMT0M6+tCLRgtC10YHRgjI5NTcgPHRlc3RAYWZ0ZXJsb2dpYy5jb20+iQE1\n" +
            "BBABCAAfBQJfROpQBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAKCRBqqSb/sgJq\n" +
            "aBWkB/wOTGwnazfz6LyOZIhJ7HNajteQpSIj8S8YK0ZMaN/j1+Je1LX4+HKJpzzF\n" +
            "4+cTXfz/gexZRP1jPRxCxrk5j0OfJmEdPwa9ffYpfSO5Lh3c8gUCFBHop4tYNfrR\n" +
            "I4KeI2pcXe4mGoiFKLLby1e9OT1k94W5NZVY1lJagWq8adIoXYqjf9RrkkmjqNqI\n" +
            "2dBvQqlq13JmjXBKHP/Ai4Lfr9ahqTGSZQL3FYt6udRIOi/yx90FjDtEDon79AP6\n" +
            "szeNA2PThkkZ7xW1DtZOvXD8/kLIrkG0hm1SwdYty1ON83yLk4XAwh2JLXLqKTk2\n" +
            "8+3nc8ZmbkBLjl/Im1HZTd3a537anQPGBF9E6lABCADSYYy6ctsOh23hQdxfXX4h\n" +
            "G1rtTuIep2bLQCDUXO4B2RoAqunRtLO99JTpU3YeqwTSglsLZJgfIoeue3AKAlTm\n" +
            "nVuAYrxj541SxgR6tv6OxY4FL467lwsC/G7CkJqoWkgCTNaI3v/N+QExePnyHorj\n" +
            "I8927VXdaV8XLc9EdQKZaB5+qaPuaY4eQWJa8LTPjfOO+8ct5SngsJ/FpuoRo9RO\n" +
            "EN31pizO0gWnVWZdJgM3V3s5z/Q7r6wsrGq4x89MVROwcGxRVqc//089KBfizxNj\n" +
            "pVyTOCmHwnfBBxeZQIie/Uv5XjDrViq7i5D+yfdXOqxVEXJqDsrvvUFpx5/9Z50T\n" +
            "ABEBAAH+CQMI4DFF2JIn/YbgnjldbZo3TSAZkbGMNsOUoPlRf/yWJH3qEURJiEJ1\n" +
            "/5jPrqTUebZDct3bVPNUakKhk4znTONdTHYzoseWmRdLnoo7NuxSuXHlCRKqkgX7\n" +
            "viBv7N/loSyfJsVSU/SVRCGJXXhdscWpdHsmaso1G89o1Q66SArMGVhUBD1E/bs2\n" +
            "phg8Jre+ufKCwOTAv0Q5W9tETESJ56RPvyzGvVxU+A4DYxAdz9oozPZAt1RbfqgU\n" +
            "3rBqtQdN9Tg+99p8vlqduG4tuBW1Qx5qBtfHwLQX4zDdf5xoeSlr56+mpmS/ArV9\n" +
            "+YGjR0WxHk4XVcehRruTsb7Gic+beyzzYgbAasyFqOok/z2ofB3lB5P6thgyhvXv\n" +
            "4uAAjtgVIJLYLyG44ad/c4uYMMCchxqVP9Z7S2SyvXO0gdHr84hitW/pt+zSxCS5\n" +
            "F5AFK2M4GGy8M/oNGS88n0uuijy9dMdLnmO/0oVweCZBIZwL7aU4BBF/54sTb0Ol\n" +
            "TaK8nZLaXq3PAv/sPF4p8195emj0PzY3oElTOa25MUTHJsZtqR9qEqXAmGiNzs/Q\n" +
            "wITH/wbCNICuvjHTsbVrNlfmnwL8efq0lYst4zaW3o2Hk06C3MG1vm8UdFbh4mMq\n" +
            "gRfuyrRrwGGbORq6WajX5nSo6z9kALQvssPF938G6tAlUCfFswMEs2cfnuSiRFNc\n" +
            "B93H/+NQ2NcaaeZs4z/afxX0XETXCztCtSmWlQnzUB/KrXMb9kjeALZY5der4ul7\n" +
            "0DHysF1sW7Y1vDsqLKJ0viD5mD0uVeluq46XfnvITt8lQtyqFIzifMIqsPE1VpG0\n" +
            "RaLHhj6j6vST+6SXBuApfWxqrcnrQFGo7tD5QDatNRFi6arXBf095PRMh0Nlgo5F\n" +
            "LBvEwr48NiBnJ9d6Y4mtV81i3gSrqkbQFxqW7i6siQEfBBgBCAAJBQJfROpQAhsM\n" +
            "AAoJEGqpJv+yAmpokggH/RDR8oV4Yf1AGE40zVS9Z3+BnhQR+rcl0/2LB4oNGRFK\n" +
            "37r+fcMOpjbsWzU8TReMpgcapXIG55xeTbgAzFWM8Kx8IgGvCG8zZ+KToc9Uospd\n" +
            "u5Sis03qO9Rppp0tOTDeoXY3F7lbrLU1K9mST4Xf5rsJSPZkmAXQmXMtTFcUGdh/\n" +
            "vsVVh/I58iaV2q1Yl9Lkf8WKIVGMMqFnlSfvj5Ikd29hVSap3UuV/F0myS7J/odk\n" +
            "GD1/nd65wxmb3Fnek9vFLq+ZHgLWm27RoHbvkIb1GHbdq3LCZswUasLbcyj/S+X+\n" +
            "9nzaiwDi/Y5NtLFpPOcsPro4c2iLmWfzvlQs84gwlZU=\n" +
            "=esLd\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n"
    val webPublic = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: OpenPGP.js v4.5.5\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xsBNBF9SMKgBCADQJQ1KQOtREJm8r7arOGIzT5in5lgRtJJyQtNxNzqTVDYr\n" +
            "TIeylKpBB968v7Q4l07jPRmHzqlRzrpuv2SR465nLaGoY5lg9xlwnr0BnZsw\n" +
            "66APrNN2c98h6mxRC7s4oFF84Il/QFeE+9gtRJmndURuDqY+V3Kc4bSXGAbD\n" +
            "YXabDxQgyWI6PyCBGnvGh2kegKF3G8uGSn0U/3rfbMq+5tWJfklaOJBuHpz/\n" +
            "KhCTIqWYJWfk+46SpwKmJpZnBDk4GR2bZlT2hI/SZ6m7f75JiF3s/B7dsqBB\n" +
            "SFT+ueVwe/R73IUn5EhYJ6oDTH4002e030/fx3Me8/bGRHfjjgIZ8eVZABEB\n" +
            "AAHNFTx0ZXN0QGFmdGVybG9naWMuY29tPsLAdQQQAQgAHwUCX1IwqAYLCQcI\n" +
            "AwIEFQgKAgMWAgECGQECGwMCHgEACgkQ2BbWjGaAKfQDtAgAoNGab5eyeAa9\n" +
            "1r8Uj1s2844CgnURqQea9myzNW1CuDnzsZD2nG0XMAG8xCF6rV1xtgVB/Zfx\n" +
            "cpSSYKNBR0WqsOtw+CXTR8j/vwNBRvCBbWBqsUjF8PoWYfi0oNyUgbLKn6lD\n" +
            "n1iQpVraePh2tq8WjffFXDi3mgi6MT77VJHs3Ek1q727zP7Oy0IGre3d6CeR\n" +
            "SF0BoNvFziah1Wx8t0OPA10zIY4qHSJHRmfWUJe8k++yVHpoaXJIleu1Gj/Q\n" +
            "QKGNXclJT4hVWt3F7h5W7uzlMgpzd1b37O/bAfO0ry1IG2upuQFQJBZXIvsB\n" +
            "3vjKUcn3k2W4NZ95L4g2OFW699xm+87ATQRfUjCoAQgAqYa4bmguKUjbUJbB\n" +
            "p/4yTKGKSX3ivR6kqkTaNfuwlavQTgHPqwOfaE23gwp94veiwPCxkbVnfjn8\n" +
            "9pPrYJ2DRrMmGr5TnY/tbWfUn1Y/Vwt1ir05EgvsZBdQA3Y5Rnq71gW0f17F\n" +
            "EtidqMMJDzdRRhXEoI7lznkCh9Yp1nX6aXwqqXCwfX/L+IU6qJNAYExdwVuZ\n" +
            "Ya7ZwlJug+wUvEHlcyTU43yFZ+ZyknsmjKRzCh0C+/QkJGvhlnN5dM/i90vV\n" +
            "RIRB7PlU+jau7ptXGjYMvZovRy2Ez7iJygI+dPFsWu7QHkJ/jnTO8C+s4nbB\n" +
            "4vMLQPk2cZFF8O3RmxiBRpmtCwARAQABwsBfBBgBCAAJBQJfUjCoAhsMAAoJ\n" +
            "ENgW1oxmgCn0XOYH/2jdrVpH0MyQ7aae/iaN5AM8fZld0AnrwVy0E7X9J1hf\n" +
            "LzLgwWCIKBGxONR4FX67rAsdPOPadn4TBD9SUJUQtRIax3Bp7a0puqdIFc/J\n" +
            "8sU+oiJATP2fH5FVxYr3OF4D5+Qhlcu5szOLeRZApEYdmbUIXoBKfw8gOg1S\n" +
            "+V5y0lcxKFYALFG+TDnHG5qiQ7hpSQSTHS7412ssW2i/sviWnm/cfdOWvmy8\n" +
            "7+YgaTkKJ5g+jxntWaHmTeqhoFbyMJYoCgwh0vl1GTe/BPvta5iFt50bzSt/\n" +
            "7f80fydJjyRzw1ohxorVhEaeKQDnjRBEN6F//cN+Ef6EwAZ3f2EBQuWJQ+U=\n" +
            "=R/5j\n" +
            "-----END PGP PUBLIC KEY BLOCK-----"
    val webPrivate = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: OpenPGP.js v4.5.5\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xcMGBF9SMKgBCADQJQ1KQOtREJm8r7arOGIzT5in5lgRtJJyQtNxNzqTVDYr\n" +
            "TIeylKpBB968v7Q4l07jPRmHzqlRzrpuv2SR465nLaGoY5lg9xlwnr0BnZsw\n" +
            "66APrNN2c98h6mxRC7s4oFF84Il/QFeE+9gtRJmndURuDqY+V3Kc4bSXGAbD\n" +
            "YXabDxQgyWI6PyCBGnvGh2kegKF3G8uGSn0U/3rfbMq+5tWJfklaOJBuHpz/\n" +
            "KhCTIqWYJWfk+46SpwKmJpZnBDk4GR2bZlT2hI/SZ6m7f75JiF3s/B7dsqBB\n" +
            "SFT+ueVwe/R73IUn5EhYJ6oDTH4002e030/fx3Me8/bGRHfjjgIZ8eVZABEB\n" +
            "AAH+CQMIWVsujY3oLXbge3cdwDf1C6Z9xlFbCdpKVRQaiUN+y8PFHElCgADD\n" +
            "9Z+Hj8x1EYJHyov12aqTdJvE9ZgbR0xPnkfYus4qFZE95nrPckAyeZgcpnoa\n" +
            "WGImmpp5B8WhLiAslG4qvzaDw+aUAXMfBsrIuQO1A7tSilxQA3t1bh2M3z9H\n" +
            "Lk63mKzxnYR+yBHO3y/n7KEo0SauNGH2S37G3VwofdqFF4W5tjHjtQ2OOGYO\n" +
            "KPC3m46zUFeVBxjgIe+T497QmuwF0qvhMQ+0iQ7kXWxxgRLnSGGtxfSfpbIH\n" +
            "QCu83sVgEbNS0HmUY9mmcaKSjp7CZ5sfkBPtlVSzn6MiJyj8v4imFlAyRFQj\n" +
            "ewtV8ssvLr7ugi3NBa58+N2MI3v61AxJNGvCtZ1d6XRWBX31elWoHSFwYnEf\n" +
            "bWTjKizPubC6fjBjTYOO6SY8xwni+QIuqlouuEn7hdLKxoiPTjXl8sbFgvdv\n" +
            "4D71ypf2jWA9tCBbPHIBwxh7VfmXovLXMOnnIZloBy5mof6j6c82dAsPOQ3x\n" +
            "HBvmOiKyPKCUQ/JPAkHMSy3+h/e4AXpAxB0O3TLI6/G9HQNmPCl+kjWgT+Dj\n" +
            "O+ZSVhx2YOdnGR8MZqJS5Vwngyky8Ax5Koc4HaEr/KoGDMFROnyT0KTO6lEI\n" +
            "nbh0npzs1CmfRemzDuzXc0DUkiQFfXdsO0R79Hfaa+JuPqrc+fQbM0NEk3ZI\n" +
            "YU0cd9bT0yRY7c5+4ThMdMgtm2FN+qmcB8Dtu+tbcG6uLqyF6EDbx/YWSfrV\n" +
            "RhHFbCw3QFVOr/mUYk+OkOTWxPRKWdM6PI9kvbx3IAQ6xNfXoMzO7Zn5szjy\n" +
            "09ZQAJgvLWvdk+mmZeD/1Q5WoyD82UGZzOtmms34Y0PGZHPOYAmJZSVAojDY\n" +
            "n2S44+ba8zhem6G7YaWERbiJT2YrdB/TzRU8dGVzdEBhZnRlcmxvZ2ljLmNv\n" +
            "bT7CwHUEEAEIAB8FAl9SMKgGCwkHCAMCBBUICgIDFgIBAhkBAhsDAh4BAAoJ\n" +
            "ENgW1oxmgCn0A7QIAKDRmm+XsngGvda/FI9bNvOOAoJ1EakHmvZsszVtQrg5\n" +
            "87GQ9pxtFzABvMQheq1dcbYFQf2X8XKUkmCjQUdFqrDrcPgl00fI/78DQUbw\n" +
            "gW1garFIxfD6FmH4tKDclIGyyp+pQ59YkKVa2nj4dravFo33xVw4t5oIujE+\n" +
            "+1SR7NxJNau9u8z+zstCBq3t3egnkUhdAaDbxc4modVsfLdDjwNdMyGOKh0i\n" +
            "R0Zn1lCXvJPvslR6aGlySJXrtRo/0EChjV3JSU+IVVrdxe4eVu7s5TIKc3dW\n" +
            "9+zv2wHztK8tSBtrqbkBUCQWVyL7Ad74ylHJ95NluDWfeS+INjhVuvfcZvvH\n" +
            "wwYEX1IwqAEIAKmGuG5oLilI21CWwaf+Mkyhikl94r0epKpE2jX7sJWr0E4B\n" +
            "z6sDn2hNt4MKfeL3osDwsZG1Z345/PaT62Cdg0azJhq+U52P7W1n1J9WP1cL\n" +
            "dYq9ORIL7GQXUAN2OUZ6u9YFtH9exRLYnajDCQ83UUYVxKCO5c55AofWKdZ1\n" +
            "+ml8KqlwsH1/y/iFOqiTQGBMXcFbmWGu2cJSboPsFLxB5XMk1ON8hWfmcpJ7\n" +
            "JoykcwodAvv0JCRr4ZZzeXTP4vdL1USEQez5VPo2ru6bVxo2DL2aL0cthM+4\n" +
            "icoCPnTxbFru0B5Cf450zvAvrOJ2weLzC0D5NnGRRfDt0ZsYgUaZrQsAEQEA\n" +
            "Af4JAwhNpqa5gSX4auBpzsm0Ct6KXUS3YYX5g2L/aDj2BSs2TQhC9kkwCGJN\n" +
            "ydbMe3kdIdU+3uJI3NX5rLzWGb4sNSgEbXyEGcL4DTznz78f3517i5i4vT4f\n" +
            "V1wC2sLW37aG57iguwVGEjaM/OnR4ilJ/szBQUrmgV+g36Wdgz7EhLUJXTaX\n" +
            "Q9XlbpiNTTfNUtdo8oDTNHGGRo1aW5W5FSP+D6g6YzDg0vdq4j2RIExuYf4O\n" +
            "D1rDzMuqQK463NAp9QKTZUBytxa299hT/Yc7p9atSQIzPvTyWahe4o6OkH41\n" +
            "vA81GhngDKHCO0ey8tTaVjfymXK+6ZLxiPXZZnZ5y+ZBP6XsY2O/3b7dQFs7\n" +
            "9uaKpSAfUHeccSLDZPuVDhqgh9v2+duZy6JVaOz30ZS6bdVXsOpw4nkRK/TR\n" +
            "f5f2DS+xLnWR5+/ZwnnbWFzUW7GiOYIR7s0eaY1BU71aWFzZavJtB8ifNlLG\n" +
            "egHar1GTNNaJRNv9rD+wvhOArerWu9Cs7C/HsJX2r8vXUpomLAkYjyDktQ+r\n" +
            "CP1bddiZRqvPiauSSCBi3eZzvnQSFVDi/F7ziniVyar62dM9XMXpeZlRPt1V\n" +
            "RwLeoZ5jKzyLiSm9KGhfL+J7SHQHJ7nEE8EaChUmgidIldpdJdbRE4Xm9Zhk\n" +
            "hxHENqCnA+o7R/V8iNPViEla/q/4samk/SsX1WX2lfOKhL6Wg5jKcXAroMhN\n" +
            "Og52lnoPvbLoo1Tv7C6WYHz6/NGF2kKNhN6jcEPS6qNWniFx4tTycCd3bluF\n" +
            "e4avLBLX2+uNVsDuXYOaE4Mx1rN5JMdHvAWB/VTxhWM+x0VlMrw9NEdMxsIS\n" +
            "aV5HnGK5BMKb/UkpO0/IoPMQexbvvio8lyuq/oCJeAkceC38p3kF4zkLUEUR\n" +
            "cOOPO+dlwyvqmHI1RjHIBUr+q2nMlRDCwF8EGAEIAAkFAl9SMKgCGwwACgkQ\n" +
            "2BbWjGaAKfRc5gf/aN2tWkfQzJDtpp7+Jo3kAzx9mV3QCevBXLQTtf0nWF8v\n" +
            "MuDBYIgoEbE41HgVfrusCx0849p2fhMEP1JQlRC1EhrHcGntrSm6p0gVz8ny\n" +
            "xT6iIkBM/Z8fkVXFivc4XgPn5CGVy7mzM4t5FkCkRh2ZtQhegEp/DyA6DVL5\n" +
            "XnLSVzEoVgAsUb5MOccbmqJDuGlJBJMdLvjXayxbaL+y+Jaeb9x905a+bLzv\n" +
            "5iBpOQonmD6PGe1ZoeZN6qGgVvIwligKDCHS+XUZN78E++1rmIW3nRvNK3/t\n" +
            "/zR/J0mPJHPDWiHGitWERp4pAOeNEEQ3oX/9w34R/oTABnd/YQFC5YlD5Q==\n" +
            "=RNRj\n" +
            "-----END PGP PRIVATE KEY BLOCK-----"
    val iosEncrypt = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: BCPG v1.61\n" +
            "\n" +
            "hQEMA9gW1oxmgCn0AQgAhSfb9V3SVyVk4jFzKzBZAhgW+lDdFkNDCClKZhQg4TxI\n" +
            "HPnW1jMkcu+zgeLShRNJGKUoTz3lBxO3Xy1p7sH4mdiBE2rrsI8F7msfNLKhOenP\n" +
            "mUh/O+yq1p3StpuNQnanlQs3kUq11t4eCl3BxekxdjbvOq/NFT69HbpMIQYXw+SS\n" +
            "hqFbfuq4ZrckT2TxP11zWvr7KTJD4ooSkfsML0tlQtVgwSai0OyInC1OXvw3OPkU\n" +
            "QVxx8RTv8o5PzNKa/oowY7ub5Y231FwqxHu+WeZES7d2kTQMqY+fK0u4agzYgNnT\n" +
            "ChInhTCZwHHgKBk5/rvlpFgJk/zYVXjNvxYYVtjd7oUBDANKLTwjkXgsDQEH/jJY\n" +
            "D3ohQ8uMHJYFcMFeDmG4GrpK5zKyQghAhVUAPoxyXMgS/5fnTmGanj///6fRvgmF\n" +
            "G2CrCU5HQBIHXocIm5guQdYCvPtUwMMrrII7AXuhu3BTVNe3NXsaEp0cAy/n7qJ7\n" +
            "mZuFuD3yuMcsdGB/dJSGiYAR5co/h7Yn6hyqcEcJV9elOSKf6DpjFW424f4mp+32\n" +
            "dF/ayZ7pgzYQuDVwekjdbHrbUpF8nvIjcML0U5U5Vl71rGhZ4VEtDvZ0YA74IUGn\n" +
            "9YA2Nv6iDqJPvb4TPedXxj8V/XYjxzZ54pZv67V59gxWl3eJGirR1oFMsUfPirzZ\n" +
            "afrtxxaRLL1ysaZXepHSQQFJoe6+yFhECa8j1XICbzZkWKguuHJptujSDa9FRgid\n" +
            "GB521EagZhcfldKQw8A1fHODVZ4gGfnZbSNRuLXxd1/3\n" +
            "=ppH6\n" +
            "-----END PGP MESSAGE-----"
}