package com.afterlogic.crypto_stream.pgp

import lib.com.afterlogic.pgp.PgpApi
import lib.com.afterlogic.pgp.PgpUtilApi
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

class PgpApiTest {
    @Test
    fun encryptDecrypt() {
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
        assert(!description.isPrivate && description.emails[0] == email && description.length - length < 100)
        description = pgpUtilApi.getKeyDescription(keys[1])
        assert(description.isPrivate && description.emails[0] == email && description.length - length < 100)
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
    fun test() {
        val pgp = PgpApi()
        val decrypted = pgp.verify(invalidSignature, arrayOf(vasilPublicKey))
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
        const val privateKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v4.5.5\nComment: https://openpgpjs.org\n\nxcMGBF2bSLIBCACQPD0/sROI7sdCtDxC21CLZPBM9ZBJAsqpOjuL8yYyuzyO\nypr+eS+XyI3yggq6G/fQHvY7zrDXTz+Nlr0lU7wYr93pKzbjNgmhQjWSKN47\nn20h1vXM9GIUeXlTrQB+Bv/xfGawHaWAwo5RpEB9vk8EYYzAPy8GCVCPcpYw\nO8civ6IYSdDur+yymPcc07OCSIslsIG3sG+B1N4zTcQATZLCC5QD2KZO8kDJ\nsbl3haz+IJjIsnwGHyahagpHM1YvLpsb5Bkehs7zTgmM+NEeAjLaFCsN28Vd\nMre7jxbpCP0ZSXbyn8DYWuYo8iJ19QplqRBNogpeet5Yttv0Jif9lT09ABEB\nAAH+CQMILpweicjXskLgUv4a2emCQVZ9je+fo7wuHuIsgOQ4TtBgy9O4laIX\nLMDus3t4ISH1DKPwriF+sz9O/G+Ogj9fNKKIq5KuOeI1BE+ya9+YoWSA4zdO\nPoCYECRBX1VAz91FwbA+7PtneqVeLlF6FOVHWC8njr2fMNm4yI/b52C/iyQQ\nM6fv7hjcVil4WKAXB0E+Bdk/RROAuuO30cm5r/BFyAJPrzl8gTL+TPe8sfLl\nhkeVzUbTaxH9BZZwPKWyAFdRnnRF3EKnN8BBgcOj71J1grJhIc2OHkvsM6bf\n5OrsaGOG95sUmVHQoV8khrgQbN6nQh8jco6Mf+0s5Pmbj35SZ3OH9jfNiih1\nhrJka2Dc/E87hfsQ/3NXdRVX3K1OiW+PMzWjQFfuWTF1DK1l2qvbO3ttNywy\nQ6tq0OJ4Y+yqb4nJE7TYs9kOU5WbJRi2OMrWrVB8Jf+vMrj8ujdjJ+5V6xR9\n1Ogk7j3niFOeEn55HV4Z7FNoc1nmnQ/3Hx0ttBATBaO19ZW3b7p+cC5lHU6P\n/MMRaFVNzyEdGAdQ85cVoRJwSftX24AhnyCvtqtegEy2eAMpSM+AcJkMZIvA\nWp0X5o3ECHiiFUgW6QsKd3RaAY1ougS/xSQTUzaoAK2sbiTWtlwPYrn0PemX\nh3px9RzKKA1H4+iM45gxC89riG7sSVEhVCs9q2UQ+lb9aGZq61hGHVclt3Gp\nB4uKMzeq5TkWiBFMnDOgm9/LgWW/mfZt6kMkn5LJfABP3tmRrNfNTYmIASNw\nXIyij1ZA5tfQMK1R4VwLkUGU88ZTumhs6M5RKuekSmBAtFhCy4HsfoYiNUeV\nTBD7uSYHFwTp5VfDjFVEPsSmZf1nWj3z92jqeq0QhQzjqzByAPQMOlSH+pPH\nWxCDaQcBSe1GmxsDfRdLOocHVbC+rjyEzRpUZXN0IDx0ZXN0QGFmdGVybG9n\naWMuY29tPsLAdQQQAQgAHwUCXZtIsgYLCQcIAwIEFQgKAgMWAgECGQECGwMC\nHgEACgkQnYa9/Y6JDC6NUAf/bdgxCBDpAoE8Xg1BEHx80386ApwV1e7l6kMN\nWqkXRFu8wgipwEdfjcaBiGuHbHeB/2LjR64fQdFId8sBOGPHuCQx34/YNRtu\nxQB21ulQJYHg3NKrdRhV/Ym/Wfn5NW8XzcMgY9IeImV5cULJTCDCasNSHC1g\ndHDd8Y8yk1B2jVfc3fIQFKeE6q7uAeq29V84OtUQLIOCrPo2nH8yHN5a9Och\ngWlZ93ZHJ+aSi+OrDwQW93msHuTaBioKE3utestJp+kszFP9TRvlJdy/JUfH\n4vdGus8tFCAW4VhrY/PkXy45nSlXLmGM/Yo+pF9z5lQyuOwAQN/6harrCpsP\nm2rXvMfDBgRdm0iyAQgA1zq3FOOFuaHQj3mG8RqgeaRY+H6lpzIur87+A1pf\nk2+4Lt353i/P6cDP9JdHDMiBGSU4XBCdqRfM5PoVenME6zU4DvlQjDnHnc5S\neN0+XbD7ZSHnNzUE+e93fxxNwy+5CgHSzmU5SfzdukVb5bjPc2tSA5ISs8Qh\nzTSt2PgH5oCnyrt1QeI52FV9gfUdA4VDjCn1UFeLgb8U6sVVlRMrvrOhCQg7\nn5PXVUg5m1LtHbThKa7Twqstm1O2PQb1XgGpIhMURdCNELk+NyUob+4rhkGD\nqUdE6iQky210h2lp4JFbDsNz4pQ2GtL/t8PDutFxL8RxS1+8eoOO7QW35K1B\n8wARAQAB/gkDCHeDFJ7iobu44Fc7Su/55mJOGoA3TIHozTcKcMAE0263RVkT\noCTxK607WJRGR9jv/pCqBBZIvYLZPp6SIfbwJYd7Tzsnx1kq4C5y+i/yUDQY\nHqbnUJ05IK6Dix7Bov7KnDD4FpoGU8d683Iu+hkLKViouapq6kJ2aaF+nMxD\nlJk1C92pDABPbcyH9pglcMK3kFEysLs9AVO3qC2l+L3T4MbJWlYUGTBAf+gJ\nILk3LFjBgNom+bttm3XKzSj0c/2tMct+pzLrcltdjyWFPGNG5cB8pSUQmwgD\nAyl/DFwf1vdbDw8x6oZNJwPHY0V7cj5QqcTj4HRQIUesfNpb5wbFxJYp/ooN\nK2b2Bu7gr5pneAkNQNQwh6Pif2Di/gFArgS5Jm6wBAL2dK6DW3gtUFSEvc3C\n6HkR7cB8P0nOgopnGXQVjHRz5vz1MLNz2x8qYrEvCoGGR9vodUwRbeX5KR0S\nUbyG+5QZ+KZDOQdNnc7Cr24iKGRkc0A6XZXCdR42L5mCVqfzHmIbIfLP90E/\n6bg7BJj/sXBzE0zxak+izi6ONrpEvAbkkRKd3KwpQoTatVJIbDOvQkIWc3XM\nsJrdWd3z1pbT35kiHQwKtFgH09zsTOJPz2XpGGs8pa+HIO3yMz54bwrL1Tqu\nlTDRpykAKfb/0qoXLxkZCO7CJ8wQCcodbEU8Q3lomHFV/urGiH2z7m6QQMuJ\npfOlnh5u08HIXCpKZoh8b6k/R2e3BDoClSSDMSmrx5KHW/sqTKTpuS40MyC4\nf5Hw7/cMCg6Rv9WNZQROoHJRPaidyePQIV/DqPSZvOeLmAGywxyXNgBVHKu+\nUeyY1DBIbWqKuKThUrhSbMTjh9GLSezHHMQM0wqsVKkfw7I73WQHddaqujhX\nU9zsKMEAazhgkIMLwxw5Kz2dOOc2Fx6YSIZF5sLAXwQYAQgACQUCXZtIsgIb\nDAAKCRCdhr39jokMLt3ZB/90iBCpyWJY6S6V2x8hn47im58EZfgFaxv7Hg53\nZxye3XezbbX3TCR+r9+N3RF+Gmf85RovccuMT5/+deroxS9anHYhI73QADIZ\nchOnZvzQOdrcY5oQlEnWx9dDz6LQXSJE8dIRKJ5gvkUOgMh2jk+0nCITKwxT\nf4NH2geAUGB3xvou1myDMSPlVcLuvRYlfgRo1Vj1t7aQ7awkivm8m6Se2SNZ\nHCpd7MX0cpqe7u9kYvomFilwQv1KIPEJV1n4jpsv7NAzn4PGN+O8uly0aXdg\n15R/aEJ94mrT5f2WJ59dBTBiabaSSa42rXMz9nCJHP2z7JGesFYRrV7P6Uos\nkiDE\n=JfKa\n-----END PGP PRIVATE KEY BLOCK-----"
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
    val vasilPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: OpenPGP.js v4.5.5\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xsBNBF3wzYoBCAC10pqXSg4DdK00ztLMARZU/f0eVVCrEQIurgF9J8KMr0Tb\n" +
            "0RQKf1RJpu81nJZGfQrZAx9Ti3kXUmI+MtG/VTvejWQoOkCju5HVMShXLcpl\n" +
            "9I4STOlufG9eVlKTaDhBqEw1/XZaz1uHJ8kKeaWlBTExI5zKRGOU95Celm6G\n" +
            "rKIOKaZZDEwjIdqfamdaBXMBW9yjgFeA3hhSpHNs345GLRE8Hzok2cAt4V4E\n" +
            "pGSEYWkLQ+ROvgqve2Iaah2YvZIjumnT9H6uH/AScJBXB/OrzqeA74JAUYMc\n" +
            "PoLKXL5ni+8LGlj7BRMMoLRIhJXb288JMmBfQwoT87pmlOA2alTyRepdABEB\n" +
            "AAHNJFZhc2lsIFNva29sb3YgPHZhc2lsQGFmdGVybG9naWMuY29tPsLAdQQQ\n" +
            "AQgAHwUCXfDNigYLCQcIAwIEFQgKAgMWAgECGQECGwMCHgEACgkQ59kGhJPa\n" +
            "eXD53wf+IrkS57pFFQcMRtWE+mpBppnNA77HyUkNQoibsvrbaE7WkPLI0cJA\n" +
            "tBWgCSHCAXsYx9qeh7UJ1Eg0GOW3s22R/bWR5j32XTYK1cgLJkvhaBz2xT34\n" +
            "E33FWk1SHuH+iyMV/V2o5QXNlNNdD+w7TzODQ3rgOEM1T4TnaO3RHDqq7ju7\n" +
            "0m6pCzc8VCai8vOQjCKOQZ+2Trg8lbzKaIsVk22T2/gl1vOmb/4dV9nKgs8V\n" +
            "2zUpCHQA6w3lFht5FSpw/bT34HP3GvCaAd8Esj3Ei3Sk8I4Jx5u7xN/SQTbF\n" +
            "S+aUomcrvnKBohh/ljHBOhEe2a+tFF7qXSnbcdxl1JoZI4Dvgs7ATQRd8M2K\n" +
            "AQgA3gfzG4CciJGtUKh+VfbDYG+ZJjHcVP8bKaJLVoioW5CRQqCkkd7lspa+\n" +
            "FlX2N89rRoD7zkn7X9M1jRbr3ImuY/K3Zo4FE/Xrbse/SUzUPgp8yAltP6yo\n" +
            "B9GHvRSYxGdeex/YAX8TIhcuzuohNkw4oGVDIoj+OOE0RxNQfsSHna0hrdLU\n" +
            "kgBu2aHA2IOfRqTRTlEfWo2FV8GW2hv1j84/htioRlFRbVQe5E6Ts7+NFpqr\n" +
            "f5eOXIff3VVN35pMlX/ieqtthEjPe3onVhnVfVVdRmkbPuLD4kxmGOv9dLez\n" +
            "5OiBLI6mFibs6hxZsWHA2YeVJ+BElmXLEhf0v6KemWJURwARAQABwsBfBBgB\n" +
            "CAAJBQJd8M2KAhsMAAoJEOfZBoST2nlws+AH/R4GYs+UVwlo9MBYxv+ttkki\n" +
            "wrUTiHVVshf7eY2iqLthJQk+mdIXPM3I0xQN747PTdAqx9OO/PwqTtgeizce\n" +
            "SeCi7fOPINh0axvfT4+SeA/2g+jgyl6f+Q4A+coFMeKvfSUsK4tFRxAkz+I0\n" +
            "dt3vIDIcLmvHg4zq+hwGSvIWtBNdX346Sas1dDVu45EFniN7Ywvxqg7hr9NN\n" +
            "aFBMLUodx+d7R7NlJj6lBd9NUT67g2LKfsy3Rzfne5EGNvClxgEXwN1B3f2z\n" +
            "L7fuko5W3+2x36rwZNj4litRSEWW75CingZgwp2ZhE/3418tcErOqtvmJLte\n" +
            "4oSAAnF7vVrFCP8DDJU=\n" +
            "=Ytll\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
}