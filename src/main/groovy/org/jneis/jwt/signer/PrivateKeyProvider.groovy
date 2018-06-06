package org.jneis.jwt.signer

import com.auth0.jwt.interfaces.RSAKeyProvider
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import org.bouncycastle.util.io.pem.PemReader
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class PrivateKeyProvider implements RSAKeyProvider {

    static final rsa = 'RSA'

    @Value('${KID}')
    String kid

    @Value('${PRIVATE_KEY_FILENAME}')
    String filename

    @Override
    RSAPublicKey getPublicKeyById(String keyId) {
        throw new IllegalStateException('Public key is owned by target API')
    }

    @Override
    RSAPrivateKey getPrivateKey() {
        def file = Paths.get filename
        def buffer = Files.newBufferedReader file
        def reader = new PemReader(buffer)
        def pem = reader.readPemObject()
        def spec = new PKCS8EncodedKeySpec(pem.content)
        def keys = KeyFactory.getInstance rsa

        return (RSAPrivateKey) keys.generatePrivate(spec)
    }

    @Override
    String getPrivateKeyId() {
        return kid
    }

}
