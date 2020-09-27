package data;

import helper.CryptoUtils;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class Voter {

    private String id;
    private PublicKey verificationKey;

    public Voter(String id, String verificationKeyString) {
        this.id = id;
        this.verificationKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(verificationKeyString);
    }

    public PublicKey getVerificationKey() {
        return this.verificationKey;
    }

    public String getVerificationKeyString() {
        if (verificationKey.getFormat().equals("X.509")) {
            return "-----BEGIN PUBLIC KEY-----" + Base64.getEncoder().encodeToString(
                    this.verificationKey.getEncoded()) + "-----END PUBLIC KEY-----";
        } else {
            return "-----BEGIN RSA PUBLIC KEY-----" + Base64.getEncoder().encodeToString(
                    this.verificationKey.getEncoded()) + "-----END RSA PUBLIC KEY-----";
        }
    }

    public String getId() {
        return this.id;
    }
}
