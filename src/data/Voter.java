package data;

import helper.CryptoUtils;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class Voter {

    private Integer id;
    private RSAPublicKey publicSignatureKey;

    public Voter(Integer id, RSAPublicKey publicSignatureKey){
        this.id = id;
        this.publicSignatureKey = publicSignatureKey;
    }

    public Voter(Integer id, String publicSignatureKeyString){
        this.id = id;
        this.publicSignatureKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(publicSignatureKeyString);
    }

    public RSAPublicKey getPublicSignatureKey(){
        return this.publicSignatureKey;
    }

    public String getPublicSignatureKeyString(){
        return Base64.getEncoder().encodeToString(this.publicSignatureKey.getEncoded());
    }

    public Integer getId(){
        return this.id;
    }
}
