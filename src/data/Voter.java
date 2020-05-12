package data;

import java.security.interfaces.RSAPublicKey;

public class Voter {

    private Integer id;
    private RSAPublicKey publicSignatureKey;

    public Voter(Integer id, RSAPublicKey publicSignatureKey){
        this.id = id;
        this.publicSignatureKey = publicSignatureKey;
    }

    public Voter(Integer id, String publicSignatureKeyString){

    }
}
