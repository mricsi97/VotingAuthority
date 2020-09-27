package data;

import java.util.Base64;

public class Vote {
    private Integer pollId;
    private String voterId;
    private byte[] blindedCommitment;
    private byte[] signature;

    public Vote(Integer pollId, String voterId, byte[] blindedCommitment, byte[] signature){
        this.pollId = pollId;
        this.voterId = voterId;
        this.blindedCommitment = blindedCommitment;
        this.signature = signature;
    }

    public Vote(Integer pollId, String voterId, String blindedCommitment, String signature){
        this.pollId = pollId;
        this.voterId = voterId;
        this.blindedCommitment = Base64.getDecoder().decode(blindedCommitment);
        this.signature = Base64.getDecoder().decode(signature);
    }

    public byte[] getBlindedCommitment(){
        return this.blindedCommitment;
    }

    public byte[] getSignature(){
        return this.signature;
    }
}
