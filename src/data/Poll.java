package data;

import java.util.ArrayList;

public class Poll {

    private Integer id;
    private String name;
    private Long expireTime;
    private ArrayList<String> candidates;
    private ArrayList<String> participants;

    public Poll(Integer id, String name, Long expireTime, ArrayList<String> candidates, ArrayList<String> participants){
        this.id = id;
        this.name = name;
        this.expireTime = expireTime;
        this.candidates = candidates;
        this.participants = participants;
    }

    public String getName() {
        return this.name;
    }

    public Long getExpireTime(){
        return this.expireTime;
    }

    public ArrayList<String> getCandidates(){
        return this.candidates;
    }

    public ArrayList<String> getParticipants(){
        return this.participants;
    }
}
