import data.Poll;
import data.Vote;
import data.Voter;
import data.VoterMap;
import helper.CryptoUtils;

import javax.json.*;
import javax.json.stream.JsonGenerator;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

import static java.lang.System.currentTimeMillis;


public class VotingAuthority {

    private static final String AUTHORITY_RESULT_ALREADY_VOTED = "AUTHORITY_RESULT_ALREADY_VOTED";
    private static final String AUTHORITY_RESULT_NOT_ELIGIBLE = "AUTHORITY_RESULT_NOT_ELIGIBLE";

    private static int saltLength = 20;

    private static RSAPrivateKey ownPrivateBlindingKey;
    private static final String ownPrivateBlindingKeyString =
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGAXyGu/7XPXIwkDpQV\n" +
                    "nkn+4VD5en2Gr+JPiJtnPZrsmll/tU7eMlpCyIyjC5s6+mbvSuYFRM9l0/1Tu4dp\n" +
                    "Fc9wv76g0hekb/k1+/WxRIgD3ul8AmJSOpJU1f9VW53jDGz4XpGfVrpAR/c26QMX\n" +
                    "xhz0E9EkXmg2Z/wZfMZmnUCAaB0CAwEAAQKBgET8BA7iJHCUH0GDGPoj5nQ1Z/Pv\n" +
                    "OtAoaExDhOYjhheXdwhfHLmewnbzpPgxpN8X7cZ+bqurScgkF6gRVZ6/Qp6kYB0V\n" +
                    "1Mch2ALdBQIQQvYxF6efHS6F3Ar3y2RlyzPhl6mWgtgMDW9hlMgooUGEhsDJYcFO\n" +
                    "PFiT0qNCp5ygb9IBAkEAs8UG3GJmk9p10InhdItyDsp1C5vCgDfG9zDUvmsrMmGf\n" +
                    "Em7CM5NUrAdey08cmnxSj0AtJn/kkwUZcLwf2vJ1vQJBAId4vAJBjrb17RHTroxi\n" +
                    "/oiGXjjYI1/n61nQjp+a5/2G79uwUZBdHyswASvcWDQDgHF5mz8Yy62f+XebzHPQ\n" +
                    "8eECQQCWw8+8Np5Ws6mJConVhzlR5EODR884Xw7zsrVJOXHR4ANbnx4pyQ8C829x\n" +
                    "zNhtS4Sl9SmolyvojSdH385Lfnp1AkAb8F516KdSPG3kG1AIS/JKncuY1ZqWEPKM\n" +
                    "12JSsFPgCZA2MqrfpxTih0f2j77xGzfGL1pBLQ/0guWkMVF9IT6BAkEApkdiJ7h6\n" +
                    "B5Uz/f6uo1IZR66igOSO16Ig9izkG6iMFx9AVCaV31oi0d39NAmdz2nDir3hrdaT\n" +
                    "NaQE8N+bgzmSfw==\n" +
                    "-----END PRIVATE KEY-----";

    private static RSAPublicKey ownPublicBlindingKey;
    private static final String ownPublicBlindingKeyString =
            "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF8hrv+1z1yMJA6UFZ5J/uFQ+Xp9\n" +
                    "hq/iT4ibZz2a7JpZf7VO3jJaQsiMowubOvpm70rmBUTPZdP9U7uHaRXPcL++oNIX\n" +
                    "pG/5Nfv1sUSIA97pfAJiUjqSVNX/VVud4wxs+F6Rn1a6QEf3NukDF8Yc9BPRJF5o\n" +
                    "Nmf8GXzGZp1AgGgdAgMBAAE=\n" +
                    "-----END PUBLIC KEY-----";

    private static HashMap<Integer, Poll> polls = new HashMap<>();
    private static VoterMap voters = new VoterMap();

    private static HashMap<Integer, HashMap<Integer, Vote>> alreadyVotedLists = new HashMap<>();
    private static HashMap<Integer, VoterMap> participantLists = new HashMap<>();

    private static final SecureRandom random = new SecureRandom();

    public void start() {
        createKeyObjectsFromStrings();

        readVoterFile();
        readPollFile();
        readVotesFile();

        // TODO: for now register test voters
        registerVoter(12345678, "-----BEGIN PUBLIC KEY-----\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPILUbSbMPnzlEWskxKYPD4rvP\n" +
                "k3i+DxtIFiRZrvoKOZG+FWt5LVDcW3+mX2vhQtZgTXB7TJf8xhgniXTQvN7kXFNt\n" +
                "Np+7xD4+XqmcUF8GRGf8/ZN/O1tB4UOpEIZ5wLnk0LqXQR12sZz412WdhAqoWq5g\n" +
                "41yOFCSAwdnU9PdqXwIDAQAB\n" +
                "-----END PUBLIC KEY-----");

        long lastTime = System.currentTimeMillis();

        try (ServerSocket serverSocket = new ServerSocket(6868)) {
            while (true) {
                // Every 5 minutes save data to disk
                long currentTime = System.currentTimeMillis();
                long deltaTime = (currentTime - lastTime) / 1000L;
                if(deltaTime > 300L){
                    writeVoterFile();
                    writePollFile();
                    writeVotesFile();
                    lastTime = currentTime;
                }
                System.out.println("Polls");
                for(Integer pollId : polls.keySet()){
                    System.out.println(pollId.toString());
                }
                System.out.println("Voters");
                for(Integer voterId : voters.keySet()){
                    System.out.println(voterId.toString());
                }

                System.out.println("Waiting for client to connect...");
                Socket client = serverSocket.accept();
                System.out.println("Client connected");
                ClientHandler clientHandler = new ClientHandler(client);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            System.err.println("Failed opening server socket.");
            e.printStackTrace();
        }
    }

    private void createKeyObjectsFromStrings() {
        ownPrivateBlindingKey = (RSAPrivateKey) CryptoUtils.createRSAKeyFromString(ownPrivateBlindingKeyString);
        ownPublicBlindingKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(ownPublicBlindingKeyString);
    }

    // Reads 'voters' file, then builds 'voters'
    private void readVoterFile(){
        voters = new VoterMap();

        File votersFile = new File(System.getProperty("user.dir") + "/voters.json");
        if(!votersFile.exists()){
            System.out.println("Voters file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray voterArray = null;
        try (FileInputStream fis = new FileInputStream(votersFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            voterArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + votersFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read voters file.");
            e.printStackTrace();
        }

        if(voterArray == null){
            System.out.println("Voters file was empty.");
            return;
        }

        for(JsonValue voterValue : voterArray){
            JsonObject voterObject = voterValue.asJsonObject();

            Integer voterId = voterObject.getInt("id");
            String publicSignatureKeyString = voterObject.getString("public key");

            Voter voter = new Voter(voterId, publicSignatureKeyString);
            voters.put(voterId, voter);
        }

        System.out.println("Reading voters file completed successfully.");
    }

    // Reads 'polls' file, then builds 'polls' and'participantLists'
    private void readPollFile(){
        polls = new HashMap<Integer, Poll>();
        participantLists = new HashMap<Integer, VoterMap>();

        File pollsFile = new File(System.getProperty("user.dir") + "/polls.json");
        if(!pollsFile.exists()){
            System.out.println("Polls file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray pollArray = null;
        try (FileInputStream fis = new FileInputStream(pollsFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            pollArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + pollsFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read polls file.");
            e.printStackTrace();
        }

        if(pollArray == null){
            System.out.println("Poll file was empty.");
            return;
        }

        for(JsonValue pollValue : pollArray){
            JsonObject pollObject = pollValue.asJsonObject();

            Integer pollId = pollObject.getInt("id");
            String pollName = pollObject.getString("name");
            Long expireTime = Long.parseLong(pollObject.getString("expire time"));

            JsonArray candidateArray = pollObject.getJsonArray("candidates");
            ArrayList<String> candidates = new ArrayList<String>();
            for(JsonValue candidateValue : candidateArray){
                JsonObject candidateObject = candidateValue.asJsonObject();
                String candidateName = candidateObject.getString("name");
                candidates.add(candidateName);
            }

            JsonArray participantArray = pollObject.getJsonArray("participants");
            ArrayList<Integer> participants = new ArrayList<>();
            for(JsonValue participantValue : participantArray){
                JsonObject participantObject = participantValue.asJsonObject();
                Integer participantId = participantObject.getInt("id");
                participants.add(participantId);
            }

            Poll poll = new Poll(pollId, pollName, expireTime, candidates, participants);
            polls.put(pollId, poll);

            VoterMap participantList;
            if (participantLists.containsKey(pollId)) {
                participantList = participantLists.get(pollId);
            } else {
                participantList = new VoterMap();
                participantLists.put(pollId, participantList);
            }

            for(Integer participantId : participants){
                Voter voter = voters.get(participantId); // TODO: nullt ad vissza
                participantList.put(voter.getId(), voter);
            }
        }

        System.out.println("Reading polls file completed successfully.");
    }

    // Reads 'votes' file, then builds 'alreadyVotedLists'
    private void readVotesFile(){
        alreadyVotedLists = new HashMap<Integer, HashMap<Integer, Vote>>();

        File votesFile = new File(System.getProperty("user.dir") + "/votes.json");
        if(!votesFile.exists()){
            System.out.println("Votes file doesn't exist.");
            return;
        }

        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonReaderFactory jrf = Json.createReaderFactory(properties);

        JsonArray voteArray = null;
        try (FileInputStream fis = new FileInputStream(votesFile);
             InputStreamReader isr = new InputStreamReader(fis);
             JsonReader jsonReader = jrf.createReader(isr)) {

            voteArray = jsonReader.readArray();

        } catch (FileNotFoundException e) {
            System.err.println("Couldn't find file: " + votesFile.getPath());
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't read votes file.");
            e.printStackTrace();
        }

        if(voteArray == null){
            System.out.println("Votes file was empty.");
            return;
        }

        for(JsonValue voteValue : voteArray){
            JsonObject voteObject = voteValue.asJsonObject();

            Integer pollId = voteObject.getInt("poll id");
            Integer voterId = voteObject.getInt("voter id");
            String blindedCommitment = voteObject.getString("blinded commitment");
            String signature = voteObject.getString("signature");

            Vote vote = new Vote(pollId, voterId, blindedCommitment, signature);

            HashMap<Integer, Vote> alreadyVotedList;
            if (alreadyVotedLists.containsKey(pollId)) {
                alreadyVotedList = alreadyVotedLists.get(pollId);
            } else {
                alreadyVotedList = new HashMap<>();
                alreadyVotedLists.put(pollId, alreadyVotedList);
            }
            alreadyVotedList.put(voterId, vote);
        }

        System.out.println("Reading voters file completed successfully.");
    }

    private void writeVoterFile(){
        JsonArrayBuilder voterArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voterBuilder = Json.createObjectBuilder();

        for(Map.Entry<Integer, Voter> voterEntry : voters.entrySet()) {
            voterBuilder.add("id", voterEntry.getKey());
            voterBuilder.add("public key", voterEntry.getValue().getPublicSignatureKeyString());
            voterArrayBuilder.add(voterBuilder);
        }

        JsonArray voterArray = voterArrayBuilder.build();

        File votersFile = new File(System.getProperty("user.dir") + "/voters.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(votersFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(voterArray);

        } catch (FileNotFoundException e) {
            System.err.println("Voters file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write voters file.");
            e.printStackTrace();
        }
        System.out.println("Writing voters file completed successfully.");
    }

    private void writePollFile(){
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder candidateArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder candidateBuilder = Json.createObjectBuilder();
        JsonArrayBuilder participantArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder participantBuilder = Json.createObjectBuilder();

        for(Map.Entry<Integer, Poll> pollEntry : polls.entrySet()) {
            pollBuilder.add("id", pollEntry.getKey());
            pollBuilder.add("name", pollEntry.getValue().getName());
            pollBuilder.add("expire time", pollEntry.getValue().getExpireTime().toString());

            for(String candidate : pollEntry.getValue().getCandidates()) {
                candidateBuilder.add("name", candidate);
                candidateArrayBuilder.add(candidateBuilder);
            }
            pollBuilder.add("candidates", candidateArrayBuilder);

            for(Integer participant : pollEntry.getValue().getParticipants()){
                participantBuilder.add("id", participant);
                participantArrayBuilder.add(participantBuilder);
            }
            pollBuilder.add("participants", participantArrayBuilder);

            pollArrayBuilder.add(pollBuilder);
        }

        JsonArray pollArray = pollArrayBuilder.build();

        File pollsFile = new File(System.getProperty("user.dir") + "/polls.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(pollsFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(pollArray);

        } catch (FileNotFoundException e) {
            System.err.println("Polls file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't write polls file.");
            e.printStackTrace();
        }
        System.out.println("Writing polls file completed successfully.");
    }

    private void writeVotesFile(){
        JsonArrayBuilder voteArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voteBuilder = Json.createObjectBuilder();

        for(Map.Entry<Integer, HashMap<Integer, Vote>> alreadyVotedEntry : alreadyVotedLists.entrySet()) {
            voteBuilder.add("poll id", alreadyVotedEntry.getKey());
            for(Map.Entry<Integer, Vote> voteEntry : alreadyVotedEntry.getValue().entrySet()){
                voteBuilder.add("voter id", voteEntry.getKey());
                Vote vote = voteEntry.getValue();
                voteBuilder.add("blinded commitment", Base64.getEncoder().encodeToString(vote.getBlindedCommitment()));
                voteBuilder.add("signature", Base64.getEncoder().encodeToString(vote.getSignature()));
                voteArrayBuilder.add(voteBuilder);
            }

        }

        JsonArray voteArray = voteArrayBuilder.build();

        File votesFile = new File(System.getProperty("user.dir") + "/votes.json");

        // Format JSON to readable form instead of one line
        final Map<String, Object> properties = new HashMap<String, Object>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        JsonWriterFactory jwf = Json.createWriterFactory(properties);

        try (FileOutputStream fos = new FileOutputStream(votesFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos);
             JsonWriter jsonWriter = jwf.createWriter(osw)) {

            jsonWriter.writeArray(voteArray);

        } catch (FileNotFoundException e) {
            System.err.println("Votes file not found.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Failed writing votes file.");
            e.printStackTrace();
        }
        System.out.println("Writing votes file completed successfully.");
    }

    private void registerVoter(Integer voterId, String publicSignatureKeyString){
        Voter voter = new Voter(voterId, publicSignatureKeyString);
        voters.put(voterId, voter);
        writeVoterFile();
    }

    private class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private String resultForClient;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            ArrayList<String> lines = new ArrayList<String>();
            InputStreamReader isr;
            BufferedReader in;
            try {
                isr = new InputStreamReader(clientSocket.getInputStream());
                in = new BufferedReader(isr);
                System.out.println("Waiting for data...");
                String line;
                while ((line = in.readLine()) != null) {
                    lines.add(line);
                }
                System.out.println("Received data from client.");
            } catch (IOException e) {
                System.err.println("Failed receiving data from client.");
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.shutdownInput();
                } catch (IOException ex) {
                    System.err.println("Problem while shutting down input stream.");
                    ex.printStackTrace();
                }
            }
            if (lines.isEmpty()) {
                System.out.println("Invalid data received");
                return;
            }

            Iterator<String> linesIter = lines.iterator();
            String command = linesIter.next();

            switch (command) {
                case "create poll": {
                    String pollName = linesIter.next();
                    Long expireTime = Long.parseLong(linesIter.next());
                    ArrayList<String> candidates = new ArrayList<>();
                    while (linesIter.hasNext()) {
                        candidates.add(linesIter.next());
                    }
                    createPoll(pollName, expireTime, candidates);
                    break;
                }
                case "fetch polls": {
                    sendPollsToClient();
                    break;
                }
                case "cast vote": {
                    Integer pollId = Integer.parseInt(linesIter.next());
                    Integer voterId = Integer.parseInt(linesIter.next());
                    String blindedCommitmentString = linesIter.next();
                    String signatureString = linesIter.next();

                    System.out.println("Poll ID: " + pollId);
                    System.out.println("Client ID: " + voterId);
                    System.out.println("Blinded commitment: " + blindedCommitmentString);
                    System.out.println("Signature of blinded commitment: " + signatureString);

                    handleVoteCast(pollId, voterId, blindedCommitmentString, signatureString);
                    break;
                }
            }
        }

        private void createPoll(String pollName, Long expireTime, ArrayList<String> candidates) {
            Integer pollId = random.nextInt(Integer.MAX_VALUE);
            while (polls.containsKey(pollId)) {
                pollId = random.nextInt(Integer.MAX_VALUE);
            }

            System.out.println("Poll created with ID: " + pollId);

            // TODO: Everyone is participant on a new poll for now
            List<Voter> voterList = new ArrayList<Voter>(voters.values());
            ArrayList<Integer> voterIds = new ArrayList<>();
            for(Voter voter : voterList){
                voterIds.add(voter.getId());
            }
            Poll poll = new Poll(pollId, pollName, expireTime, candidates, voterIds);
            participantLists.put(pollId, (VoterMap) voters.clone());

            polls.put(pollId, poll);
            writePollFile();
        }

        private void sendPollsToClient() {
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
                System.out.println("Sending polls to client...");
                if(polls.isEmpty()){
                    out.println("no polls");
                    return;
                }
                out.println("sending polls");
                for (Map.Entry<Integer, Poll> pollEntry : polls.entrySet()) {
                    Integer pollId = pollEntry.getKey();
                    Poll poll = pollEntry.getValue();

                    out.println(pollId.toString());
                    out.println(poll.getName());
                    out.println(poll.getExpireTime().toString());
                    StringBuilder candidateLine = new StringBuilder();
                    for (String candidate : poll.getCandidates()) {
                        candidateLine.append(candidate).append(";");
                    }
                    out.println(candidateLine);
                }
                System.out.println("Polls sent");
            } catch (IOException e) {
                System.out.println("Failed sending polls to client.");
                e.printStackTrace();
            }
        }

        private void handleVoteCast(Integer pollId, Integer voterId, String blindedCommitmentString, String signatureString) {
            // Check if poll exists
            if (!polls.containsKey(pollId)) {
                System.out.println("No poll with the given ID exists.");
                return;
            }
            if (!participantLists.containsKey(pollId)) {
                System.err.println("'participantLists' inconsistent with 'polls'");
                return; // TODO: exception
            }

            // Check vote eligibility
            if (!participantLists.get(pollId).containsKey(voterId)) {
                System.out.println("Client is NOT eligible to vote.");
                resultForClient = AUTHORITY_RESULT_NOT_ELIGIBLE;
                sendResultToClient();
                return;
            }
            System.out.println("Client is eligible to vote.");

            // Check signature
            Voter voter = participantLists.get(pollId).get(voterId);
            RSAPublicKey verificationKey = voter.getPublicSignatureKey();
            byte[] blindedCommitment = Base64.getDecoder().decode(blindedCommitmentString);
            byte[] signature = Base64.getDecoder().decode(signatureString);
            if (!CryptoUtils.verifySHA256withRSAandPSS(verificationKey, blindedCommitment, signature, saltLength)) {
                System.out.println("Signature not valid.");
                return;
            }
            System.out.println("Signature verified.");

            // Check if already voted
            HashMap<Integer, Vote> alreadyVotedList;
            if (alreadyVotedLists.containsKey(pollId)) {
                if (alreadyVotedLists.get(pollId).containsKey(voterId)) {
                    System.out.println("Voter has already voted before.");
                    resultForClient = AUTHORITY_RESULT_ALREADY_VOTED;
                    sendResultToClient();
                    return;
                }
                alreadyVotedList = alreadyVotedLists.get(pollId);
            } else {
                alreadyVotedList = new HashMap<>();
                alreadyVotedLists.put(pollId, alreadyVotedList);
            }
            System.out.println("Client hasn't voted before.");
            Vote vote = new Vote(pollId, voterId, blindedCommitment, signature);
            alreadyVotedList.put(voterId, vote);

            writeVotesFile();

            // Sign blinded commitment
            byte[] authSignedBlindedCommitment = CryptoUtils.signBlindedRSA(ownPrivateBlindingKey, blindedCommitment);
            System.out.println("Blinded commitment signed by authority: " + Base64.getEncoder().encodeToString(authSignedBlindedCommitment));
            resultForClient = Base64.getEncoder().encodeToString(authSignedBlindedCommitment);
            sendResultToClient();
        }

        private void sendResultToClient() {
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
                System.out.println("Sending to client...");
                out.println(resultForClient);
                System.out.println("Data sent");
            } catch (IOException e) {
                System.err.println("Failed sending data to client.");
                e.printStackTrace();
            }
        }
    }
}
