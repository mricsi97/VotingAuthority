import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import data.Poll;
import data.Vote;
import data.Voter;
import helper.CryptoUtils;

import javax.json.*;
import javax.json.stream.JsonGenerator;
import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class VotingAuthority {

    private static final String AUTHORITY_RESULT_ALREADY_VOTED = "AUTHORITY_RESULT_ALREADY_VOTED";
    private static final String AUTHORITY_RESULT_NOT_ELIGIBLE = "AUTHORITY_RESULT_NOT_ELIGIBLE";
    private static final String AUTHORITY_RESULT_INVALID_SIGNATURE = "AUTHORITY_RESULT_INVALID_SIGNATURE";
    private static final String AUTHORITY_RESULT_AUTH_SUCCESS = "AUTHORITY_RESULT_AUTH_SUCCESS";
    private static final String AUTHORITY_RESULT_AUTH_FAILURE = "AUTHORITY_RESULT_AUTH_FAILURE";

    private static RSAPrivateKey signingKey;

    private static final ConcurrentHashMap<String, Voter> voters = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, Poll> polls = new ConcurrentHashMap<>();

    private static final ConcurrentHashMap<Integer, ConcurrentHashMap<String, Vote>> alreadyVotedLists = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, ConcurrentHashMap<String, Voter>> participantLists = new ConcurrentHashMap<>();

    private static final SecureRandom random = new SecureRandom();

    public void start() {
        loadSigningKey();
        readVoterFile();
        readPollFile();
        readVotesFile();

        long lastTime = System.currentTimeMillis();

        try (ServerSocket serverSocket = new ServerSocket(6868)) {
            while (true) {
                // Every 5 minutes save data to disk
                long currentTime = System.currentTimeMillis();
                long deltaTime = (currentTime - lastTime) / 1000L;
                if (deltaTime > 60L * 5) {
                    writeVoterFile();
                    writePollFile();
                    writeVotesFile();
                    lastTime = currentTime;
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

    private void loadSigningKey() {
        final File keyFile = new File(System.getProperty("user.dir") + "/authority_private.pem");

        StringBuilder pemBuilder = new StringBuilder();
        try (FileReader fr = new FileReader(keyFile);
             BufferedReader br = new BufferedReader(fr)) {
            String line;
            while((line = br.readLine()) != null) {
                pemBuilder.append(line);
            }
        } catch (IOException e) {
            System.err.println("Failed reading signing key file.");
            e.printStackTrace();
        }

        String pem = pemBuilder.toString();
        signingKey = (RSAPrivateKey) CryptoUtils.createRSAKeyFromString(pem);
    }

    // Reads 'voters.json' file, then builds 'voters'
    private void readVoterFile() {
        File votersFile = new File(System.getProperty("user.dir") + "/voters.json");
        if (!votersFile.exists()) {
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

        if (voterArray == null) {
            System.out.println("Voters file was empty.");
            return;
        }

        for (JsonValue voterValue : voterArray) {
            JsonObject voterObject = voterValue.asJsonObject();

            String voterId = voterObject.getString("id");
            String verificationKeyString = voterObject.getString("verification key");

            Voter voter = new Voter(voterId, verificationKeyString);
            voters.put(voterId, voter);
        }

        System.out.println("Reading voters file completed successfully.");
    }

    // Reads 'polls.json' file, then builds 'polls' and 'participantLists'
    private void readPollFile() {
        File pollsFile = new File(System.getProperty("user.dir") + "/polls.json");
        if (!pollsFile.exists()) {
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

        if (pollArray == null) {
            System.out.println("Poll file was empty.");
            return;
        }

        for (JsonValue pollValue : pollArray) {
            JsonObject pollObject = pollValue.asJsonObject();

            Integer pollId = pollObject.getInt("id");
            String pollName = pollObject.getString("name");
            Long expireTime = Long.parseLong(pollObject.getString("expire time"));

            JsonArray candidateArray = pollObject.getJsonArray("candidates");
            ArrayList<String> candidates = new ArrayList<String>();
            for (JsonValue candidateValue : candidateArray) {
                JsonObject candidateObject = candidateValue.asJsonObject();
                String candidateName = candidateObject.getString("name");
                candidates.add(candidateName);
            }

            JsonArray participantArray = pollObject.getJsonArray("participants");
            ArrayList<String> participants = new ArrayList<>();
            for (JsonValue participantValue : participantArray) {
                JsonObject participantObject = participantValue.asJsonObject();
                String participantId = participantObject.getString("id");
                participants.add(participantId);
            }

            Poll poll = new Poll(pollId, pollName, expireTime, candidates, participants);
            polls.put(pollId, poll);

            ConcurrentHashMap<String, Voter> participantList;
            if (participantLists.containsKey(pollId)) {
                participantList = participantLists.get(pollId);
            } else {
                participantList = new ConcurrentHashMap<>();
                participantLists.put(pollId, participantList);
            }

            for (String participantId : participants) {
                Voter voter = voters.get(participantId);
                participantList.put(voter.getId(), voter);
            }
        }

        System.out.println("Reading polls file completed successfully.");
    }

    // Reads 'votes.json' file, then builds 'alreadyVotedLists'
    private void readVotesFile() {
        File votesFile = new File(System.getProperty("user.dir") + "/votes.json");
        if (!votesFile.exists()) {
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

        if (voteArray == null) {
            System.out.println("Votes file was empty.");
            return;
        }

        for (JsonValue voteValue : voteArray) {
            JsonObject voteObject = voteValue.asJsonObject();

            Integer pollId = voteObject.getInt("poll id");
            String voterId = voteObject.getString("voter id");
            String blindedCommitment = voteObject.getString("blinded commitment");
            String signature = voteObject.getString("signature");

            Vote vote = new Vote(pollId, voterId, blindedCommitment, signature);

            ConcurrentHashMap<String, Vote> alreadyVotedList;
            if (alreadyVotedLists.containsKey(pollId)) {
                alreadyVotedList = alreadyVotedLists.get(pollId);
            } else {
                alreadyVotedList = new ConcurrentHashMap<>();
                alreadyVotedLists.put(pollId, alreadyVotedList);
            }
            alreadyVotedList.put(voterId, vote);
        }

        System.out.println("Reading voters file completed successfully.");
    }

    // Writes 'voters.json' file using 'voters'
    private void writeVoterFile() {
        JsonArrayBuilder voterArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voterBuilder = Json.createObjectBuilder();

        for (Map.Entry<String, Voter> voterEntry : voters.entrySet()) {
            voterBuilder.add("id", voterEntry.getKey());
            voterBuilder.add("verification key", voterEntry.getValue().getVerificationKeyString());
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

    // Writes 'polls.json' file using 'polls'
    private void writePollFile() {
        JsonArrayBuilder pollArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder pollBuilder = Json.createObjectBuilder();
        JsonArrayBuilder candidateArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder candidateBuilder = Json.createObjectBuilder();
        JsonArrayBuilder participantArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder participantBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, Poll> pollEntry : polls.entrySet()) {
            pollBuilder.add("id", pollEntry.getKey());
            pollBuilder.add("name", pollEntry.getValue().getName());
            pollBuilder.add("expire time", pollEntry.getValue().getExpireTime().toString());

            for (String candidate : pollEntry.getValue().getCandidates()) {
                candidateBuilder.add("name", candidate);
                candidateArrayBuilder.add(candidateBuilder);
            }
            pollBuilder.add("candidates", candidateArrayBuilder);

            for (String participant : pollEntry.getValue().getParticipants()) {
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

    // Write 'votes.json' file using 'alreadyVotedLists'
    private void writeVotesFile() {
        JsonArrayBuilder voteArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder voteBuilder = Json.createObjectBuilder();

        for (Map.Entry<Integer, ConcurrentHashMap<String, Vote>> alreadyVotedEntry : alreadyVotedLists.entrySet()) {
            voteBuilder.add("poll id", alreadyVotedEntry.getKey());
            for (Map.Entry<String, Vote> voteEntry : alreadyVotedEntry.getValue().entrySet()) {
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

    private void registerVoter(String voterId, String verificationKeyString) {
        Voter voter = new Voter(voterId, verificationKeyString);
        voters.put(voterId, voter);
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
                    String idTokenString = linesIter.next();
                    String blindedCommitmentString = linesIter.next();
                    String signatureString = linesIter.next();

                    System.out.println("Poll ID: " + pollId);
                    System.out.println("Client ID token: " + idTokenString);
                    System.out.println("Blinded commitment: " + blindedCommitmentString);
                    System.out.println("Signature of blinded commitment: " + signatureString);

                    handleVoteCast(pollId, idTokenString, blindedCommitmentString, signatureString);
                    break;
                }
                case "authentication": {
                    String idTokenString = linesIter.next();
                    String verificationKeyString = linesIter.next();
                    handleAuthentication(idTokenString, verificationKeyString);
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

            // Everyone is participant on a new poll for now
            List<Voter> voterList = new ArrayList<Voter>(voters.values());
            ArrayList<String> voterIds = new ArrayList<>();
            for (Voter voter : voterList) {
                voterIds.add(voter.getId());
            }
            Poll poll = new Poll(pollId, pollName, expireTime, candidates, voterIds);
            participantLists.put(pollId, new ConcurrentHashMap<>(voters));

            polls.put(pollId, poll);
        }

        private void sendPollsToClient() {
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
                System.out.println("Sending polls to client...");
                if (polls.isEmpty()) {
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

        private void handleVoteCast(Integer pollId, String idTokenString, String blindedCommitmentString, String signatureString) {
            // Check client's ID token for validity
            GoogleIdToken idToken = verifyIdToken(idTokenString);
            if (idToken == null) {
                System.out.println("Client authentication failed.");
                resultForClient = AUTHORITY_RESULT_AUTH_FAILURE;
                sendResultToClient();
                return;
            }
            System.out.println("Client authenticated.");
            String userId = idToken.getPayload().getSubject();

            // Check if poll exists
            if (!polls.containsKey(pollId)) {
                System.out.println("No poll with the given ID exists.");
                return;
            }
            if (!participantLists.containsKey(pollId)) {
                System.err.println("'participantLists' inconsistent with 'polls'");
                return;
            }

            // Check vote eligibility
            if (!participantLists.get(pollId).containsKey(userId)) {
                System.out.println("Client is NOT eligible to vote.");
                resultForClient = AUTHORITY_RESULT_NOT_ELIGIBLE;
                sendResultToClient();
                return;
            }
            System.out.println("Client is eligible to vote.");

            // Check signature
            Voter voter = voters.get(userId);
            PublicKey verificationKey = voter.getVerificationKey();
            byte[] blindedCommitment = Base64.getDecoder().decode(blindedCommitmentString);
            byte[] signature = Base64.getDecoder().decode(signatureString);
            if (!CryptoUtils.verifySHA256withRSAandPSS(verificationKey, blindedCommitment, signature)) {
                System.out.println("Signature NOT valid.");
                resultForClient = AUTHORITY_RESULT_INVALID_SIGNATURE;
                sendResultToClient();
                return;
            }
            System.out.println("Signature verified.");

            // Check if already voted
            ConcurrentHashMap<String, Vote> alreadyVotedList;
            if (alreadyVotedLists.containsKey(pollId)) {
                if (alreadyVotedLists.get(pollId).containsKey(userId)) {
                    System.out.println("Voter has already voted before.");
                    resultForClient = AUTHORITY_RESULT_ALREADY_VOTED;
                    sendResultToClient();
                    return;
                }
                alreadyVotedList = alreadyVotedLists.get(pollId);
            } else {
                alreadyVotedList = new ConcurrentHashMap<>();
                alreadyVotedLists.put(pollId, alreadyVotedList);
            }
            System.out.println("Client hasn't voted before.");
            Vote vote = new Vote(pollId, userId, blindedCommitment, signature);
            alreadyVotedList.put(userId, vote);

            // Sign blinded commitment
            byte[] authSignedBlindedCommitment = CryptoUtils.signBlindedRSA(signingKey, blindedCommitment);
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

        private void handleAuthentication(String idTokenString, String verificationKeyString) {
            GoogleIdToken idToken = verifyIdToken(idTokenString);
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();

                String userId = payload.getSubject();
                if(!voters.containsKey(userId)) {
                    registerVoter(userId, verificationKeyString);
                }

                resultForClient = AUTHORITY_RESULT_AUTH_SUCCESS;
            } else {
                resultForClient = AUTHORITY_RESULT_AUTH_FAILURE;
            }
            sendResultToClient();
        }
    }

    private GoogleIdToken verifyIdToken(String idTokenString) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    GoogleNetHttpTransport.newTrustedTransport(), new JacksonFactory())
                    .setAudience(Collections.singletonList("1038869177199-v7tkrec204t60tfjkufdn8ngguqg8ha5.apps.googleusercontent.com"))
                    .build();

            return verifier.verify(idTokenString);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
