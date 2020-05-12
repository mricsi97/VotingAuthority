import data.Voter;
import data.VoterList;
import helper.CryptoUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


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

    private static HashMap<Integer, RSAPublicKey> clientPublicSignatureKeys;
    private static final Map<Integer, String> clientPublicSignatureKeyStrings = Map.ofEntries(
            Map.entry(12345678,"-----BEGIN PUBLIC KEY-----\n" +
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPILUbSbMPnzlEWskxKYPD4rvP\n" +
                    "k3i+DxtIFiRZrvoKOZG+FWt5LVDcW3+mX2vhQtZgTXB7TJf8xhgniXTQvN7kXFNt\n" +
                    "Np+7xD4+XqmcUF8GRGf8/ZN/O1tB4UOpEIZ5wLnk0LqXQR12sZz412WdhAqoWq5g\n" +
                    "41yOFCSAwdnU9PdqXwIDAQAB\n" +
                    "-----END PUBLIC KEY-----")
    );

    /*private static HashMap<Integer, VoterList> participantLists;
    private static final Map<Integer, List<Voter>> participantListExamples = Map.ofEntries(
            Map.entry(
                    0, List.of(
                            new Voter(12345678, "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPILUbSbMPnzlEWskxKYPD4rvP\n" +
                    "k3i+DxtIFiRZrvoKOZG+FWt5LVDcW3+mX2vhQtZgTXB7TJf8xhgniXTQvN7kXFNt\n" +
                    "Np+7xD4+XqmcUF8GRGf8/ZN/O1tB4UOpEIZ5wLnk0LqXQR12sZz412WdhAqoWq5g\n" +
                    "41yOFCSAwdnU9PdqXwIDAQAB\n" +
                    "-----END PUBLIC KEY-----"),
                            new Voter(12345679, "asd"))));*/

    private static ArrayList<Integer> alreadyVoted = new ArrayList<>();

    public void start() {
        createKeyObjectsFromStrings();

        try (ServerSocket serverSocket = new ServerSocket(6868)) {
            while(true){
                System.out.println("Waiting for client to connect...");
                Socket client = serverSocket.accept();
                System.out.println("Client connected");
                ClientHandler clientHandler = new ClientHandler(client);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createKeyObjectsFromStrings() {
        ownPrivateBlindingKey = (RSAPrivateKey) CryptoUtils.createRSAKeyFromString(ownPrivateBlindingKeyString);
        ownPublicBlindingKey = (RSAPublicKey) CryptoUtils.createRSAKeyFromString(ownPublicBlindingKeyString);

        clientPublicSignatureKeys = new HashMap<>();
        for(Map.Entry<Integer, String> clientKeyStringsEntry : clientPublicSignatureKeyStrings.entrySet()){
                clientPublicSignatureKeys.put(clientKeyStringsEntry.getKey(), (RSAPublicKey) CryptoUtils.createRSAKeyFromString(clientKeyStringsEntry.getValue()));
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private String resultForClient;
        private Boolean everythingOk;

        public ClientHandler(Socket socket){
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            String line = null;
            InputStreamReader isr = null;
            BufferedReader in = null;
            try {
                isr = new InputStreamReader(clientSocket.getInputStream());
                in = new BufferedReader(isr);
                System.out.println("Waiting for data...");
                line = in.readLine();
                System.out.println("Received data");
            } catch (IOException ex) {
                System.err.println("Failed receiving data from client.");
                ex.printStackTrace();
            } finally {
                try {
                    clientSocket.shutdownInput();
                } catch (IOException ex) {
                    System.err.println("Problem while shutting down input stream.");
                    ex.printStackTrace();
                }
            }
            if(line == null){
                System.out.println("Invalid data received");
                return;
            }

            Integer pollId = Integer.parseInt(line.substring(0, 7));
            Integer clientId = Integer.parseInt(line.substring(7, 15));
            String blindedCommitmentString = line.substring(15, 187);
            String signedBlindedCommitmentString = line.substring(187);

            System.out.println("Client ID: " + clientId);
            System.out.println("Blinded commitment: " + blindedCommitmentString);
            System.out.println("Signature of blinded commitment: " + signedBlindedCommitmentString);

            // Check vote eligibility
            if(!clientPublicSignatureKeys.containsKey(clientId)) {
                System.out.println("Client is NOT eligible to vote.");
                resultForClient = AUTHORITY_RESULT_NOT_ELIGIBLE;
                sendResultToClient();
                return;
            }
            System.out.println("Client is eligible to vote.");

            // Check signature
            RSAPublicKey verificationKey =  clientPublicSignatureKeys.get(clientId);
            byte[] blindedCommitment = Base64.getDecoder().decode(blindedCommitmentString);
            byte[] signedBlindedCommitment = Base64.getDecoder().decode(signedBlindedCommitmentString);
            if(!CryptoUtils.verifySHA256withRSAandPSS(verificationKey, blindedCommitment, signedBlindedCommitment, saltLength)) {
                System.out.println("Signature not valid.");
                return;
            }
            System.out.println("Signature verified.");

            // Check if already voted
            if(!alreadyVoted.isEmpty())
            if(alreadyVoted.contains(clientId)){
                System.out.println("Voter has already voted before.");
                resultForClient = AUTHORITY_RESULT_ALREADY_VOTED;
                sendResultToClient();
                return;
            }
            alreadyVoted.add(clientId);
            System.out.println("Client hasn't voted before.");

            // Sign blinded commitment
            byte[] authSignedBlindedCommitment = CryptoUtils.signBlindedRSA(ownPrivateBlindingKey, blindedCommitment);
            System.out.println("Blinded commitment signed by authority: " + Base64.getEncoder().encodeToString(authSignedBlindedCommitment));
            resultForClient = Base64.getEncoder().encodeToString(authSignedBlindedCommitment);
            sendResultToClient();
        }

        private void sendResultToClient(){
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream())) {
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
