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
        // Own private key
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader reader = new BufferedReader(new StringReader(ownPrivateBlindingKeyString));
        String line;
        while (true){
            try {
                if ((line = reader.readLine()) == null) break;
                pkcs8Lines.append(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        byte[] ownPrivateBlindingKeyBytes = Base64.getDecoder().decode(pkcs8Pem);
        KeySpec keySpec = new PKCS8EncodedKeySpec(ownPrivateBlindingKeyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(keySpec);
            ownPrivateBlindingKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // Own public key
        pkcs8Lines = new StringBuilder();
        reader = new BufferedReader(new StringReader(ownPublicBlindingKeyString));
        while (true){
            try {
                if ((line = reader.readLine()) == null) break;
                pkcs8Lines.append(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        byte[] ownPublicBlindingKeyBytes = Base64.getDecoder().decode(pkcs8Pem);
        keySpec = new X509EncodedKeySpec(ownPublicBlindingKeyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            ownPublicBlindingKey = (RSAPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // Client public key
        clientPublicSignatureKeys = new HashMap<>();
        for(Map.Entry<Integer, String> entry : clientPublicSignatureKeyStrings.entrySet()){
            pkcs8Lines = new StringBuilder();
            reader = new BufferedReader(new StringReader(entry.getValue()));
            while (true){
                try {
                    if ((line = reader.readLine()) == null) break;
                    pkcs8Lines.append(line);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            pkcs8Pem = pkcs8Lines.toString();
            pkcs8Pem = pkcs8Pem.replace("-----BEGIN PUBLIC KEY-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----END PUBLIC KEY-----", "");
            pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

            byte[] clientPublicSignatureKeyBytes = Base64.getDecoder().decode(pkcs8Pem);
            keySpec = new X509EncodedKeySpec(clientPublicSignatureKeyBytes);
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                Integer i = entry.getKey();
                RSAPublicKey value = (RSAPublicKey) kf.generatePublic(keySpec);
                clientPublicSignatureKeys.put(i, value);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;

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

            Integer clientId = Integer.parseInt(line.substring(0, 8));
            String blindedCommitmentString = line.substring(8, 180);
            String signedBlindedCommitmentString = line.substring(180);

            System.out.println("Client ID: " + clientId);
            System.out.println("Blinded commitment: " + blindedCommitmentString);
            System.out.println("Signature of blinded commitment: " + signedBlindedCommitmentString);

            // Check vote eligibility
            if(!clientPublicSignatureKeys.containsKey(clientId)) {
                System.out.println("Client is NOT eligible to vote.");
                return;
            }
            System.out.println("Client is eligible to vote.");

            // Check signature
            RSAPublicKey verificationKey =  clientPublicSignatureKeys.get(clientId);
            byte[] blindedCommitment = Base64.getDecoder().decode(blindedCommitmentString);
            byte[] signedBlindedCommitment = Base64.getDecoder().decode(signedBlindedCommitmentString);
            if(!verifySHA256withRSAandPSS(verificationKey, blindedCommitment, signedBlindedCommitment)) {
                System.out.println("Signature not valid.");
                return;
            }
            System.out.println("Signature verified.");

            // Check if already voted
            if(!alreadyVoted.isEmpty())
            if(alreadyVoted.contains(clientId)){
                System.out.println("Voter has already voted before.");
                return;
            }
            alreadyVoted.add(clientId);
            System.out.println("Client hasn't voted before.");

            // Sign blinded commitment
            byte[] authSignedBlindedCommitment = signBlindedRSA(ownPrivateBlindingKey, blindedCommitment);
            System.out.println("Blinded commitment signed by authority: " + Base64.getEncoder().encodeToString(authSignedBlindedCommitment));

            // Send signature back to client
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream())) {
                System.out.println("Sending to client...");
                out.println(Base64.getEncoder().encodeToString(authSignedBlindedCommitment));
                System.out.println("Data sent");

            } catch (IOException e) {
                System.err.println("Failed sending data to client.");
                e.printStackTrace();
            }
        }
    }

    private static byte[] signBlindedRSA(RSAPrivateKey signingKey, byte[] message){
        RSAKeyParameters keyParameters = new RSAKeyParameters(true, signingKey.getModulus(), signingKey.getPrivateExponent());

        RSAEngine signer = new RSAEngine();
        signer.init(true, keyParameters);

        return signer.processBlock(message, 0, message.length);
    }

    private static Boolean verifySHA256withRSAandPSS(RSAPublicKey verificationKey, byte[] message, byte[] signature){
        RSAKeyParameters keyParameters = new RSAKeyParameters(false, verificationKey.getModulus(), verificationKey.getPublicExponent());

        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), saltLength);
        signer.init(false, keyParameters);
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

}
