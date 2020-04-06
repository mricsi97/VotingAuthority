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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class VotingAuthority {

    private static final String TAG = "MainActivity";

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
    private static final String ownPublicBlindingKeyString =
            "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF8hrv+1z1yMJA6UFZ5J/uFQ+Xp9\n" +
                    "hq/iT4ibZz2a7JpZf7VO3jJaQsiMowubOvpm70rmBUTPZdP9U7uHaRXPcL++oNIX\n" +
                    "pG/5Nfv1sUSIA97pfAJiUjqSVNX/VVud4wxs+F6Rn1a6QEf3NukDF8Yc9BPRJF5o\n" +
                    "Nmf8GXzGZp1AgGgdAgMBAAE=\n" +
                    "-----END PUBLIC KEY-----";

    private static final Map<Integer, String> clientPublicSignatureKeyStrings = Map.ofEntries(
            Map.entry(12345678,"-----BEGIN PUBLIC KEY-----\n" +
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPILUbSbMPnzlEWskxKYPD4rvP\n" +
                    "k3i+DxtIFiRZrvoKOZG+FWt5LVDcW3+mX2vhQtZgTXB7TJf8xhgniXTQvN7kXFNt\n" +
                    "Np+7xD4+XqmcUF8GRGf8/ZN/O1tB4UOpEIZ5wLnk0LqXQR12sZz412WdhAqoWq5g\n" +
                    "41yOFCSAwdnU9PdqXwIDAQAB\n" +
                    "-----END PUBLIC KEY-----")
    );

    private static HashMap<Integer, RSAPublicKey> clientPublicSignatureKeys;

    private static ArrayList<Integer> alreadyVoted = new ArrayList<>();

    // Actual RSA keys
    private static RSAPrivateKey ownPrivateBlindingKey;
    private static RSAPublicKey ownPublicBlindingKey;

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
            PrintWriter out = null;
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                System.out.println("Waiting for data...");
                String line = in.readLine();
                Integer clientId = Integer.parseInt(line.substring(0, 8));
                String blindedCommitmentString = line.substring(8, 180);
                String signedBlindedCommitmentString = line.substring(180);

                System.out.println("Received data");
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
                if(!verifySHA256withRSA(verificationKey, blindedCommitment, signedBlindedCommitment)) {
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
                byte[] authSignedBlindedCommitment = signSHA256withRSA(ownPrivateBlindingKey, blindedCommitment);
                System.out.println("Blinded commitment signed by authority: " + Base64.getEncoder().encodeToString(authSignedBlindedCommitment));

                // Send signature back to client
                System.out.println("Sending to client...");
                out = new PrintWriter(clientSocket.getOutputStream());
                out.println(Base64.getEncoder().encodeToString(authSignedBlindedCommitment));
                System.out.println("Data sent");

                if(verifySHA256withRSA(ownPublicBlindingKey, blindedCommitment, authSignedBlindedCommitment))
                    System.out.println("nice");

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (out != null)
                        out.close();
                    if (in != null)
                        in.close();
                    clientSocket.close();
                } catch (IOException e){
                    e.printStackTrace();
                }
            }
        }
    }

    private static Boolean verifySHA256withRSA(RSAPublicKey verificationKey, byte[] message, byte[] signature){
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(verificationKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.out.println("Signature verification failed.");
        }
        return false;
    }

    private static byte[] signSHA256withRSA(RSAPrivateKey signingKey, byte[] message) {
        Signature sig;
        try {
            sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(signingKey);
            sig.update(message);
            return sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.out.println("Signing failed.");
        }
        return null;
    }
}
