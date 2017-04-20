package com.example.CP2;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
 * Created by test on 19/4/2017.
 */

public class Client {
    int port;
    private Socket socket;
    private OutputStream output;
    private InputStream input;
    private X509Certificate serverCertificate;
    private X509Certificate CA;
    private SecretKey symKey;

    public static void main(String[] args) {

        // Client init at localhost and port 5000
        Client client = new Client("localhost", 5000);
        try {

            // perform authentication
            client.authenticate();
            int numTrial = 10;

            // test encryption and file storage
            client.encryptedTransfer("src\\main\\java\\com\\example\\sampleData\\smallFile.txt", "smallFileCP2.txt");
            client.encryptedTransfer("src\\main\\java\\com\\example\\sampleData\\medianFile.txt", "medianFileCP2.txt");
            client.encryptedTransfer("src\\main\\java\\com\\example\\sampleData\\largeFile.txt", "largeFileCP2.txt");

            // end of job
            System.out.println("Job Done.");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    public Client(String ip, int port) {
        // set port and initialize socket
        this.port = port;
        socket = new Socket();

        // set server IP address
        SocketAddress sockaddr = new InetSocketAddress(ip, this.port);

        try {
            // connect to server using the IP address
            socket.connect(sockaddr);
            socket.setSoTimeout(100);

            //input and output streams
            output = socket.getOutputStream();
            input = socket.getInputStream();

            // CA certificate from CA.crt
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CA = (X509Certificate) cf.generateCertificate(new FileInputStream("src\\main\\java\\com\\example\\CA.crt"));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void authenticate() throws Exception {

        // generate a cNonce to use
        String cNonce = generateCnonce();

        // send cNonce to server as comBytes
        output.write(cNonce.getBytes());

        // recieve encrypted cNonce encrypted using servers private key
        byte[] encryptedCnonce = serverResponseRead(input);

        // ask server for certificate
        output.write("Certificate Request".getBytes());
        System.out.println("Asking for cert");

        // recieve certificate from server and extract the certificate
        byte[] byteCert = serverResponseRead(input);
        serverCertificate = extractCertificate(byteCert);

        // check if server is verified
        if (verifyServer(cNonce, encryptedCnonce, serverCertificate.getPublicKey())) {
            output.write("Verified".getBytes());

            // get secret key from encrypted secret key by RSA decrypting using the certificate public key
            byte[] byteSecretKey = decryptBytes(serverResponseRead(input), "RSA/ECB/PKCS1Padding", serverCertificate.getPublicKey());
            getSymKey(byteSecretKey);
        } else {
            System.out.println("Authentication Failed");
        }
    }

    private boolean verifyServer(String cNonce, byte[] encryptedCnonce, Key key) throws Exception {
        // check if decrypted cNonce is the same as client generated cNonce
        return cNonce.equals(new String(decryptBytes(encryptedCnonce, "RSA/ECB/PKCS1Padding", key)));
    }

    private X509Certificate extractCertificate(byte[] byteArray) throws Exception {
        // extract certificate and check validity
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream stream = new ByteArrayInputStream(byteArray);
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(stream);
        stream.close();

        // checking validity and verifying with CA public key
        certificate.checkValidity();
        certificate.verify(CA.getPublicKey());
        return certificate;
    }

    private byte[] readInputStream(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int i;
        byte[] data = new byte[16384];

        // read entire input stream
        while (true) {
            try {
                i = in.read(data, 0, data.length);
                bos.write(data, 0, i);
            } catch (SocketTimeoutException sTimeout) {
                break;
            }
        }
        bos.flush();

        // return byte array of bos
        return bos.toByteArray();
    }

    private byte[] encryptBytes(byte[] byteArr, String encryptType, Key key) throws Exception {

        // instantiate a cypher based on encryption type
        Cipher cipher = Cipher.getInstance(encryptType);

        // initialize cypher using the key
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // encrypt the byte array using the key
        if (encryptType.contains("AES")) return cipher.doFinal(byteArr);

        // for Data longer than 117 bytes
        return SecStore.blockCipher(byteArr, Cipher.ENCRYPT_MODE, cipher);
    }

    private byte[] decryptBytes(byte[] encryptedArray, String decryptType, Key key) throws Exception {

        // instantiate a cypher based on the decryption type
        Cipher cipher = Cipher.getInstance(decryptType);

        // initialize the cypher using the key
        cipher.init(Cipher.DECRYPT_MODE, key);

        // return decrypted byte array
        return SecStore.blockCipher(encryptedArray, Cipher.DECRYPT_MODE, cipher);
    }

    private void uploadFile(String pathToFile, String name) throws Exception {
        // set key type based on encryptionType
        Key key = symKey;

        // encrypted byte array of file to send
        File upload = new File(pathToFile);
        byte[] toSend = encryptBytes(Files.readAllBytes(upload.toPath()), "AES", key);

        // file Size
        System.out.println("Size: " + toSend.length);

        // send encryption Type to server so that it prepares its key
        output.write("AES".substring(0, 3).getBytes());
        serverResponseRead(input);

        // send file name to the server (The name of the file which is supposed to be on the server)
        output.write((name).getBytes());
        serverResponseRead(input);

        // send the encrypted file array
        output.write(toSend);
        output.flush();
        successOrFailure();
    }

    private byte[] serverResponseRead(InputStream input) throws Exception {
        byte[] data = new byte[0];
        while (data.length == 0) {
            data = readInputStream(input);
        }
        return data;
    }

    private void successOrFailure() throws Exception {
        String line = new String(serverResponseRead(input));
        if (line.equals("Job Done")) System.out.println("Received done");
        else System.out.println("Cannot receive Done");
    }

    private void getSymKey(byte[] byteKey) throws NoSuchAlgorithmException {
        symKey = new SecretKeySpec(byteKey, "AES");
    } // symKey for AES

    private String generateCnonce() {
        return new BigInteger(50, new SecureRandom()).toString();
    } // cNonce for verification

    private void encryptedTransfer(String path, String fileName) throws Exception {
        FileWriter excel = new FileWriter("PA2Saved\\Timings.csv", true);
        excel.append(fileName + ",");
        long trialTiming;
        long startTrial;
        startTrial = System.currentTimeMillis();
        uploadFile(path, fileName);
        trialTiming = System.currentTimeMillis() - startTrial;
        System.out.println(trialTiming);
        excel.append("" + trialTiming + "\n");
        excel.flush();
        excel.close();
        System.out.println("Average time: " + trialTiming);
    }
}