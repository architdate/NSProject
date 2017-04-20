package com.example;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Created by test on 19/4/2017.
 */

public class SecStore {
    private ServerSocket socket;
    private final Executor tpool;
    private final int port;
    private X509Certificate certificate;
    private PrivateKey key;

    /**
     * Set certificate locations here : [Make sure that the working directory is "lib"
     */

    private String privateServer = "src\\main\\java\\com\\example\\privateServer.der";
    private String myCertificate = "src\\main\\java\\com\\example\\1001695.crt";


    public static void main(String[] args) {
        // server at port 6789 with 5 threads in executor threadpool
        SecStore server = new SecStore(6789, 5);

        // start server
        server.startServer();
    }

    public SecStore(int port, int numThreads) {
        this.port = port;
        tpool = Executors.newFixedThreadPool(numThreads);
        try {
            // Make sure the path is set with respect to lib in "Edit configuration"
            key = getPrivateKey(privateServer);

            //create a certificate factory
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // File input stream for 1001695.crt
            FileInputStream fis_myCert = new FileInputStream(myCertificate);
            certificate = (X509Certificate) cf.generateCertificate(fis_myCert);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private PrivateKey getPrivateKey(String location) throws Exception {
        // byte array of the file at location
        byte[] bytes = Files.readAllBytes(new File(location).toPath());

        // PKCS8 key spec
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

        // RSA key factory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // generate private key based on spec
        return keyFactory.generatePrivate(spec);
    }

    public void startServer() {
        try {
            // new socket at port specified in the constructor
            socket = new ServerSocket(port);

            while (true) {
                // socket connection with the client
                final Socket connection = socket.accept();

                // cant use lambda overwrite in java 7
                Runnable task = new Runnable() {
                    @Override
                    public void run() {
                        try {

                            // call server response to handle the client requests from client
                            serverResponse(connection);

                        } catch (Exception e) {
                            System.out.println(e.getMessage());
                            e.printStackTrace();
                        }
                    }
                };

                // execute using numThreads amount of threads in the executor to avoid thread creation overhead
                tpool.execute(task);
            }
        } catch (IOException ioE) {
            System.out.println(ioE.getMessage());
            ioE.printStackTrace();
        }
    }

    private void serverResponse(Socket socket) throws Exception {

        // set input and output streams
        OutputStream output = socket.getOutputStream();
        InputStream input = socket.getInputStream();

        // Connected with the client when this command is called
        System.out.println("Connected with the client");

        SecretKey symKey;

        // wait for cNonce from the client
        byte[] comBytes = clientResponseRead(socket, input);

        // encrypt cNonce with the private key using RSA encryption
        output.write(encryptBytes(comBytes, "RSA/ECB/PKCS1Padding", key));

        // wait for certificate request
        comBytes = clientResponseRead(socket, input);

        // check if the request was a certificate request. If so send encoded certificate for the public key extraction by the client
        if (Arrays.equals(comBytes, "Certificate Request".getBytes())) {
            output.write(certificate.getEncoded());
            output.flush();
        }

        // check for the confirmation from the server
        comBytes = clientResponseRead(socket, input);
        if (Arrays.equals(comBytes, "Verified".getBytes())) {

            // if confimed a communication, generate a secretKey
            symKey = getSecretKey();

            // encrypt secret key with private key and send it to client
            output.write(encryptBytes(symKey.getEncoded(), "RSA/ECB/PKCS1Padding", key));

            // wait for the file to be uploaded
            uploadState(socket, output, input, symKey);
        }
    }

    private byte[] clientResponseRead(Socket socket, InputStream input) throws Exception {

        // return a byte array after reading everything from the client input
        byte[] data = new byte[0];
        while (data.length == 0) {
            data = readInputStream(socket, input);
        }
        return data;
    }

    private void uploadState(Socket socket, OutputStream output, InputStream input, SecretKey symKey) throws Exception {
        String comBytes;
        String encryptType;
        Key keyType;

        try {
            while (true) {

                // waits for client inputs and convert byte array to a string
                comBytes = new String(clientResponseRead(socket, input));

                // first string sent is encryption type. Check for the encryption type and set the key and encryption padding for file receiving
                if (comBytes.equals("AES")) {
                    encryptType = "AES/ECB/PKCS5Padding";
                    keyType = symKey;
                } else if (comBytes.equals("RSA")) {
                    encryptType = "RSA/ECB/PKCS1Padding";
                    keyType = key;
                } else {
                    encryptType = "GEEEEET DUNKED ON!!! (undertale sans :])";
                    keyType = symKey;
                }

                // receive file from the client and decrypt it
                receiveFile(socket, output, input, encryptType, keyType);

            }
        } catch (SocketException se) {
            // closing the communication socket
            System.out.println("Socket Closed.");
            output.close();
            input.close();
            socket.close();
        }
    }

    private void receiveFile(Socket conn, OutputStream out, InputStream in, String decryptType, Key key) throws Exception {

        // else condition after upload State
        if (decryptType.equals("GEEEEET DUNKED ON!!! (undertale sans :])")) {
            System.out.println("The encryption type specified by the client is wrong. The client is trolling. inb4 exception");
        }

        // wait for file Name from the client
        out.write("K".getBytes());
        String fileName = new String(clientResponseRead(conn, in));
        out.write("K".getBytes());

        // byte array of what to decrypt
        byte[] encryptedFile = clientResponseRead(conn, in);

        // decrypted file save location using file output stream
        FileOutputStream fileWriter = new FileOutputStream("PA2Saved\\" + fileName);

        // decrypt the encrypted file byte array using key
        fileWriter.write(decryptBytes(encryptedFile, decryptType, key));
        fileWriter.close();

        // print completion message
        System.out.println("Decryption finished");
        out.write("Job Done".getBytes());
    }

    private SecretKey getSecretKey() throws NoSuchAlgorithmException {

        // generate a symkey for AES file encryption and to share with client
        KeyGenerator k = KeyGenerator.getInstance("AES");
        return k.generateKey();
    }

    private byte[] encryptBytes(byte[] byteArr, String encryptType, Key key) throws Exception {

        // instantiate a cypher based on encryption type
        Cipher cipher = Cipher.getInstance(encryptType);

        // initialize cypher using the key
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // encrypt the byte array using the key
        return cipher.doFinal(byteArr);
    }

    private byte[] decryptBytes(byte[] encryptedArray, String decryptType, Key key) throws Exception {

        // instantiate a cypher based on the decryption type
        Cipher cipher = Cipher.getInstance(decryptType);

        // initialize the cypher using the key
        cipher.init(Cipher.DECRYPT_MODE, key);

        // decrypt the byte array using the key
        if (decryptType.contains("AES")) return cipher.doFinal(encryptedArray);

        // for RSA files (used to tackle larger files being decrypted using RSA)
        else return blockCipher(encryptedArray, Cipher.DECRYPT_MODE, cipher);
    }

    private byte[] readInputStream(Socket connection, InputStream input) throws Exception {
        connection.setSoTimeout(100);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int i;
        byte[] data = new byte[16777216];

        // read entire inputstream
        while (true) {
            try {
                i = input.read(data, 0, data.length);

                //write input stream to byte array output stream
                bos.write(data, 0, i);
            } catch (SocketTimeoutException sTimeout) {
                break;
            }
        }
        connection.setSoTimeout(0);

        //convert bytearrayoutputstream to array and return to user
        return bos.toByteArray();
    }

    protected static byte[] blockCipher(byte[] bytes, int mode, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException, IOException {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results

        // toReturn will hold the total result
        ByteArrayOutputStream toReturn = new ByteArrayOutputStream();
        // if we encrypt we use 117 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        int length = (mode == Cipher.ENCRYPT_MODE) ? 117 : 128;
        int count = 0;

        // another buffer. this one will hold the bytes that have to be modified in this step
        byte[] buffer = new byte[length];

        System.out.println("Begin encryption/decryption");
        while (count < bytes.length) {
            if (count + length > bytes.length) {
                length = bytes.length - count;
                // clean the buffer array
                buffer = new byte[length];
            }
            System.arraycopy(bytes, count, buffer, 0, length);
            toReturn.write(cipher.doFinal(buffer));
            count += length;
        }
        System.out.println("Stopped encryption/decryption");

        return toReturn.toByteArray();
    }
}
