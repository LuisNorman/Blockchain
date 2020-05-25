

// import java.util.*;
// import java.io.*;
// import java.net.*;
// import java.util.concurrent.*;
// import java.math.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.spec.*;
import java.security.*;
import java.util.Arrays;

import java.util.Base64;

class Playground {

  public static void main(String[] argv) throws Exception {
        // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);

        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privateKey = keypair.getPrivate();
        	
    	// System.out.println(privateKey);

    	// System.out.println("\n\n\n\nHERE\n\n");
    	PublicKey publicKey = keypair.getPublic();
    	// System.out.println(publicKey);


        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        // Byte[] messageHash = md.digest(document.getBytes());

        // System.out.println(messageHash[0]);

        // Cipher cipher = Cipher.getInstance("RSA");
        // cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        // Byte[] digitalSignature = cipher.doFinal(document.getBytes());

        // System.out.println(digitalSignature[0]);

        // you decrypt by hashing the message and see 


        String document = "This is my document.";
        Signature signature = Signature.getInstance("SHA256withRSA"); // Create signature object using SHA256 w RSA
        byte[] signedDocument = signDocument(signature, document, privateKey);
        // String signedDocumentString = bytesToHex(signedDocument); // convert to hex string to store in object
        String signedDocumentString = Base64.getEncoder().encodeToString(signedDocument);
        System.out.println ("toString");
        System.out.println (signedDocumentString);


        byte[] signDocumentByteArr = Base64.getDecoder().decode(signedDocumentString);
        System.out.println ("toBytes");
        System.out.println (signDocumentByteArr);
        // byte[] signDocumentByteArr = decodeHexString(signedDocumentString); // convert from hex string to byte arr for normal use again
        System.out.println(verifySignedDocument(signature, signDocumentByteArr, publicKey, document));

        // byte[] signedDocument2 = signedDocumentString.split(",");
        // System.out.println(verifySignedDocument(signature, signedDocument, publicKey, document));
        

    }

    public static byte[] decodeHexString(String hexString) {
        byte[] val = new byte[hexString.length() / 2];
        for (int i = 0; i < val.length; i++) {
           int index = i * 2;
           int j = Integer.parseInt(hexString.substring(index, index + 2), 16);
           val[i] = (byte) j;
        }
        System.out.println(val);
        return val;
    }

    public static  byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            hexString.append(Integer.toHexString(0xFF & hash[i]));
        }
        return hexString.toString();
    }
  

  // Method to sign document using this instance's private key
    public static byte[] signDocument(Signature signature, String documentToSign, PrivateKey privateKey) throws Exception {
        // Init signature using the instance's private key
        try {signature.initSign(privateKey);} 
        catch (Exception ex) {System.out.println(ex);}
        signature.update(documentToSign.getBytes());
        byte[] signedDocument = signature.sign();

        
        return signedDocument;
    }

    public static Boolean verifySignedDocument(Signature signature, byte[] signedDocument, PublicKey publicKey, String documentToVerify) throws Exception {
        
        signature.initVerify(publicKey);
        signature.update(documentToVerify.getBytes());
        boolean isCorrect = signature.verify(signedDocument);

        return isCorrect;
    }



}



