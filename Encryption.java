import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Encryption {

    public static byte[] encrypt(String imageFile, String imageCaption, PublicKey receiverPK, PrivateKey clientPK)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // Path path = Paths.get("./AliceFiles/" + imageFile);
        // byte[] imageData = Files.readAllBytes(path);
        BufferedImage bImage = ImageIO.read(new File("./AliceFiles/"+imageFile));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(bImage, "jpg", bos);
        byte[] imageData = bos.toByteArray();
        byte[] captionData = imageCaption.getBytes(StandardCharsets.UTF_8);
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(captionData.length);
        byte[] captionLen = bb.array();
        // creating a hash using image and caption
        byte[] data = new byte[captionLen.length + imageData.length + captionData.length];

        for (int i = 0; i < captionLen.length; i++) {
            data[i] = captionLen[i];

        }

        for (int i = 0; i < data.length - 4; i++) {

            data[i + 4] = i < captionData.length ? captionData[i] : imageData[i - captionData.length];

        }

        /**
         * SIGNING
         */

        // Sign hash of image and caption
        Signature SHA256Sign = Signature.getInstance("SHA256withRSA");
        SHA256Sign.initSign(clientPK);
        SHA256Sign.update(data);
        byte[] SHA256Signature = SHA256Sign.sign();
        int byteArrayLength = SHA256Signature.length + data.length;
        ByteArrayOutputStream outStream = new ByteArrayOutputStream(byteArrayLength);
        outStream.write(SHA256Signature);
        outStream.write(data);
        byte[] signedHashedData = outStream.toByteArray();
        // System.out.println(signedHashedData);

        /**
         * ENCRYPTION
         */

        // Compression
        // for (int i=0;i<=signedHashedData.length;i++){
        // System.out.println(signedHashedData[i]);
        // }
        outStream = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(outStream);
        ZipEntry entry = new ZipEntry("Data");
        entry.setSize(signedHashedData.length);
        zip.putNextEntry(entry);
        zip.write(signedHashedData);
        zip.closeEntry();
        zip.close();
        byte[] cData = outStream.toByteArray();
        // System.out.println(cData);

        // symetric encryption for a shared key
        Cipher symEncyption = Cipher.getInstance("AES/CBC/PKCS5Padding");
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sk = kg.generateKey();

        // creating an initializing vector for CBC mode
        // byte[] iv = new byte[128 / 8];
        // SecureRandom sRandom = new SecureRandom();
        // sRandom.nextBytes(iv);
        // IvParameterSpec ivspec = new IvParameterSpec(iv);

        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        symEncyption.init(Cipher.ENCRYPT_MODE, sk, iv);

        // Encrypting the compressed data
        byte[] eData = symEncyption.doFinal(cData);

        // asymetric encryption for a secret key
        Cipher asymEncyption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymEncyption.init(Cipher.ENCRYPT_MODE, receiverPK);
        asymEncyption.update(sk.getEncoded());
        // Encrypting the compressed data
        byte[] eSk = asymEncyption.doFinal();
        outStream = new ByteArrayOutputStream(eData.length + eSk.length);
        outStream.write(eSk);
        outStream.write(eData);
        byte[] eDataSend = outStream.toByteArray();
        return eDataSend;

    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey,PublicKey socketPublickey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

        // Asymetric decryption to get the secret key
        byte[] eSK = Arrays.copyOfRange(data, 0, 512);
        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        byte[] eData = Arrays.copyOfRange(data, 512, data.length);
        Cipher asymDecryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymDecryption.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] sKDecrypted = asymDecryption.doFinal(eSK);
        SecretKeySpec sKeySpec = new SecretKeySpec(sKDecrypted, "AES");

        Cipher symDecryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
        symDecryption.init(Cipher.DECRYPT_MODE, sKeySpec, iv);
        byte[] dataDecrypted = symDecryption.doFinal(eData);

        // Decompression- unzip
        ByteArrayInputStream inStream = new ByteArrayInputStream(dataDecrypted);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ZipInputStream zip = new ZipInputStream(inStream);
        ZipEntry entry = zip.getNextEntry();
        int bytes = 0;
        byte[] buffer = new byte[1024];
        while ((bytes = zip.read(buffer)) != -1) {
            outStream.write(buffer, 0, bytes);
        }
        byte[] unzippedData = outStream.toByteArray();
        byte[] sign = Arrays.copyOfRange(unzippedData, 0, 512);
        byte[] combinedData = Arrays.copyOfRange(unzippedData, 512, unzippedData.length);
        
        Signature SHA256Sign = Signature.getInstance("SHA256withRSA");
        SHA256Sign.initVerify(socketPublickey);
        SHA256Sign.update(combinedData);
        if(SHA256Sign.verify(sign)){
                return combinedData;

        }else{
            System.out.println("Invalid signature on hash, Reject");
            System.exit(1);
        }
        return null ;
    }

}