import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
//import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.imageio.ImageIO;
import javax.management.OperationsException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyPairGenerator;

public class Server {
    // CA
    private static PrivateKey cAuthPK;
    private static X509CertificateHolder cAuthCerHold;
    private static X509Certificate cAuthCer;
    // Client
    private static PrivateKey clientPK;
    private static X509Certificate clientCer;
    // Socket client certificates
    public static X509Certificate socketClientCert;
    public final static int PORT = 4000;

    // Input and Output
    public static DataInputStream in;
    public static DataOutputStream out;

    public static void main(String[] args) throws Exception,CertificateException {
        System.out.println("Name: Bob");
        //createCAuthCer(); //Run this when you need to create Certificate Authority

        // Certificate and keystore
        String clientName = "Bob";
        String clientPass = "changeit";

        // Loading CA Certificate and keystore
        KeyStore cAuthKeyStore = loadPrivateKey("CAKeyStore.p12", "changeit");
        char[] pass = "changeit".toCharArray();
        cAuthPK = (PrivateKey) cAuthKeyStore.getKey("CA", pass);
        cAuthCerHold = new JcaX509CertificateHolder((X509Certificate) cAuthKeyStore.getCertificateChain("CA")[0]);
        //createClientCerAndKeyStore(clientName,clientPass);

        //Getting client Private, Public keys and certificate
        KeyStore clientKeyStore = loadPrivateKey("Bob.p12", clientPass);
        Certificate[] certChain = clientKeyStore.getCertificateChain(clientName);
		clientCer = (X509Certificate) certChain[0];
		cAuthCer = (X509Certificate) certChain[1];
        char[] clientCharPass = clientPass.toCharArray();
		clientPK = (PrivateKey) clientKeyStore.getKey(clientName, clientCharPass);

        //Setting up socket connection
        try{
            ServerSocket ss=new ServerSocket(PORT);
            Socket s= ss.accept();
            ss.close();
            try{
                in = new DataInputStream(s.getInputStream());
			    out = new DataOutputStream(s.getOutputStream());
            }
            catch(IOException e){
                System.out.println("Error in Stream");
            }
        }
        catch(IOException e){
            System.out.println("Connection error");
        }

        //getting certificate from Alice
        int inputLength= in.readInt();
        byte[] byteInput= new byte[inputLength];
        in.read(byteInput);
        byte[] byteCert = byteInput;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        socketClientCert  = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteCert));
        
        //Ensuring that the certificate is valid
        try {
            socketClientCert.verify(cAuthCer.getPublicKey());
            System.out.println("Alice's Certificate successfully validated");

            //let client know certificate was accepted
            System.out.println("Letting Alice know.");
            byte[] acceptReject="True".getBytes();
            out.writeInt(acceptReject.length);
            out.write(acceptReject);

        }
        catch (SignatureException e) {
            System.out.println("Certificate Invalid");
            System.out.println("Closing connections");
            System.exit(0);
        }


        //Two way
        //Sending server certificate to client
        try{

            byte[] clientCerBytes=clientCer.getEncoded();
            out.writeInt(clientCerBytes.length);
            out.write(clientCerBytes);
            System.out.println("Certificate sent to Alice");
            // Write code to checkwhether server accepted
            int arinputLength = in.readInt();
            byte[] arbyteInput = new byte[arinputLength];
            in.read(arbyteInput);
            byte[] byteAcceptReject = arbyteInput;
            String strAcceptReject = new String(byteAcceptReject);
            if(strAcceptReject.equals("True")){
                System.out.println("Alice accepted your certificate.");
            }
            else {
                System.out.println("Alice rejected your certificate.");
                System.out.println("Closing connection.");
                System.exit(0);
            }
        }
        catch(IOException e){
            System.out.println(e + "Client byte error");
        }
        // Listener listener = new Listener(in);
        // Thread thread = new Thread(listener);
        // thread.start();

        int receivedBytesLength = in.readInt();
        byte[] receivedBytes = new byte[receivedBytesLength];
        in.read(receivedBytes);

        byte[] receivedCombinedData = Encryption.decrypt(receivedBytes, clientPK,socketClientCert.getPublicKey());
        
        // Length if the Caption
        byte[] byteLenCaption = Arrays.copyOfRange(receivedCombinedData, 0, 4);    
        int lenCaption = ByteBuffer.wrap(byteLenCaption).getInt();
        // Slicing Out Caption from Combined Data
        byte[] byteCaption = Arrays.copyOfRange(receivedCombinedData, 4, lenCaption+4);
        // Slicing out Image Data from Combined Data
        byte[] byteImage =  Arrays.copyOfRange(receivedCombinedData, lenCaption+4, receivedCombinedData.length);
        String caption = new String(byteCaption, StandardCharsets.UTF_8);
        System.out.println(caption);
        ByteArrayInputStream bis = new ByteArrayInputStream(byteImage);
        BufferedImage bImage = ImageIO.read(bis);
        ImageIO.write(bImage, "jpg", new File("./BobFiles/"+caption+".jpg") );
        
    }

    // Method to create a certificate
    public static void createCertificate() {
        // KeyStore store = CertificateUtils.loadKeyStoreFromPKCS12("uct.p12", "123");
    }

    // Creating Certificate Authority details
    public static void createCAuthCer() throws NoSuchAlgorithmException, OperatorCreationException, IOException,
            CertificateException, KeyStoreException {
        System.out.println("Creating a Certificates for Certificate Authority.");
        KeyPair cAuthKeyPair = createKeyRSA();
        X509CertificateHolder cHold = createCertificate(cAuthKeyPair);
        saveCertificate("caCert.der", cHold);
        // saving to a keystore
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(cHold);
        Certificate[] certChain = new Certificate[] { cert };
        savePrivateKey(cAuthKeyPair, certChain, "CA", "changeit", "CAKeyStore.p12", "changeit", cHold);
        System.out.println("CA Certificate and Keystore created");
    }

    // creating a client certificate and keystore
    public static void createClientCerAndKeyStore(String clientName, String clientPass) throws NoSuchAlgorithmException,
            OperatorCreationException, CertificateException, IOException, KeyStoreException {
        // Setting up client details
        X500NameBuilder clientDets = new X500NameBuilder();
        clientDets.addRDN(BCStyle.NAME, clientName);
        clientDets.addRDN(BCStyle.C, "ZA");
        clientDets.addRDN(BCStyle.O, "UCT");
        clientDets.addRDN(BCStyle.OU, "CPTUCT");
        clientDets.addRDN(BCStyle.EmailAddress, "MyUCT@myuct.ac.za");

        // Creating new client key pair
        KeyPair clientKP = createKeyRSA();

        // Creating & Signing of client certificate
        long fourtyDays = 100 * 100 * 50 * 4984;
        Date dateBefore = new Date(System.currentTimeMillis() - fourtyDays);
        Date dateAfter = new Date(System.currentTimeMillis() + fourtyDays);
        X509v3CertificateBuilder clientCertGen = new JcaX509v3CertificateBuilder(cAuthCerHold.getSubject(),
                BigInteger.valueOf(1), dateBefore, dateAfter, clientDets.build(), clientKP.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(cAuthPK);
        X509CertificateHolder cHold = clientCertGen.build(signer);

        // Conversion of certificate
        JcaX509CertificateConverter certConvertor = new JcaX509CertificateConverter();
        X509Certificate cAuthCert = certConvertor.getCertificate(cAuthCerHold);
        X509Certificate clientCert = certConvertor.getCertificate(cHold);

        Certificate[] cChain = new Certificate[] { clientCert, cAuthCert };
        // Save certificate
        saveCertificate(clientName + ".der", cHold);
        // save private key
        savePrivateKey(clientKP, cChain, clientName, clientPass, clientName + ".p12", clientPass, cHold);
        System.out.println("Certificate and Keystore for client has been created.");
    }

    // Creating an RSA Public and Private key
    public static KeyPair createKeyRSA() throws NoSuchAlgorithmException {
        System.out.println("Creating a key with RSA");
        KeyPairGenerator kG = KeyPairGenerator.getInstance("RSA");
        kG.initialize(4096);
        KeyPair info = kG.generateKeyPair();
        return info;
    }

    // Creating a certificate with default values.
    public static X509CertificateHolder createCertificate(KeyPair kp) throws OperatorCreationException {
        X500NameBuilder certDets = new X500NameBuilder();
        certDets.addRDN(BCStyle.C, "ZA");
        certDets.addRDN(BCStyle.O, "UCT");
        certDets.addRDN(BCStyle.OU, "CPTUCT");
        certDets.addRDN(BCStyle.EmailAddress, "MyUCT@myuct.ac.za");
        X500Name certName = certDets.build();
        long fourtyDays = 100 * 100 * 50 * 4984;
        Date dateBefore = new Date(System.currentTimeMillis() - fourtyDays);
        Date dateAfter = new Date(System.currentTimeMillis() + fourtyDays);

        X509v3CertificateBuilder certificateGenerator = new JcaX509v3CertificateBuilder(certName, BigInteger.valueOf(1),
                dateBefore, dateAfter, certName, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(kp.getPrivate());
        X509CertificateHolder cHold = certificateGenerator.build(signer);
        return cHold;
    }

    // Saving certificate to a specified file
    public static void saveCertificate(String file, X509CertificateHolder cHold) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(cHold.getEncoded());
        fos.flush();
        fos.close();
    }

    // Saving to a private keystore using PKCS12
    public static void savePrivateKey(KeyPair kp, Certificate[] certChain, String alias, String keyPass, String file,
            String storePass, X509CertificateHolder certHolder)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(alias, kp.getPrivate(), keyPass.toCharArray(), certChain);

        FileOutputStream fos = new FileOutputStream(file);
        store.store(fos, storePass.toCharArray());
        fos.flush();
        fos.close();
    }

    // Loading a private keystore using PKCS12
    public static KeyStore loadPrivateKey(String file, String pass)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(file);
        keyStore.load(fis, pass.toCharArray());
        fis.close();
        return keyStore;
    }
}