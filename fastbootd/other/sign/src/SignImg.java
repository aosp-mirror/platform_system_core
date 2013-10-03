package signtool;

import java.io.*;
import java.util.Properties;
import java.util.ArrayList;

import javax.mail.internet.*;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.activation.MailcapCommandMap;
import javax.activation.CommandMap;

import java.security.PrivateKey;
import java.security.Security;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.asn1.ASN1InputStream;    
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.ASN1Object;


public class SignImg {

    /* It reads private key in pkcs#8 formate
     * Conversion:
     * openssl pkcs8 -topk8 -nocrypt -outform DER < inkey.pem > outkey.pk8
     */
    private static PrivateKey getPrivateKey(String path) throws IOException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File(path);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();

        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(data);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(kspec);

        return privateKey;
    }

    private static MimeBodyPart getContent(String path) throws IOException, FileNotFoundException, MessagingException {
        MimeBodyPart body = new MimeBodyPart();

        File file = new File(path);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();

        body.setContent(data, "application/octet-stream");

        return body;
    }

    private static CMSProcessableByteArray getCMSContent(String path) throws IOException, FileNotFoundException, MessagingException {
        File file = new File(path);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();
        CMSProcessableByteArray cms = new CMSProcessableByteArray(data);

        return cms;
    }

    private static X509Certificate readCert(String path) throws IOException, FileNotFoundException, CertificateException {
        File file = new File(path);
        FileInputStream is = new FileInputStream(file);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(is);
        is.close();

        return (X509Certificate) cert;
    }

    private static void save(MimeBodyPart content, String path) throws IOException, FileNotFoundException, MessagingException {
        File file = new File(path);
        FileOutputStream os = new FileOutputStream(file);

        content.writeTo(os);

        os.close();
    }

    private static Store certToStore(X509Certificate certificate) throws CertificateEncodingException {
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(certificate);
        return new JcaCertStore(certList);
    }

    public static void setDefaultMailcap()
    {
        MailcapCommandMap _mailcap =
            (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        _mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        _mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        _mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        _mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        _mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        CommandMap.setDefaultCommandMap(_mailcap);
    } 

    public static void main(String[] args) {
        try {
            if (args.length < 4) {
                System.out.println("Usage: signimg data private_key certificate output");
                return;
            }
            System.out.println("Signing the image");
            setDefaultMailcap();

            Security.addProvider(new BouncyCastleProvider());

            PrivateKey key = getPrivateKey(args[1]);
            System.out.println("File read sucessfully");

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            CMSTypedData body = getCMSContent(args[0]);
            System.out.println("Content read sucessfully");

            X509Certificate cert = (X509Certificate) readCert(args[2]);
            System.out.println("Certificate read sucessfully");

            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key);

            Store certs = certToStore(cert);

            generator.addCertificates(certs);
            generator.addSignerInfoGenerator(
                          new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                          .build(sha256Signer, cert));

            CMSSignedData signed = generator.generate(body, true);
            System.out.println("Signed");

            Properties props = System.getProperties();
            Session session = Session.getDefaultInstance(props, null);
            
            File file = new File(args[3]);
            FileOutputStream os = new FileOutputStream(file);

            ASN1InputStream asn1 = new ASN1InputStream(signed.getEncoded());
            ByteArrayOutputStream out = new ByteArrayOutputStream(); 
            DEROutputStream dOut = new DEROutputStream(os); 
            dOut.writeObject(ASN1Object.fromByteArray(signed.getEncoded()));

        }
        catch (Exception ex) {
            System.out.println("Exception during programm execution: " + ex.getMessage());
        }
    }
}
