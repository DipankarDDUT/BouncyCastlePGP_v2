import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.util.Base64;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
//import org.bouncycastle.util.encoders.Base64;

public class PGP {
	static Scanner sc;
	public static void main(String[] args) throws Exception {
		
		
		Security.setProperty("crypto.policy", "unlimited");
		
		int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
		
		Security.addProvider(new BouncyCastleProvider());
		CertificateFactory certFactory= CertificateFactory
		  .getInstance("X.509", "BC");
				//Private key need to be in correct format -----IMPORTANT---------
		//was generating from file ,but need to be in input field so extracted one key and used as string down below 
		// in field PrivateKey
		
		String PrivateKey="MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMouRpjnjeEGh/wj+YEjsh1/M52+Uwx1lfMHPmU+5DVPM7ebRjIY6MyuoWsdeef+rTrAQ0dK0mAYS/g5v/rglUu6jpUR4X+nDRrcxhdYJzSQdloyPKDAGJtuMaS49VqYSlMCq5950zD50LqeTqDQDGJffX5QDa0WFY48ay0Lw2Q1IqOiLo6wmdk7VxjNIP4D/vtvCk+4NSpVLot8bQdLt98Me1DfBYsdyZozmjxxsMRqcD91Rko37PHLoalcEUGmaQjqB1Pz/MKVysPNLEnYc/kkbnjD7VWKitAoiy+fztIdGN5XuCFcIYINyhtYkxjlp+tFDBZ9RGJkNfJOTbJmulAgMBAAECggEBAMn5DFBS2mDy+PEAHBxQAiUJK3sz2iYm28Lj48C1nji+o8NUAALHoBa+QAVeSl6aCoAZC51qe2tDnG4Zy+KzN2p2PeTqtzUbbjbFvy+B99spfS+HsU8+QlZWOBg/85ysz8rqm4EpL/KxumNEsDeB1f28g76GvC0880P0rKzY8KrsSzhmLBCukTkFaTHCeCs8tNI9m97MqIWHGuDna2Lu5bWy+lvGV+FlV+gSbCBdlWVgoSM0Jgf5FLycZvJKzjTrlpD280GYy5kFZOeT3Qt90IPF8lW+6UwRXTTTrfsgEVdJtmS9a2QUF2P7h7nqsQJsqrx68Grotm+NtDYqD/q3dYECgYEA6vyjUg+m51VCUyUUSGB4Sgfs09p4XVZEi4wPJzDFs+Bt+sSh4wmbTBlIObpdwlacmc7qOzJcolNMpXMBaLHE7aGzr5uAQecZm0lhyPCffcfHn7k3eGPVbKCHh9VivThquKKrVvJlYmtfzAl3E+mal5ab7UcOVIRQqR3fyEhtT5kCgYEA3u92qV8Gq9J6kSU2NwaZRfdLSJPUodpwMkRxvKn7A9xre0XfvrG1kF5//tcOjMPzk2PLYT3uidMFLdCfL/gaH+4W4Bly86EUg0s7pr7g6ISKn/qrmFkfZoOeoJ53HEd0aUxJWw+SgMrmeWOQuCFRgb4S3C42+4mGDb3BIzQCc+0CgYEA1tjGOnE1GK1LRtnQAZyyXn2AevJ0umH1qeEUubBOEnhQFcdSfFJ8Osei0aUjtFucMsSMRDN3nrKqkVrlHuPqOZpuv1Bdo+O39dLSJPZb3JScX9zoappcuETNpdPjwz2h1c5k+coGCEZEADlnNj2Pqql5RyiAYaXYWceGo4gU6YECgYAUR+CZo+VteCZiUepOszD6ZnbY0WoEl2Shjgxyx1vojALTIhYquOv1iENIobPXJnRgMjHsVMAAlcvg0RvKN13ZDcXS+T214C+Hii6RCshXHselqh42K9VpdAvYPNJFJlL2yVPbDt2bDdpNrLsbpRxPG0WH9kRWObqSQXLyiua2OQKBgAMHa+6bAAqSqlg5c2NZK7gUx4fr72fMknGMq6KPSwkdskJ4eZEcQnDpaCk702y2y1q6Vvm2G4WzmMSBrfC5mtpx+G4YCnBkeTKlVQADxSrMNbyQciNfFXky/LC3z0znTdodICYVaXQ3HIctz7YrYTxv7ayxVgFIVn/4E1k+0Es6";

		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("Baeldung.cer"));
		  
//	

		  // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PrivateKey));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");

        // Base64 decode the result
       // byte[] newB = 
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        System.out.println(privKey);
		
		//------------------------------------------------------------
		
		String secretMessage;
		System.out.println("Enter the message");
         sc=new Scanner(System.in);
         secretMessage=sc.nextLine();
		System.out.println("Original Message : " + secretMessage);
		byte[] stringToEncrypt = secretMessage.getBytes();
		byte[] encryptedData = encryptData(stringToEncrypt, certificate);
		System.out.println("Encrypted Message : " + new String(encryptedData));
		byte[] rawData = decryptData(encryptedData,privKey);
		String decryptedMessage = new String(rawData);
		System.out.println("Decrypted Message : " + decryptedMessage);
		//--------------------------------------------------------------
		
		
		
		byte[] signedData = signData(rawData, certificate, privKey);
		System.out.println(signedData);
		Boolean check = verifSignedData(signedData);
		System.out.println(check);
		
	}
	public static byte[] encryptData(byte[] data,
			  X509Certificate encryptionCertificate)
			  throws CertificateEncodingException, IOException, CMSException {
			  
			    byte[] encryptedData = null;
			    if (null != data && null != encryptionCertificate) {
			        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator
			          = new CMSEnvelopedDataGenerator();
			  
			        JceKeyTransRecipientInfoGenerator jceKey 
			          = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
			        cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
			        CMSTypedData msg = new CMSProcessableByteArray(data);
			        OutputEncryptor encryptor
			          = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
			          .setProvider("BC").build();
			        CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
			          .generate(msg,encryptor);
			        encryptedData = cmsEnvelopedData.getEncoded();
			    }
			    return encryptedData;
			}
	public static byte[] decryptData(
			  byte[] encryptedData, 
			  PrivateKey decryptionKey) 
			  throws CMSException {
			  
			    byte[] decryptedData = null;
			    if (null != encryptedData && null != decryptionKey) {
			        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
			  
			        Collection<RecipientInformation> recipients
			          = envelopedData.getRecipientInfos().getRecipients();
			        KeyTransRecipientInformation recipientInfo 
			          = (KeyTransRecipientInformation) recipients.iterator().next();
			        JceKeyTransRecipient recipient
			          = new JceKeyTransEnvelopedRecipient(decryptionKey);
			         
			        return recipientInfo.getContent(recipient);
			    }
			    return decryptedData;
			}
	public static byte[] signData(
			  byte[] data, 
			  X509Certificate signingCertificate,
			  PrivateKey signingKey) throws Exception {
			  
			    byte[] signedMessage = null;
			    List<X509Certificate> certList = new ArrayList<X509Certificate>();
			    CMSTypedData cmsData= new CMSProcessableByteArray(data);
			    certList.add(signingCertificate);
			    Store<?> certs = new JcaCertStore(certList);
			 
			    CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
			    ContentSigner contentSigner 
			      = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
			    cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
			      new JcaDigestCalculatorProviderBuilder().setProvider("BC")
			      .build()).build(contentSigner, signingCertificate));
			    cmsGenerator.addCertificates(certs);
			     
			    CMSSignedData cms = cmsGenerator.generate(cmsData, true);
			    signedMessage = cms.getEncoded();
			    return signedMessage;
			}
	public static boolean verifSignedData(byte[] signedData)
			  throws Exception {
			  
			    X509Certificate signCert = null;
			    ByteArrayInputStream inputStream
			     = new ByteArrayInputStream(signedData);
			    ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
			    CMSSignedData cmsSignedData = new CMSSignedData(
			      ContentInfo.getInstance(asnInputStream.readObject()));
			    Store<?> store = cmsSignedData.getCertificates(); 
		        SignerInformationStore signers = cmsSignedData.getSignerInfos(); 
		        Collection<?> c = signers.getSigners(); 
		        Iterator<?> it = c.iterator();
		        while (it.hasNext()) { 
		            SignerInformation signer = (SignerInformation) it.next(); 
		            Collection<?> certCollection = store.getMatches(signer.getSID()); 
		            Iterator<?> certIt = certCollection.iterator();
		            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
		            X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
		            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData))) {
		                System.out.println("Signature verified");
		                return true;
		            }
		            
	}
		        System.out.println("Signature verification failed");
				return false;

	}
	}
