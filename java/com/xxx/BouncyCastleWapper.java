package com.xxx;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

import java.security.cert.Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceParser;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class BouncyCastleWapper {

  public static void initProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void generateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, IOException, InvalidKeyException, SignatureException {
        String userID = "1234567812345678";
//        userID = "lixf@vma.com";
        KeyPairGenerator kenGen = KeyPairGenerator.getInstance("EC", "BC");
        kenGen.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = kenGen.generateKeyPair();
        System.out.println(keyPair.getPrivate().getClass().getName());
        System.out.println(keyPair.getPublic().getClass().getName());
        JcaPEMWriter writer = new JcaPEMWriter(new FileWriter("privateKey.pem"));
        writer.writeObject(keyPair.getPrivate());
        writer.flush();
        writer.close();
        writer = new JcaPEMWriter(new FileWriter("publicKey.pem"));
        writer.writeObject(keyPair.getPublic());
        writer.flush();
        writer.close();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.ST, "GD");
        builder.addRDN(BCStyle.L, "SZ");
        builder.addRDN(BCStyle.O, "vma");
        builder.addRDN(BCStyle.E, "lixf@aliyun.com");
        builder.addRDN(BCStyle.CN, "lixf");
        X500Name name = builder.build();
        ContentSigner sigGen = new JcaContentSignerBuilder("SM3WITHSM2").setProvider("BC").build(keyPair.getPrivate());
        Calendar date = Calendar.getInstance();
        Date fromDate = date.getTime();
        date.add(Calendar.YEAR, 1);
        Date toDate = date.getTime();
        JcaX509v3CertificateBuilder x509v3CertGen = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(1), fromDate, toDate, name, keyPair.getPublic());
        X509Certificate x509V3Cert =  new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509v3CertGen.build(sigGen));
        System.out.println("x509V3Cert = " + x509V3Cert);
        writer = new JcaPEMWriter(new FileWriter("cert.pem"));
        writer.writeObject(x509V3Cert);
        writer.flush();
        writer.close();

        String content = "test sm3withsm2 content";
        Signature signer = Signature.getInstance("SM3withSM2", "BC");
        signer.setParameter(new SM2ParameterSpec(userID.getBytes()));
        signer.initSign(keyPair.getPrivate());
        signer.update(content.getBytes());
        byte[] signResult = signer.sign();

        Signature verify = Signature.getInstance("SM3withSM2", "BC");
        signer.setParameter(new SM2ParameterSpec(userID.getBytes()));
        signer.initVerify(keyPair.getPublic());
        signer.update(content.getBytes());
        boolean verifyFlag = signer.verify(signResult);
        System.out.println(verifyFlag);
        OutputStream signFile = new FileOutputStream("signResult.dat");
        signFile.write(signResult);
        signFile.flush();
        signFile.close();
    }
}
