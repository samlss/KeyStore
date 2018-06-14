package com.iigo.keystore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.text.TextUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

/**
 * @author SamLeung
 * @Emial 729717222@qq.com
 * @date 2018/6/14 0014 12:15
 */
public class KeyStoreUtil {
    private static KeyStoreUtil INSTANCE;
    private static Object LOCK = new Object();
    private KeyStore keyStore;
    private X500Principal x500Principal; //自签署证书
    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private KeyStoreUtil(){
        init();
    }

    private void init() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            /**
             *   CN      commonName
             *   O       organizationName
             *   OU      organizationalUnitName
             *   C       countryName
             * */
            x500Principal = new X500Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static KeyStoreUtil get(){
        if (INSTANCE == null){
            synchronized (LOCK){
                if (INSTANCE == null){
                    INSTANCE = new KeyStoreUtil();
                }
            }
        }

        return INSTANCE;
    }


    /**
     * 获取当前应用密钥库中的条目
     *
     * @return
     * */
    public Enumeration<String> getAliases(){
        if (keyStore == null) {
            return null;
        }

        try {
            return keyStore.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 先判断是否存在该别名
     * */
    public boolean containsAlias(String alias) {
        if (keyStore == null || TextUtils.isEmpty(alias)){
            return false;
        }

        boolean contains = false;
        try{
            contains = keyStore.containsAlias(alias);
        }catch (Exception e){
            e.printStackTrace();
        }
        return contains;
    }

    /**
     * 生成新的密钥
     *
     * @param context
     * @param alias 存储在KeyStore中的别名
     * */
    public KeyPair generateKey(Context context, String alias){
        if (containsAlias(alias)){
            return null;
        }

        try {
            Calendar endDate = Calendar.getInstance();
            endDate.add(Calendar.YEAR, 10);

            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context.getApplicationContext())
                    .setAlias(alias)
                    .setSubject(x500Principal)
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(Calendar.getInstance().getTime())
                    .setEndDate(endDate.getTime())
                    .build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);

            return  generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NullPointerException e){
            e.printStackTrace();
        }

        return null;
    }

    public void deleteKey(final String alias){
        try{
            keyStore.deleteEntry(alias);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 加密
     *
     * @param data 要加密的数据
     * @param alias KeyStore中的别名
     * */
    public byte[] encrypt(byte[] data, String alias){
        try {
            //取出密钥
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 解密
     *
     * @param data 要解密的数据
     * @param alias KeyStore中的别名
     * */
    public byte[] decrypt(byte[] data, String alias){
        try {
            //取出密钥
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 对数据进行签名
     *
     * @param data
     * @param alias
     * */
    public byte[] sign(byte[] data, String alias){
        try{
            //取出密钥
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initSign(privateKeyEntry.getPrivateKey());
            s.update(data);
            return s.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }


    /**
     * 验证数据签名
     *
     * @param data 原始数据
     * @param signatureData 签署的数据
     * @param alias
     * */
    public boolean verify (byte[] data, byte[] signatureData, String alias){
        try{
            //取出密钥
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);

            Signature s = Signature.getInstance("SHA1withRSA");
            s.initVerify(privateKeyEntry.getCertificate());
            s.update(data);
            return s.verify(signatureData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }
}
