package org.example.txemasv.securestorage;

import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


class DeCryptor {

    /**
     * Supported Algorithms
     * @see <a href="https://developer.android.com/training/articles/keystore.html#SupportedAlgorithms">Android doc</a>
     */
    private static final String TRANSFORMATION_A23 = "AES/GCM/NoPadding";
    private static final String TRANSFORMATION_B23 = "RSA/ECB/PKCS1Padding";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TAG = DeCryptor.class.getSimpleName();

    private KeyStore keyStore;

    private String finalText;

    DeCryptor() throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException {
        initKeyStore();
    }

    private void initKeyStore() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
    }

    /**
     * Decrypt saved data into plain text.
     * Select the correct method independently of the Android API Version.
     *
     * @return String with the decrypted text
     */
    String decryptData(final String alias, final byte[] encryptedData, final byte[] encryptionIv) throws IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return decryptAfterApi23(alias, encryptedData, encryptionIv);
        } else {
            return decryptBeforeApi23(alias, encryptedData);
        }
    }

    /**
     * Decrypt saved data into plain text.
     * Supported: API >= 23
     *
     * @return String with the encrypted text
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private String decryptAfterApi23(final String alias, final byte[] encryptedData, final byte[] encryptionIv)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION_A23);
        final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);

        SecretKey secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return new String(cipher.doFinal(encryptedData), "UTF-8");
    }


    /**
     * Decrypt saved data into plain text.
     * Supported: 19 <= API < 23
     *
     * @return String with the encrypted text
     */
    private String decryptBeforeApi23(final String alias, final byte[] encryptedData) {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance(TRANSFORMATION_B23, "AndroidOpenSSL");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            String cipherText = Base64.encodeToString(encryptedData, Base64.DEFAULT);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();

            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            finalText = new String(bytes, 0, bytes.length, "UTF-8");

        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }

        return finalText;
    }
}