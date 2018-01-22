package org.example.txemasv.securestorage;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String ALIAS = "BankAccount";

    private String textToEncrypt = "ES91 2100 0418 4502 0005 1332";

    private EnCryptor encryptor;
    private DeCryptor decryptor;
    private TextView outputText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        outputText = findViewById(R.id.output);

        encryptor = new EnCryptor();
        encryptText();

        try {
            decryptor = new DeCryptor();
            decryptText();

        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException |
                IOException e) {
            e.printStackTrace();
        }
    }

    private void encryptText() {
        try {
            outputText.setText("");
            outputText.append("1) ENCRYPT (For Android API " + android.os.Build.VERSION.SDK_INT + ")");
            outputText.append("\n\nALIAS : " + ALIAS);
            outputText.append("\n\nText to encrypt : " + textToEncrypt);
            outputText.append("\n\nEncrypting ....");

            final byte[] encryptedText = encryptor.encryptText(ALIAS, textToEncrypt, this);
            String encryptedTextValue = Base64.encodeToString(encryptedText, Base64.DEFAULT);

            outputText.append("\n\nEncrypted text: \n\n" + encryptedTextValue);

        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException |
                KeyStoreException | IOException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | SignatureException |
                IllegalBlockSizeException | BadPaddingException | CertificateException e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    private void decryptText() {
        try {
            outputText.append("\n\n\n\n2) DECRYPT (For Android API " + android.os.Build.VERSION.SDK_INT + ")");
            outputText.append("\n\nALIAS : " + ALIAS);
            outputText.append("\n\nDecrypting (from alias '" + ALIAS + "')....");

            String decryptedTextValue = decryptor.decryptData(ALIAS, encryptor.getEncryption(), encryptor.getIv());

            outputText.append("\n\nDecrypted text : \n\n" + decryptedTextValue);

        } catch (UnrecoverableEntryException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchPaddingException | NoSuchProviderException |
                IOException | InvalidKeyException e) {
            Log.e(TAG, "decryptData() called with: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
