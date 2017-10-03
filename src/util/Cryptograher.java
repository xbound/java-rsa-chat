package util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class Cryptograher
{
    private Cipher cipher;
    private SecureRandom secureRandom;
    private KeyPairGenerator keyPairGenerator;

    public Cryptograher()
    {
        try
        {
            this.cipher = Cipher.getInstance("RSA");
            this.secureRandom = new SecureRandom();
            keyPairGenerator  = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {e.printStackTrace();}

    }

    public byte[] encrypt(byte [] bytesToEncrypt,Key encryptKey) throws Exception
    {
        this.cipher.init(Cipher.ENCRYPT_MODE,encryptKey);
        return blockCipher(bytesToEncrypt,Cipher.ENCRYPT_MODE);
    }

    public byte[] decrypt(byte [] encrypted,Key decryptKey) throws Exception
    {
        this.cipher.init(Cipher.DECRYPT_MODE,decryptKey);
        return blockCipher(encrypted,Cipher.DECRYPT_MODE);
    }

    public KeyPair generateKeyPair()
    {
        return keyPairGenerator.generateKeyPair();
    }

    private byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException{
        byte[] scrambled = new byte[0];
        byte[] toReturn = new byte[0];
        int length = (mode == Cipher.ENCRYPT_MODE)? 100 : 128;
        byte[] buffer = new byte[length];
        for (int i=0; i< bytes.length; i++)
        {
            if ((i > 0) && (i % length == 0))
            {
                scrambled = cipher.doFinal(buffer);
                toReturn = append(toReturn,scrambled);
                int newlength = length;
                if (i + length > bytes.length)
                {
                    newlength = bytes.length - i;
                }
                buffer = new byte[newlength];
            }
            buffer[i%length] = bytes[i];
        }
        scrambled = cipher.doFinal(buffer);
        toReturn = append(toReturn,scrambled);
        return toReturn;
    }

    private byte[] append(byte[] prefix, byte[] suffix)
    {
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i=0; i< prefix.length; i++)
        {
            toReturn[i] = prefix[i];
        }
        for (int i=0; i< suffix.length; i++)
        {
            toReturn[i+prefix.length] = suffix[i];
        }
        return toReturn;
    }

    public byte[] randomIdentifyingString(int size)
    {
        byte [] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
