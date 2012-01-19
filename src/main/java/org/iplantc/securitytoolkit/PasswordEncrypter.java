package org.iplantc.securitytoolkit;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.security.auth.login.LoginException;

import org.apache.commons.codec.binary.Base64;

/**
 * Used to encrypt passwords.
 *
 * @author Dennis Roberts
 */
public class PasswordEncrypter {

    /**
     * The hash algorithm to use when encrypting the password.
     */
    private String hashAlgorithm;

    /**
     * The character encoding to use when encrypting the password.
     */
    private String characterEncoding;

    /**
     * Creates a new password encrypter using the given hash algorithm and character encoding.
     * 
     * @param hashAlgorithm the hash algorithm to use.
     * @param characterEncoding the character encoding to use.
     */
    public PasswordEncrypter(String hashAlgorithm, String characterEncoding) {
        this.hashAlgorithm = hashAlgorithm;
        this.characterEncoding = characterEncoding;
    }

    /**
     * Encrypts a password.
     *
     * @param password the password to encrypt.
     * @return the encrypted password.
     * @throws LoginException if the password can't be encrypted.
     */
    public String encryptPassword(String password) throws LoginException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
            messageDigest.update(password.getBytes(characterEncoding));
            byte[] passwordBytes = messageDigest.digest();
            return new String(Base64.encodeBase64(passwordBytes, false), characterEncoding);
        }
        catch (NoSuchAlgorithmException e) {
            throw new LoginException("hash algorithm not available: " + e);
        }
        catch (UnsupportedEncodingException e) {
            throw new LoginException("character encoding not available: " + e);
        }
    }
}
