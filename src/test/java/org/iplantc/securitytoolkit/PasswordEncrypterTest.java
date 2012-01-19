package org.iplantc.securitytoolkit;

import static org.junit.Assert.*;

import javax.security.auth.login.LoginException;

import org.iplantc.securitytoolkit.PasswordEncrypter;
import org.junit.Test;

/**
 * Unit tests for org.iplantc.idpauthn.
 *
 * @author Dennis Roberts
 */
public class PasswordEncrypterTest {

    /**
     * Verifies that we can encrypt a password.
     *
     * @throws LoginException if the encryption attempt fails.
     */
    @Test
    public void shouldEncryptPassword() throws LoginException {
        PasswordEncrypter encrypter = new PasswordEncrypter("SHA-512", "UTF-8");
        String actual = encrypter.encryptPassword("da password");
        String expected = "/aRPkL0JBuNHS/ZVBaHWEA5dTLxiFdZxEoKWURnaZ+tF+BJjtZ76Ms0b2pRZ23RwhRHh/Ld1xD3ay+KKnSTQew==";
        assertEquals(expected, actual);
    }
    
    /**
     * Verifies that we get a LoginException if the hash algorithm is invalid.
     *
     * @throws LoginException if the password can't be encrypted.
     */
    @Test(expected=LoginException.class)
    public void shouldGetLoginExceptionForInvalidHashAlgorithm() throws LoginException {
        PasswordEncrypter encrypter = new PasswordEncrypter("BLARGUS-SHANUS", "UTF-8");
        encrypter.encryptPassword("da password");
    }

    /**
     * Verifies that we get a LoginException if the character encoding is invalid.
     *
     * @throws LoginException if the password can't be encrypted.
     */
    @Test(expected=LoginException.class)
    public void shouldGetLoginExceptionForInvalidCharacterEncoding() throws LoginException {
        PasswordEncrypter encrypter = new PasswordEncrypter("SHA-512", "CHARACTUS-ENCODINGUS");
        encrypter.encryptPassword("da password");
    }
}
