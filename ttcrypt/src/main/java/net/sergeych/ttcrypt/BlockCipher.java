package net.sergeych.ttcrypt;

/**
 * Created by sergeych on 04/01/16.
 */
public interface BlockCipher {
    void processBlock(boolean encrypt, byte[] data) throws Error;
}
