package net.sergeych.ttcrypt;

/**
 * Created by sergeych on 04/01/16.
 */
public class RJ256 implements BlockCipher {

    private byte[] key;

    public RJ256(byte[] key) {
        if( key.length != 32 )
            throw new IllegalArgumentException("illegal key size");
        this.key = key;
    }

    static native void _cipherBlock(boolean encrypt,byte[] key, byte[] block);

    @Override
    public void processBlock(boolean encrypt, byte[] data) {
        if( data.length != 32 )
            throw new IllegalArgumentException("illegal data size");
        _cipherBlock(encrypt, key, data);
    }

    static {
        // The order is VITAL!
        System.loadLibrary("gmp");
        System.loadLibrary("ttcrypt");
    }

}
