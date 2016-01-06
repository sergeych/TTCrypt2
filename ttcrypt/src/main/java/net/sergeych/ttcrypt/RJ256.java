package net.sergeych.ttcrypt;

import android.util.Log;

/**
 * Created by sergeych on 04/01/16.
 */
public class RJ256 implements BlockCipher {

    public RJ256(byte[] key) {
        if( key.length != 32 )
            throw new IllegalArgumentException("illegal key size");
        _setKey(key);
    }

    private native void _setKey(byte[] key);

    @Override
    public native void processBlock(boolean encrypt,byte[] data);

    /**
     * Frees allocated C++ resources
     */
    @Override
    protected void finalize() {
        Log.i("RJ256", "Freeing up resources");
        freeResources();
    }

    private final native void freeResources();
    private long instancePtr;

    static {
        // The order is VITAL!
        RsaKey.initLibrary();
    }

}
