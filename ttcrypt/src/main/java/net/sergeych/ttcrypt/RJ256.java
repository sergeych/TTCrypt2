package net.sergeych.ttcrypt;

import android.util.Log;

/**
 * Created by sergeych on 04/01/16.
 */
public class RJ256 extends NativeBase implements BlockCipher {

    public RJ256(byte[] key) {
        if( key.length != 32 )
            throw new IllegalArgumentException("illegal key size");
        _setKey(key);
    }

    private native void _setKey(byte[] key);

    @Override
    public native void processBlock(boolean encrypt,byte[] data);

}
