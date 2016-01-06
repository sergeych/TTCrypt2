package net.sergeych.ttcrypt;

import android.util.Log;

/**
 * Created by sergeych on 07/01/16.
 */
public class NativeBase {
    private long instancePtr;

    /**
     * Frees allocated C++ resources
     */
    @Override
    protected void finalize() {
        Log.i("RJ256", "Freeing up resources");
        freeResources();
    }

    // Each subclass MUST override!
    private final native void freeResources();

    // This implements custom static initialization
    private native static void staticInit();

    static {
        // The order is VITAL!
        System.loadLibrary("gmp");
        System.loadLibrary("ttcrypt");
        staticInit();
    }
}
