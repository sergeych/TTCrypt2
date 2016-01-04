package net.sergeych.ttcrypt;

import junit.framework.TestCase;

import java.util.Arrays;

/**
 * Created by sergeych on 04/01/16.
 */
public class TestRJCipher extends TestCase  {

    public void testBlockCipher() throws Exception {
        byte[] key = "0123456789abcdef0123456789ABCDEF".getBytes();
        byte[] src = "Hello world! I'm gladd to see ya".getBytes();
        byte[] data = src.clone();
        RJ256 cipher = new RJ256(key);
        assertTrue(Arrays.equals(src, data));
        cipher.processBlock(true, data);
        assertFalse(Arrays.equals(src, data));
        cipher.processBlock(false, data);
        assertTrue(Arrays.equals(src, data));
    }
}
