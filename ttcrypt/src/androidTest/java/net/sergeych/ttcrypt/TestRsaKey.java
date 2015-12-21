package net.sergeych.ttcrypt;
import junit.framework.TestCase;
import net.sergeych.ttcrypt.RsaKey;


public class TestRsaKey extends TestCase {

	protected RsaKey key;
	
	protected void setUp() throws Exception {
		super.setUp();
		key = new RsaKey(1024);
	}
	
	public void assertArrayEquals( byte[] a, byte[] b) {
		if( a.length != b.length )
			fail("Array length error: "+a.length+", "+b.length);
		for( int i=0; i<a.length; i++ ) {
			if( a[i] != b[i] )
				fail("Arrays are different at index: "+i);
		}
	}
	
	public void testLoading() throws Exception {
		assertTrue(RsaKey.selfTest());
		assertNotNull(RsaKey.VERSION);
		assertEquals(1024, key.bits());
		assertArrayEquals(new byte[] { 0x01, 0x00, 0x01 },key.getParam("e"));
	}
	
	public void testSign() throws Exception {
		String message = "Hello all";
		byte[] signature = key.sign(message.getBytes(), RsaKey.SHA1);
		assertEquals(128,  signature.length);
		assertTrue(key.verify(message.getBytes(), signature, RsaKey.SHA1));

		signature = key.sign(message.getBytes(), RsaKey.SHA256);
		assertEquals(128,  signature.length);
		assertTrue(key.verify(message.getBytes(), signature, RsaKey.SHA256));
	}
	
	public void testUsingParameters() throws Exception {
		String message = "foobar";
		RsaKey k2 = RsaKey.fromEPQ(key.getE(), key.getP(), key.getQ());
		byte[] signature = k2.sign(message.getBytes(), RsaKey.SHA1);
		assertEquals(128,  signature.length);
		assertTrue(key.verify(message.getBytes(), signature, RsaKey.SHA1));
		assertTrue(key.hasPrivate());
		assertTrue(k2.hasPrivate());
		RsaKey pubk = k2.getPublic();
		assertFalse(pubk.hasPrivate());
		assertTrue(pubk.verify(message.getBytes(), signature, RsaKey.SHA1));
//		assertEquals(key, k2);
//		assertFalse(key.equals(pubk));
	}

}
