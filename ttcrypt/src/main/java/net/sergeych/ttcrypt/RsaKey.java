package net.sergeych.ttcrypt;

import java.util.Arrays;
import java.util.Map;

import android.annotation.SuppressLint;
import android.util.Log;

/**
 * Fast native modern pkcs#1 v2.2, RSAES-OAEP and RSASSA-PSS, only strong
 * padding. No weak algorithms are supported. Compatible with modern android
 * flavors. This is a port ot TTCrypt package to java and android.
 * 
 * Please note that this is a limited interface yet under construction.
 * 
 * Near future todos:
 * 
 * - add blinding control - add OAEP methods
 * 
 * Created by sergeych on 20.06.14.
 */
@SuppressLint("DefaultLocale")
public class RsaKey {

	/**
	 * Any RSA-specific error: wrong padding, message too long, wrong padding,
	 * etc.
	 * 
	 * @author sergeych
	 */
	static public class Error extends Exception {
		private static final long serialVersionUID = 1L;

		public Error(String reason) {
			super(reason);
		}
	}

	public static final String VERSION = "0.0.2";

	/**
	 * Use SHA1 hash in sign/verify
	 */
	static public final int SHA1 = 0;
	/**
	 * Use SHA256 hash in sign/verify
	 */
	static public final int SHA256 = 1;

	/**
	 * Check that your platform perform calcs in a correct manner. If this
	 * method fails or throws anything, you shoud send report and use java
	 * version of the library
	 * 
	 * @return true if the platform supports all necessary calculations in the
	 *         correct manner.
	 */
	public native static boolean selfTest();

	private RsaKey() {
	}

	/**
	 * Create random RSA key of the specified strength
	 */
	public RsaKey(int bitStrength) {
		generate(bitStrength);
	}

	/**
	 * Create a key from components. Allowed components names are 'e' and 'n'
	 * for a public key, and (currently) 'p', 'q' and 'e' for a private key.
	 * 
	 * @param params
	 */
	public RsaKey(Map<String, byte[]> params) {
		for (Map.Entry<String, byte[]> e : params.entrySet()) {
			setParam(e.getKey(), e.getValue());
		}
		normalizeKey();
	}

	/**
	 * Sign a given message using SHA256 signature and RSASSA-PSS process
	 * (pkcs#1 v2.2)
	 * 
	 * @param message
	 *            converted to bytes, no size limits.
	 * @return binary signature
	 * @throws Error
	 *             if the key is too short for SHA256 hash
	 */
	public byte[] sign(byte[] message) throws Error {
		return sign(message, SHA256);
	}

	/**
	 * Sign a given message using SHA1/SHA256 signature and RSASSA-PSS process
	 * (pkcs#1 v2.2). This method requires private key.
	 * 
	 * @param message
	 *            message to sign, any size
	 * @param hashTypeId
	 *            integer hash method constant (either {@link #SHA1} or
	 *            {@link #SHA256}
	 * @return binary signature
	 * @throws Error
	 *             if key size is not enough for the signarue (either use SHA1
	 *             or stronger key)
	 */
	public byte[] sign(byte[] message, int hashTypeId) throws Error {
		return _sign(message, hashTypeId);
	}

	/**
	 * Verify a message using SHA256/SHA1 signature and RSASSA-PSS process
	 * (pkcs#1 v2.2). This method requires private key.
	 * 
	 * @param message
	 *            message to check
	 * @param signature
	 *            the signature to test
	 * @param hashTypeId
	 *            should be exactly same as used when signing
	 * @return true if the signature is consistent and false in all other cases.
	 */
	public boolean verify(byte[] message, byte[] signature, int hashTypeId) {
		return _verify(message, signature, hashTypeId);
	}

	/**
	 * Verify a message using SHA256 signature and RSASSA-PSS process (pkcs#1
	 * v2.2)
	 * 
	 * @param message
	 *            message to check
	 * @param signature
	 *            the signature to test
	 * @return true if the signature is consistent and false in all other cases.
	 */
	public boolean verify(byte[] message, byte[] signature) throws Error {
		return verify(message, signature, SHA256);
	}

	public native byte[] getParam(String name);

	/**
	 * @return public exponent
	 */
	public byte[] getE() {
		return getParam("e");
	}

	/**
	 * @return p-part of a private key
	 */
	public byte[] getP() {
		return getParam("p");
	}

	/**
	 * @return q-part of a private key
	 */
	public byte[] getQ() {
		return getParam("q");
	}

	/**
	 * @return public modulo (part of a public key)
	 */

	public byte[] getN() {
		return getParam("n");
	}

	/**
	 * Construct a private key from components
	 * 
	 * @param e
	 * @param p
	 * @param q
	 * @return generated key
	 * @throws Exception
	 *             of components are inconsistent (not always)
	 */
	static public RsaKey fromEPQ(byte[] e, byte[] p, byte[] q) throws Exception {
		RsaKey k = new RsaKey();
		k.setParam("e", e);
		k.setParam("p", p);
		k.setParam("q", q);
		k.normalizeKey();
		return k;
	}

	/**
	 * Construct a public key from components
	 * 
	 * @param n
	 * @param e
	 * @return public key instance
	 */
	public static RsaKey fromNE(byte[] n, byte[] e) {
		RsaKey k = new RsaKey();
		k.setParam("e", e);
		k.setParam("n", n);
		k.normalizeKey();
		return k;
	}

	/**
	 * Extracts public instance out of this key (either private or public)
	 * 
	 * @return instance not containing private key parts.
	 */
	public RsaKey getPublic() {
		return RsaKey.fromNE(getN(), getE());
	}

	/**
	 * Frees allocated C++ resources
	 */
	@Override
	protected void finalize() {
		Log.i("RSA", "Freeing up resources");
		freeResources();
	}

//	public native void testBytes(byte[] data);

	/**
	 * @return true if this instance contains private key
	 */
	public final native boolean hasPrivate();

	/**
	 * @return strength in bits of this key instance
	 */
	public final native int bits();

	/**
	 * Keys are equal if are of the same type and components. To check whether
	 * some public key fits some private key, use instead something like:
	 * 
	 * <pre>
	 * publicKey.equals(privateKey.getPublic())
	 * </pre>
	 */
	@Override
	public boolean equals(Object other) {
		if (other instanceof RsaKey) {
			RsaKey k = (RsaKey) other;
			if (k.hasPrivate() != hasPrivate())
				return false;
			if (!Arrays.equals(getE(), k.getE()))
				return false;
			if (hasPrivate()) {
				if (!Arrays.equals(getP(), k.getP())
						|| !Arrays.equals(getQ(), k.getQ()))
					return false;
			} else {
				if (!Arrays.equals(getN(), k.getN()))
					return false;
			}
			return true;
		}
		return false;
	}

	/**
	 * RsaKey can be used as hashtable keys too, either public and private ones.
	 */
	@Override
	public int hashCode() {
		return getN().hashCode();
	};

	private final native void generate(int bitStrength);

	private final native void setParam(String param, byte[] data);

	private final native void normalizeKey();

	private final native byte[] _sign(byte[] message, int hashId);

	private final native boolean _verify(byte[] message, byte[] signature,
			int hashId);

	private final native void freeResources();

	private long instancePtr;

	// This implements custom static initialization
	private native static void staticInit();

	static {
		// The order is VITAL!
		System.loadLibrary("gmp");
		System.loadLibrary("ttcrypt");
		staticInit();
	}
}
