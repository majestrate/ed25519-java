
import java.io.PrintStream;
import java.util.Random;
/**
 * JNI Wrapper Class for ref10 implementation of curve25519
 * Highly Based off https://github.com/krm2/ed25519-java 
 * 
 * @author Jeff Becker
 *
 */
public class Curve25519
{
    static {
        System.loadLibrary("Curve25519");
    }

    private static native int _sig_length();
    private static native int _pubkey_length();
    private static native int _seckey_length();

    public static final int SIG_LENGTH = _sig_length();
    public static final int PUBKEY_LENGTH = _pubkey_length();
    public static final int SECKEY_LENGTH = _seckey_length();

    protected static native byte [] _crypto_sign(byte [] msg, byte [] sk);
    protected static native boolean _crypto_verify(byte [] sig, byte [] msg, byte [] pk); 


    /**
     * Calculate the public key from the given seed.
     * @param sk The private seed.
     * @return The 32-byte public key.
     */
    public static native byte [] publickey(byte[] sk); 


    /**
     * Sign a message 
     * @param msg The message to be signed.
     * @param sk The private seed.
     * @return The 64-byte signature (R+S).
     */
    public static byte [] signature(byte [] msg, byte [] sk) throws Exception {
        if (sk.length != SECKEY_LENGTH ) { throw new Exception("invalid secret key size"); }

        return _crypto_sign(msg, sk); 
    }

    /**
     * Check the validity of a signature.
     * @param sig The signature to validate.
     * @param msg The message.
     * @param pk The 32-byte public key.
     * @return true if signature is valid
     */
    public static boolean checkvalid(byte [] sig, byte [] msg, byte [] pk) throws Exception {
        if (sig.length != SIG_LENGTH ) { throw new Exception("signature length is wrong"); }
        if (pk.length != PUBKEY_LENGTH ) { throw new Exception("public-key length is wrong"); }

        return _crypto_verify(sig, msg, pk);
    }

    private static String dump(byte [] ba) {
        String str = "";
        for ( byte b : ba ) str += String.format("%02x", b);
        return str;
    }

    /**
       Used to test if the native implementation works
     */
    public static void main(String [] args) throws Exception {
       
        PrintStream out = System.out;
        Random rand = new Random();

        byte [] sk = new byte[Curve25519.SECKEY_LENGTH];
        out.println("sklen = " + Curve25519.SECKEY_LENGTH);
        out.println("pklen = " + Curve25519.PUBKEY_LENGTH);
        out.println("sig   = " + Curve25519.SIG_LENGTH);
                    
        //rand.nextBytes(sk);
        out.println("sk    = "+dump(sk));
        
        byte [] data = "0123456789".getBytes();
        out.println("data  = "+dump(data));  
       
        byte [] pk = Curve25519.publickey(sk);
        out.println("pk    = "+dump(pk));
       
        byte [] sig = Curve25519.signature(data, sk);
        out.println("sig   = "+dump(sig));
        
        if ( ! Curve25519.checkvalid(sig, data, pk) ) { out.print("X"); return; }
        else { out.print("."); }
        
        out.println("OMGWTFBBQ!");
        
    }
}
