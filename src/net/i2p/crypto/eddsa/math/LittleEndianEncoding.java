package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

public class LittleEndianEncoding implements Encoding {
    @Override
    public byte[] encode(BigInteger x, int len) {
        byte[] in = x.toByteArray();
        byte[] out = new byte[len];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return out;
    }

    @Override
    public BigInteger decode(byte[] in) {
        // Convert 'in' to big endian
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        //XXX is it always positive?
        return new BigInteger(1, out);
    }
}
