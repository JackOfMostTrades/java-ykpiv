package com.github.jackofmosttrades.ykpiv;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class SimpleAsn1Test {
    /**
     * Test parsing out an ASN.1 object with a long tag.
     */
    @Test
    public void testLongTag() {
        final ByteString data = ByteString.copyOf(new byte[] { 127, 73, -126, 1, 9, -127, -126, 1, 0, -102, -10, 124, -71, 76, 14, 123, -83, -109, -98, -2, 27, 34, -51, -48, 36, -55, 52, 14, 22, -32, -12, 119, -94, 89, -32, 110, -98, -116, -119, -111, 85, 98, -44, -115, -17, -85, -128, 73, -15, -77, -39, 62, -20, 68, 40, 39, 105, -126, -16, 21, -17, -86, 71, 117, -81, 50, 99, 69, 54, -27, -45, -3, 87, -112, 13, -6, 96, 96, 50, 4, 40, 121, -45, 10, 36, -96, 24, 111, -126, 82, -55, -69, -76, -65, -9, 60, -9, 14, -113, 16, 91, 93, 70, 63, 100, 31, 57, 52, -86, -48, 54, -54, -56, -78, -92, 50, -63, 122, -80, 79, -18, 24, 53, 51, -12, -114, -124, 33, -87, -125, 38, 120, 93, 34, -19, 117, 101, -12, 44, 27, -71, 30, -95, -82, 73, 21, 54, -118, -30, -30, -112, 92, 86, 49, -90, -73, 47, -5, -57, 91, -102, 86, -45, -43, -57, 94, 11, 84, 54, -22, -33, -16, 115, -116, 81, 65, -87, 97, 6, -45, -50, -95, -35, 29, -81, -108, -21, 19, -49, 117, -24, -78, -95, 24, 61, -52, -60, 71, 38, -21, 12, 114, -82, -1, 33, -39, -95, -13, -5, -97, 87, -36, 43, -17, -83, 45, 32, 88, -107, 44, -63, 33, -55, 16, -24, -95, 101, -88, -32, 115, 45, 98, -13, 102, 42, 27, -105, 9, 126, -65, -43, 5, -117, -108, 110, -44, 62, -111, -70, 49, 100, -113, -69, -67, -43, 59, 121, -54, 111, -43, 53, 16, -21, 109, -59, -126, 3, 1, 0, 1 });
        List<SimpleAsn1.Asn1Object> objects = SimpleAsn1.decode(data);
        Assert.assertEquals(1, objects.size());
        Assert.assertEquals(0x49, objects.get(0).getTag());
        objects = SimpleAsn1.decode(objects.get(0).getData());
        Assert.assertEquals(2, objects.size());
        Assert.assertEquals(0x81, objects.get(0).getTag());
        Assert.assertEquals(0x82, objects.get(1).getTag());
        Assert.assertEquals(ByteString.copyOf(new byte[]{ 1, 0, 1 }), objects.get(1).getData());
    }
}
