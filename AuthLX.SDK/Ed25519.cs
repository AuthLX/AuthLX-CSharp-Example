using System;
using System.Security.Cryptography;
using System.Text;

namespace AuthLX
{
    public static class Ed25519
    {
        private static readonly long[] gf0 = new long[16];
        private static readonly long[] gf1 = new long[16] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static readonly long[] D = new long[16]
        {
            0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
            0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
        };
        private static readonly long[] D2 = new long[16]
        {
            0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
        };
        private static readonly long[] X = new long[16]
        {
            0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
            0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
        };
        private static readonly long[] Y = new long[16]
        {
            0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
        };
        private static readonly long[] I = new long[16]
        {
            0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
            0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
        };

        private static readonly ulong[] L = new ulong[32]
        {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
        };

        private static void set25519(long[] r, long[] a)
        {
            for (int i = 0; i < 16; ++i) r[i] = a[i];
        }

        private static void car25519(long[] o)
        {
            for (int i = 0; i < 16; ++i)
            {
                o[i] += (1L << 16);
                long c = o[i] >> 16;
                int nextIdx = (i < 15) ? (i + 1) : 0;
                o[nextIdx] += c - 1 + ((i == 15) ? 37 * (c - 1) : 0);
                o[i] -= (c << 16);
            }
        }

        private static void sel25519(long[] p, long[] q, int b)
        {
            long c = ~(b - 1);
            for (int i = 0; i < 16; ++i)
            {
                long t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        private static void pack25519(byte[] o, long[] n)
        {
            long[] t = new long[16];
            long[] m = new long[16];
            for (int i = 0; i < 16; ++i) t[i] = n[i];
            car25519(t);
            car25519(t);
            car25519(t);
            for (int j = 0; j < 2; ++j)
            {
                m[0] = t[0] - 0xffed;
                for (int i = 1; i < 15; ++i)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                int b = (int)((m[15] >> 16) & 1);
                m[14] &= 0xffff;
                sel25519(t, m, 1 - b);
            }
            for (int i = 0; i < 16; ++i)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        private static bool FixedTimeEquals32(byte[] a, byte[] b)
        {
            int diff = 0;
            for (int i = 0; i < 32; ++i)
                diff |= (a[i] ^ b[i]);
            return diff == 0;
        }

        private static bool neq25519(long[] a, long[] b)
        {
            byte[] c = new byte[32];
            byte[] d = new byte[32];
            pack25519(c, a);
            pack25519(d, b);
            return !FixedTimeEquals32(c, d);
        }

        private static byte par25519(long[] a)
        {
            byte[] d = new byte[32];
            pack25519(d, a);
            return (byte)(d[0] & 1);
        }

        private static void unpack25519(long[] o, byte[] n, int offset = 0)
        {
            for (int i = 0; i < 16; ++i)
            {
                o[i] = n[offset + 2 * i] + ((long)n[offset + 2 * i + 1] << 8);
            }
            o[15] &= 0x7fff;
        }

        private static void A(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
        }

        private static void Z(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
        }

        private static void M(long[] o, long[] a, long[] b)
        {
            long[] t = new long[31];
            for (int i = 0; i < 16; ++i)
                for (int j = 0; j < 16; ++j)
                    t[i + j] += a[i] * b[j];
            for (int i = 0; i < 15; ++i)
                t[i] += 38 * t[i + 16];
            for (int i = 0; i < 16; ++i)
                o[i] = t[i];
            car25519(o);
            car25519(o);
        }

        private static void S(long[] o, long[] a)
        {
            M(o, a, a);
        }

        private static void inv25519(long[] o, long[] i)
        {
            long[] c = new long[16];
            for (int a = 0; a < 16; ++a) c[a] = i[a];
            for (int a = 253; a >= 0; --a)
            {
                S(c, c);
                if (a != 2 && a != 4) M(c, c, i);
            }
            for (int a = 0; a < 16; ++a) o[a] = c[a];
        }

        private static void pow2523(long[] o, long[] i)
        {
            long[] c = new long[16];
            for (int a = 0; a < 16; ++a) c[a] = i[a];
            for (int a = 250; a >= 0; --a)
            {
                S(c, c);
                if (a != 1) M(c, c, i);
            }
            for (int a = 0; a < 16; ++a) o[a] = c[a];
        }

        private static void add(long[][] p, long[][] q)
        {
            long[] a = new long[16];
            long[] b = new long[16];
            long[] c = new long[16];
            long[] d = new long[16];
            long[] t = new long[16];
            long[] e = new long[16];
            long[] f = new long[16];
            long[] g = new long[16];
            long[] h = new long[16];

            Z(a, p[1], p[0]);
            Z(t, q[1], q[0]);
            M(a, a, t);
            A(b, p[0], p[1]);
            A(t, q[0], q[1]);
            M(b, b, t);
            M(c, p[3], q[3]);
            M(c, c, D2);
            M(d, p[2], q[2]);
            A(d, d, d);
            Z(e, b, a);
            Z(f, d, c);
            A(g, d, c);
            A(h, b, a);

            M(p[0], e, f);
            M(p[1], h, g);
            M(p[2], g, f);
            M(p[3], e, h);
        }

        private static void cswap(long[][] p, long[][] q, byte b)
        {
            for (int i = 0; i < 4; ++i)
                sel25519(p[i], q[i], b);
        }

        private static void pack(byte[] r, long[][] p)
        {
            long[] tx = new long[16];
            long[] ty = new long[16];
            long[] zi = new long[16];
            inv25519(zi, p[2]);
            M(tx, p[0], zi);
            M(ty, p[1], zi);
            pack25519(r, ty);
            r[31] ^= (byte)(par25519(tx) << 7);
        }

        private static void scalarmult(long[][] p, long[][] q, byte[] s, int sOffset = 0)
        {
            set25519(p[0], gf0);
            set25519(p[1], gf1);
            set25519(p[2], gf1);
            set25519(p[3], gf0);
            for (int i = 255; i >= 0; --i)
            {
                byte b = (byte)((s[sOffset + i / 8] >> (i & 7)) & 1);
                cswap(p, q, b);
                add(q, p);
                add(p, p);
                cswap(p, q, b);
            }
        }

        private static void scalarbase(long[][] p, byte[] s, int sOffset = 0)
        {
            long[][] q = new long[4][] { new long[16], new long[16], new long[16], new long[16] };
            set25519(q[0], X);
            set25519(q[1], Y);
            set25519(q[2], gf1);
            M(q[3], X, Y);
            scalarmult(p, q, s, sOffset);
        }

        private static void modL(byte[] r, long[] x)
        {
            long carry;
            for (int i = 63; i >= 32; --i)
            {
                carry = 0;
                int j;
                for (j = i - 32; j < i - 12; ++j)
                {
                    x[j] += carry - 16 * x[i] * (long)L[j - (i - 32)];
                    carry = (x[j] + 128) >> 8;
                    x[j] -= carry << 8;
                }
                x[j] += carry;
                x[i] = 0;
            }
            carry = 0;
            for (int j = 0; j < 32; ++j)
            {
                x[j] += carry - (x[31] >> 4) * (long)L[j];
                carry = x[j] >> 8;
                x[j] &= 255;
            }
            for (int j = 0; j < 32; ++j)
            {
                x[j] -= carry * (long)L[j];
            }
            for (int i = 0; i < 32; ++i)
            {
                x[i + 1] += x[i] >> 8;
                r[i] = (byte)(x[i] & 255);
            }
        }

        private static void reduce(byte[] r)
        {
            long[] x = new long[64];
            for (int i = 0; i < 64; ++i) x[i] = (long)r[i];
            for (int i = 0; i < 64; ++i) r[i] = 0;
            modL(r, x);
        }

        private static int unpackneg(long[][] r, byte[] p)
        {
            long[] t = new long[16];
            long[] chk = new long[16];
            long[] num = new long[16];
            long[] den = new long[16];
            long[] den2 = new long[16];
            long[] den4 = new long[16];
            long[] den6 = new long[16];

            set25519(r[2], gf1);
            unpack25519(r[1], p);
            S(num, r[1]);
            M(den, num, D);
            Z(num, num, r[2]);
            A(den, r[2], den);

            S(den2, den);
            S(den4, den2);
            M(den6, den4, den2);
            M(t, den6, num);
            M(t, t, den);

            pow2523(t, t);
            M(t, t, num);
            M(t, t, den);
            M(t, t, den);
            M(r[0], t, den);

            S(chk, r[0]);
            M(chk, chk, den);
            if (neq25519(chk, num)) M(r[0], r[0], I);

            S(chk, r[0]);
            M(chk, chk, den);
            if (neq25519(chk, num)) return -1;

            if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

            M(r[3], r[0], r[1]);
            return 0;
        }

        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            if (signature == null || signature.Length != 64 || publicKey == null || publicKey.Length != 32 || message == null)
                return false;

            byte[] sm = new byte[64 + message.Length];
            Buffer.BlockCopy(signature, 0, sm, 0, 64);
            Buffer.BlockCopy(message, 0, sm, 64, message.Length);

            byte[] t = new byte[32];
            byte[] h;
            long[][] p = new long[4][] { new long[16], new long[16], new long[16], new long[16] };
            long[][] q = new long[4][] { new long[16], new long[16], new long[16], new long[16] };

            if (unpackneg(q, publicKey) != 0) return false;

            byte[] m = new byte[sm.Length];
            Buffer.BlockCopy(sm, 0, m, 0, sm.Length);
            Buffer.BlockCopy(publicKey, 0, m, 32, 32);

            using (SHA512 sha512 = SHA512.Create())
            {
                h = sha512.ComputeHash(m);
            }

            reduce(h);
            scalarmult(p, q, h);

            scalarbase(q, sm, 32);
            add(p, q);
            pack(t, p);

            return FixedTimeEquals32(sm, t);
        }

        public static bool VerifyHex(string signatureHex, string message, string publicKeyHex)
        {
            if (string.IsNullOrEmpty(signatureHex) || signatureHex.Length != 128) return false;
            if (string.IsNullOrEmpty(publicKeyHex) || publicKeyHex.Length != 64) return false;
            if (message == null) return false;

            byte[] sigBytes = HexToBytes(signatureHex);
            byte[] pkBytes = HexToBytes(publicKeyHex);
            if (sigBytes == null || sigBytes.Length != 64 || pkBytes == null || pkBytes.Length != 32) return false;

            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            return Verify(sigBytes, msgBytes, pkBytes);
        }

        public static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return null;
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = HexNibble(hex[i * 2]);
                int lo = HexNibble(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return null;
                bytes[i] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        private static int HexNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }
}
