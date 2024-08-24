unsigned int F(unsigned int X, unsigned int Y, unsigned int Z) {
  return (X&Y)|((X^4294967295)&Z); 
}

unsigned int G(unsigned int X, unsigned int Y, unsigned int Z) {
  return (X&Z) | (Y&(Z^4294967295));
}

//unsigned int H(unsigned int X, unsigned int Y, unsigned int Z) {
//  return (X) ^ (Y) ^ (Z);
//}

// Round 1, return (a + F(b,c,d) + M + T) <<< s:
unsigned int FF(unsigned int aa, unsigned int bb, unsigned int cc, unsigned int dd, unsigned int M, int s, unsigned int T)
{
  unsigned int out = ((aa + F(bb, cc, dd)) + M) + T;
  unsigned int mod = out >> (32 - s);  // cyclic shift <<< is first >> and then << and sum
  return ((out << s) + mod) + bb;
}

// Round 2, return (a + F(b,c,d) + M + T) <<< s:
unsigned int GG(unsigned int aa, unsigned int bb, unsigned int cc, unsigned int dd, unsigned int M, int s, unsigned int T)
{
  unsigned int out = ((aa + G(bb, cc, dd)) + M) + T;
  unsigned int mod = out >> (32 - s);  // cyclic shift <<< is first >> and then << and sum
  return ((out << s) + mod) + bb;
}

// Round 2, return (a + F(b,c,d) + M + T) <<< s:
unsigned int GG_weak(unsigned int aa, unsigned int bb, unsigned int cc, unsigned int dd, unsigned int M, int s, unsigned int T)
{
  int j = 1; // line for changing
  int l = 32 - j;
  unsigned int weakM = (M >> l) << l;
  unsigned int out = ((aa + G(bb, cc, dd)) + weakM) + T;
  unsigned int mod = out >> (32 - s);  // cyclic shift <<< is first >> and then << and sum
  return ((out << s) + mod) + bb;
}


// Round 3, return (a + F(b,c,d) + M + T) <<< s:
//unsigned int HH(unsigned int aa, unsigned int bb, unsigned int cc, unsigned int dd, unsigned int M, int s, unsigned int T)
//{
//  unsigned int out = ((aa + H(bb, cc, dd)) + M) + T;
//  unsigned int mod = out >> (32 - s);  // cyclic shift <<< is first >> and then << and sum
//  return ((out << s) + mod) + bb;
//}

void md4(unsigned int* M, unsigned int* hash) {
  // unsigned int hash[4];
  unsigned int A = 1732584193; //67452301;
  unsigned int B = 4023233417; //EFCDAB89;
  unsigned int C = 2562383102; //98BADCFE;
  unsigned int D = 271733878;  //10325476;

  unsigned int a = A;
  unsigned int b = B;
  unsigned int c = C;
  unsigned int d = D;

        // Round 1, steps 1-16:
        a = FF(a, b, c, d, M[0], 7, 3614090360);   // 0xd76aa478
	d = FF(d, a, b, c, M[1], 12, 3905402710);  // 0xe8c7b756
	c = FF(c, d, a, b, M[2], 17, 606105819);   // 0x242070db
	b = FF(b, c, d, a, M[3], 22, 3250441966);  // 0xc1bdceee

	a = FF(a, b, c, d, M[4], 7, 4118548399);   // 0xf57c0faf
	d = FF(d, a, b, c, M[5], 12, 1200080426);  // 0x4787c62a
	c = FF(c, d, a, b, M[6], 17, 2821735955);  // 0xa8304613
	b = FF(b, c, d, a, M[7], 22, 4249261313);  // 0xfd469501
	
	a = FF(a, b, c, d, M[8], 7, 1770035416);   // 0x698098d8
	d = FF(d, a, b, c, M[9], 12, 2336552879);  // 0x8b44f7af
	c = FF(c, d, a, b, M[10], 17, 4294925233); // 0xffff5bb1
	b = FF(b, c, d, a, M[11], 22, 2304563134); // 0x895cd7be

	a = FF(a, b, c, d, M[12], 7, 1804603682);  // 0x6b901122
	d = FF(d, a, b, c, M[13], 12, 4254626195); // 0xfd987193
	c = FF(c, d, a, b, M[14], 17, 2792965006); // 0xa679438e
	b = FF(b, c, d, a, M[15], 22, 1236535329); // 0x49b40821

        // Round 2, steps 17-32:
        a = GG(a, b, c, d, M[1], 5, 4129170786);   // 0xf61e2562
	d = GG(d, a, b, c, M[6], 9, 3225465664);   // 0xc040b340
	c = GG(c, d, a, b, M[11], 14, 643717713);  // 0x265e5a51
	b = GG(b, c, d, a, M[0], 20, 3921069994);  // 0xe9b6c7aa

	a = GG(a, b, c, d, M[5], 5, 3593408605);   // 0xd62f105d
	d = GG(d, a, b, c, M[10], 9, 38016083);    // 0x02441453
	c = GG(c, d, a, b, M[15], 14, 0xd8a1e681); // 0xd8a1e681
	b = GG(b, c, d, a, M[4], 20, 3889429448);  // 0xe7d3fbc8

	a = GG(a, b, c, d, M[9], 5, 568446438);    // 0x21e1cde6
	d = GG(d, a, b, c, M[14], 9, 3275163606);  // 0xc33707d6
	c = GG(c, d, a, b, M[3], 14, 4107603335);  // 0xf4d50d87
	b = GG_weak(b, c, d, a, M[8], 20, 1163531501);  // 0x455a14ed, step 28

	//a = GG_weak(a, b, c, d, M[13], 5, 2850285829);  // 0xa9e3e905
	//d = GG(d, a, b, c, M[2], 9, 4243563512);   // 0xfcefa3f8
	//c = GG(c, d, a, b, M[7], 14, 1735328473);  // 0x676f02d9
	//b = GG(b, c, d, a, M[12], 20, 2368359562); // 0x8d2a4c8a

        // Round 3, steps 33-48:
        // XXX

        // Round 4, steps 49-64:
        // XXX

        hash[0] = a + A;
        hash[1] = b + B;
        hash[2] = c + C;
        hash[3] = d + D;
}

int main() {
  int M = 16;
  int N = 4;
  unsigned int input1[M];
  unsigned int output1[N];
  unsigned int hash = 4294967295; // 32 1s
  md4(input1, output1);
  // Known hash:
  __CPROVER_assume( output1[0] == hash );
  __CPROVER_assume( output1[1] == hash );
  __CPROVER_assume( output1[2] == hash );
  __CPROVER_assume( output1[3] == hash );
  __CPROVER_assert(0,"test");
  return 0;
}
