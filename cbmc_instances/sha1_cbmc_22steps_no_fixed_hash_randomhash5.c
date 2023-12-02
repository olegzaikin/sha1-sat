unsigned int F(unsigned int X, unsigned int Y, unsigned int Z) {
  return (X&Y)|((X^4294967295)&Z); 
}

unsigned int G(unsigned int X, unsigned int Y, unsigned int Z) {
  return (X) ^ (Y) ^ (Z);
}

unsigned int H(unsigned int X, unsigned int Y, unsigned int Z) {
  return (X&Y) | (X&Z) | (Y&Z);
}


void sha1(unsigned int* M, unsigned int* hash, int steps_num) {
  unsigned int A = 0x67452301;
  unsigned int B = 0xEFCDAB89;
  unsigned int C = 0x98BADCFE;
  unsigned int D = 0x10325476;
  unsigned int E = 0xC3D2E1F0;

  unsigned int a = A;
  unsigned int b = B;
  unsigned int c = C;
  unsigned int d = D;
  unsigned int e = E;

  unsigned int W[steps_num];

  unsigned int mod;
  unsigned int s1;
  unsigned int t;
  unsigned int t1;
  int i;

  for(i = 0; i < 16; i = i + 1)
  {
    W[i] = M[i];
  }

  for(i = 16; i < steps_num; i = i + 1)
  {
    // __mem bit t[32] = (W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]) <<< 1;
    t = (W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]);
    mod = t >> (32 - 1);
    t1 = (t << 1) + mod;
    W[i] = t1;
  }

  // Round 1
  for(i = 0; i < 20; i = i + 1)
  {
    // bit t[32] = sum(sum(sum(sum(a <<< 5, F(b, c, d), 32), e, 32), 0x5A827999, 32), W[i], 32);

    mod = a >> (32 - 5);
    s1 = (a << 5) + mod;
    t = s1 + F(b, c, d)+ e + 0x5A827999 + W[i];
    e = d;
    d = c;
    // c = (b <<< 30);
    mod = b >> (32 - 30);
    c = (b << 30) + mod;
    b = a;
    a = t;
  }

  // Round 2
  for(i = 20; i < steps_num; i = i + 1)
  {
    // bit t[32] = sum(sum(sum(sum(a <<< 5, G(b, c, d), 32), e, 32), 0x6ED9EBA1, 32), W[i], 32);
    mod = a >> (32 - 5);
    s1 = (a << 5) + mod;
    t = s1 + G(b, c, d)+ e + 0x6ED9EBA1 + W[i];
    e = d;
    d = c;
    // c = (b <<< 30);
    mod = b >> (32 - 30);
    c = (b << 30) + mod;
    b = a;
    a = t;
  }

  // // Round 3
  // for(i = 40; i < 60; i = i + 1)
  // {
  //  bit t[32] = sum(sum(sum(sum(a <<< 5, H(b, c, d), 32), e, 32), 0x8F1BBCDC, 32), W[i], 32);
  //  e = d;
  //  d = c;
  //  c = (b <<< 30);
  //  b = a;
  //  a = t;
  // }

  // // Round 4
  // for(i = 60; i < 80; i = i + 1)
  // {
  //  bit t[32] = sum(sum(sum(sum(a <<< 5, G(b, c, d), 32), e, 32), 0xCA62C1D6, 32), W[i], 32);
  //  e = d;
  //  d = c;
  //  c = (b <<< 30);
  //  b = a;
  //  a = t;
  // }

  // A = sum(A, a, 32);
  // B = sum(B, b, 32);
  // C = sum(C, c, 32);
  // D = sum(D, d, 32);
  // E = sum(E, e, 32);
  
  /*
  unsigned int aa = A + a;
  unsigned int bb = B + b;
  unsigned int cc = C + c;
  unsigned int dd = D + d;
  unsigned int ee = E + e;

  hash[0] = aa; 
  hash[1] = bb; 
  hash[2] = cc; 
  hash[3] = dd; 
  hash[4] = ee;
  */

  hash[0] = a; 
  hash[1] = b; 
  hash[2] = c; 
  hash[3] = d; 
  hash[4] = e;
}


int main() {
  int M = 16;
  int N = 5;
  unsigned int input1[M];
  unsigned int output1[N];
  int steps_num = 22;
  int i;

  sha1(input1, output1, steps_num);
 
  __CPROVER_assume(output1[0] == 4080085315);
  __CPROVER_assume(output1[1] == 1336481021);
  __CPROVER_assume(output1[2] == 2030961535);
  __CPROVER_assume(output1[3] == 735639500);
  __CPROVER_assume(output1[4] == 3794422835);
  __CPROVER_assume(output1[5] == 1718767418);
  __CPROVER_assume(output1[6] == 720870234);
  __CPROVER_assume(output1[7] == 1743634663);
  __CPROVER_assume(output1[8] == 2044328735);
  __CPROVER_assume(output1[9] == 775910576);
  __CPROVER_assume(output1[10] == 4097434170);
  __CPROVER_assume(output1[11] == 1116957868);
  __CPROVER_assume(output1[12] == 1066400346);
  __CPROVER_assume(output1[13] == 3848199373);
  __CPROVER_assume(output1[14] == 164661332);
  __CPROVER_assume(output1[15] == 4066788284);
 
  __CPROVER_assert(0,"test");
  return 0;
}
