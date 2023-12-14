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

/*
  unsigned int aa = A + a;
  unsigned int bb = B + b;
  unsigned int cc = C + c;
  unsigned int dd = D + d;
  unsigned int ee = E + e;
*/

  hash[0] = A + a; 
  hash[1] = B + b; 
  hash[2] = c + c; 
  hash[3] = D + d; 
  hash[4] = E + e;
}


int main() {
  int M = 16;
  int N = 5;
  unsigned int input1[M];
  unsigned int output1[N];
  int steps_num = 21;
  int i;

  sha1(input1, output1, steps_num);
 
  __CPROVER_assert(0,"test");
  return 0;
}
