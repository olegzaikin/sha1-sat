import sys

var1 = int(sys.argv[1])
var2 = int(sys.argv[2])
sign = sys.argv[3]

for i in range(var1, var2+1):
    s = ''
    if sign == '-':
      s += '-'
    s += str(i) + ' 0'
    print(s)
