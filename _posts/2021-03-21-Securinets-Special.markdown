---
layout: post
title:  "Special from Securinets CTF 2021"
---

The following problem appears simple but it took me a long time to do. I really enjoyed solving it though!

## Special from Securinets CTF <a name="baby-rsa"></a>

#### **`app.py`**

```python
from Crypto.Util.number import isPrime, bytes_to_long
from secret import flag
import random

def get(r):
    while True:
        a = random.getrandbits(512)
        p = a**2 + r 
        if isPrime(p) :
            return p

m = bytes_to_long(flag)
e = 65537
p, q = get(1337), get(1187)
n = p*q
c = pow(m, e, n)
print ("Modulus : {}".format(n))
print ("Public exponent : {}".format(e))
print ("Ciphertext : {}".format(c))

"""

Modulus : 9205101698706979739826801043045342787573860852370120009782047065091267165813818945944938567077767109795693195306758124184300669243481673570359620772491153042678478312809811432352262322016591328649959068333993409371541201650938826630256112619578125044564261211415732174900162604077497313177347706230511508892968172603494805342653386527679619380762253476920434736431368696225307809325876263469267138456334317623292049963916185087736277032965175422891773251267119088153064627668031982940139865703040003065759250189294830016815658342491949959721771171008624698225901660128808998889116825507743256985320474353400908203
Public exponent : 65537
Ciphertext : 7936922632477179427776336441674861485950589109838466370248848810603305227730610589646741819313897162184198914593449584513298801516246072184328924490958302064664202813944180474377318619755541891685799909623945111729243482919086734358170659346187530089396234296268433976153029353575494866263288471212406042845186256151549768916089844077364464961133610687655801313809083988904726871667971720011220619598069236604397523051054337851497256894302257378216064087800301371122182309897203436049352850483968349573626245496903689129366737214112517774597434631637719018819317503710042658242522690613437843118568709251604555104

"""
```

This article/stub presumes that the reader is familiar with [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Encryption) and he/she understands the source code.

The only file I was given was `app.py`. This is another RSA problem, where the only unusual information is $$ p = x^{2} + 1337 $$ and $$ q = y^{2} + 1187 $$ for some random integers $$ x $$ and $$ y $$.

The first thing I tried was solving for $$ \phi(n) $$. The difference between $$ n $$ and $$ \phi(n) $$ was only $$ (x^{2} + 1337)(y^{2} + 1187) - (x^{2} + 1336)(y^{2} + 1186) = x^{2} + y^{2} + 2523 $$ but I could not find any way to obtain $$ x^{2} + y^{2} $$ so far. Then, I approximated $$ x $$ and $$ y $$ by setting them equal in $$ (x^{2} + 1337)(y^{2} + 1187) = n $$. SageMath solved the roots of $$ (z^{2} + 1337)(z^{2} + 1187) - n = 0 $$ quite easily. 

Then I had to repeatedly come up with hypotheses. I discovered that $$ \frac{z}{x}\approx\frac{y}{z} $$, which meant that $$ z^{2}\approx xy$$. I found that plugging in $$ 2z^{2} + 2523 $$ to solve for $$\phi(n)$$ leaked the first $$\approx1018$$ bits of $$\phi(n)$$, but I could not pivot off this vulnerability. I also found that the difference between $$ \sqrt{n - 1337\cdot 1187 - 1187z^{2} - 1337z^{2}} $$ and $$ xy $$ ranged from $$ -10000 $$ to $$ 10000 $$ with likely differences between 0 and 1000 and negative differences being highly unlikely. (Off topic: this sparked an idea to create an intelligent for loop, one which iterates over numbers first based on how likely they are to appear in a distribution given a sample of points. I thought of this since iterating from `range(-10000, 10000)` would not be efficient as $$-10000$$ is hardly likely to appear in my distribution, yet it would be picked first.)

I now had a set of solvable equations.

\\[ xy = \sqrt{n - 1337\cdot 1187 - 1187z^{2} - 1337z^{2}} + \mathrm{diff} \\]
\\[ 1187x^{2} + 1337y^{2} = n - 1337 \cdot 1187 - (xy)^{2} \\]

Collapsing these equations to one equation and testing whether $$ x $$ and $$ y $$ form correct $$ p $$ and $$ q $$ was the way I solved Special. My solution script is really messy since I tested all my hypotheses in the same script. In case you want to run this, I found that the diff between the $$z$$ derived $$xy$$ and actual $$xy$$ for the non-experimental case to be around $$1767$$. The original script took a few hours to finish.

#### **`complete.sage`**

```python
from Crypto.Util.number import isPrime, bytes_to_long, GCD, long_to_bytes
import random
from tqdm import tqdm
from gmpy2 import iroot

experiment = True
x = y = 0

if experiment:
    flag = b"Securinets{fake_flag}"
    def get(r):
        global x, y
        while True:
            a = random.getrandbits(512)
            p = a**2 + r 

            if isPrime(p) :
                if x == 0:
                    x = a
                else:
                    y = a
                return p

    m = bytes_to_long(flag)
    e = 65537
    p, q = get(1337), get(1187)
    n = p*q
    c = pow(m, e, n)
    print("n =", n)
    print("x =", x)
    print("y =", y)
    print("c =", c)
else:
    n = 9205101698706979739826801043045342787573860852370120009782047065091267165813818945944938567077767109795693195306758124184300669243481673570359620772491153042678478312809811432352262322016591328649959068333993409371541201650938826630256112619578125044564261211415732174900162604077497313177347706230511508892968172603494805342653386527679619380762253476920434736431368696225307809325876263469267138456334317623292049963916185087736277032965175422891773251267119088153064627668031982940139865703040003065759250189294830016815658342491949959721771171008624698225901660128808998889116825507743256985320474353400908203
    e = 65537
    c = 7936922632477179427776336441674861485950589109838466370248848810603305227730610589646741819313897162184198914593449584513298801516246072184328924490958302064664202813944180474377318619755541891685799909623945111729243482919086734358170659346187530089396234296268433976153029353575494866263288471212406042845186256151549768916089844077364464961133610687655801313809083988904726871667971720011220619598069236604397523051054337851497256894302257378216064087800301371122182309897203436049352850483968349573626245496903689129366737214112517774597434631637719018819317503710042658242522690613437843118568709251604555104

zeta = 0
var("z")
for soln in solve((z^2+1337)*(z^2+1187) == n, z):
    try:
        zeta = int(soln.rhs().n())
    except:
        pass

print("z =", zeta)
approx = n - (zeta^2 + 2523)
assert (p-1)*(q-1) >> 1038 == approx >> 1038

xy = int(iroot(n - 1337*1187 - (1337+1187)*zeta^2, 2)[0])

if experiment:
    r = [xy - x*y]
    print("r =", r)
else:
    r = range(10000)

good = False

def quartic(n1, n2):
    # was gonna look up a more time efficient way to solve for quartic equation
    return solve(1337*f^4 - n1*f^2 + n2 == 0, f, solution_dict=True)

for diff in tqdm(r):
    test = xy - diff
    n1 = n - 1337*1187 - test^2
    n2 = 1187 * test^2

    var("f")
    for soln in quartic(n1, n2):
        try:
            q = int(soln[f])^2 + 1187
        if GCD(q, n) != 1:
            p = n // q
            assert p*q == n
            phi = (p-1) * (q-1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            print(long_to_bytes(m))
            good = True
        except:
            pass
        if good:
            break
```

Flag: `Securinets{6650b577b4be574b9180a52631d6d431513f6981ade2d5c81efdea43bb365d98}`
