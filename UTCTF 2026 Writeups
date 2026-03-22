# CTF Writeup | UTCTF 2026

## Challenge Information

- **CTF Name: UTCTF 2026**
- **Challenge Name: WATSON**
- **Category: FORENSICS**
- **Points: 385**
- **Difficulty: I would say easy-medium**
- **Author: Jared**

---

## Challenge Description

> We need your help again agent. The threat actor was able to escalate privileges. We're in the process of containment and we want you to find a few things on the threat actor. The triage is the same as the one in "Landfall". Can you read the briefing and solve your part of the case?.

---

## Provided Files

- Triage Files: https://cdn.utctf.live/Modified_KAPE_Triage_Files.zip
- how-to_solve.txt
- briefing.txt
- checkpointA.zip
- checkpointB.zip

> briefing.txt
>
> Welcome back agent. Please get us the following:
>
> Checkpoint A: The threat actor deleted a word document containing secret
> project information. Can you retrieve it and submit the name of the project?
>
> Checkpoint B: The threat actor installed a suspicious looking program that
> may or may not be benign. Retrieve the SHA1 Hash of the executable.

---

## Thoughts

- First, to retrieve deleted file, the first place to look at is Recycle bin. I went to recycle bin and found two word document file namely "$R07YGFU.docx" and "$I07YGFU.docx". The first file contained some info. about the project and the project name was "HOOKEM" which was the password for checkpointA.

- Now, we want to find SHA1 hash of the executable that was installed by the threat. Using the following pdf: https://drive.google.com/file/d/1bXfr1E4elPv_DFVdxg7hqGpa1h46Ls2Z/view?usp=sharing, I found something called Amcache.hve. It stores full file path of executables, file size and metadata, multiple timestamps, SHA1 hash. We have to open Amcache.hve located at "Modified_KAPE_Triage_Files\C\Windows\AppCompat\Programs\Amcache.hve".

- I use Eric Zimmerman's tool - "AmcacheParser". Download it and extract it.
  The same tool I remember I used probably in ScriptCTF last year. Go to the extracted location and open it in terminal and used the following command to store all data as .csv

> .\AmcacheParser.exe -f "F:\Modified_KAPE_Triage_Files\C\Windows\AppCompat\Programs\Amcache.hve" --csv output

- After running the command, the terminal printed many things and among those, in one line, it was written "Found 74 unassociated file entry". Then I open up "20260317005328_Amcache_UnassociatedFileEntries" and first application on the list was Calc.exe whose SHA1 hash was 67198a3ca72c49fb263f4a9749b4b79c50510155 which was the password of checkpointB.

Flag found: utflag{utflag{pr1v473_3y3_m1551n6_l1nk}}

## Challenge Information

- **CTF Name: UTCTF 2026**
- **Challenge Name: Oblivious Error**
- **Category: CRYPTOGRAPHY**
- **Points: 100**

---

## Challenge Description

> My friend made an RSA-based 1-2 oblivious transfer protocol program. I don't know what that means but I need to know quick because I accidentally deleted his code! I replaced the part I deleted with the following code in the text file below, but now one of the messages is undecodable and I don't know why!

> Can you decode the lost message?

---

## Provided Files

- my-code.txt

```python
while True:
    try:
        print("Please pick a value k.")
        k = int(input())
        break
    except ValueError:
        print("Invalid value. Please pick an integer.")
        print("Please pick a value k.")

k = int(input())

v = (x0 + (int(k) ^ e)) % N
```

---

## Thoughts

- Searched for RSA-based 1-2 oblivious transfer protocol and found this: https://crypto.stackexchange.com/questions/108981/1-out-of-2-oblivious-transfer-with-rsa. So, through this, I got to know how it works. Here, we were always using b = 0 as stated in my-code.txt.

- Seeing v = (x0 + (int(k) ^ e)) % N, I realised that ^ is XOR, not exponention as \*\* is exponention in python as long as I rememeber.

- Now, we want to recover m0 or m1 from m0' or m1' that we have recieved. They calculate v = (x0 + (int(k) ^ e)) % N from the k that I provide. So, if we use k = e, then k ^ e = 0 so v = x0. Then m0' = (pow(0, d)modN + m0)modN = m0. So, we got m0 by k = e.

```bash
ncat challenge.utctf.live 8379

Here's your entrance key!
N = 8251341060472898950544765280713533195771921505471195914799075590612944439698576515988967949972697667783764227920969924010045375486705436625113527413314521
e = 65537
Here are my random x values!
x0: 8075253444762907900176291454570455592192598863152438264749928638076054370935586082769947944033452678552609155544702085228304630004155496208694574669106399
x1: 4427244758107671868266350481226180711925441725940044624569829706409185558919607837631518942588141264705944950380024982039357691893780211963761647851376866
Please pick a value k.
65537
Here are your messages!
Message 1:  2448678142919009288543104681070630932566673647453014611974787647135372441832317580076576354200651666997607210403100460086236257627461275563541717556419506
Message 2:  14614909182015656433423375395560694783276217129595018028195683192534693780147751705041670356317823574397
```

- We decryting the messages with "To Base"(16) + "From Hex" + "ROT13" to get garbage text from Message 1 (msg0) and "utflag{Congrats! You caught a red herring!}" from Message 2 (msg1) which is a false flag.

- Now, m1 = (pow(v - x1, d)modN + m1)modN. To recover m1, v - x1 = 0. So, v = x1.
  So, v = x1 = (x0 + k^e)modN which gives k = ((x1 - x0)modN) ^ e.

```bash
ncat challenge.utctf.live 8379

Here's your entrance key!
N = 7950373284161321728085672520812700748262705876547801581937147198305661996985653284755389426479101699477083535803598013132436412115700833216154188518395403
e = 65537
Here are my random x values!
x0: 4349042862484605933665286399783372970170558465723261894654104654713777199191282626440303470437565073913553234468575653613438838984175164621018486909797236
x1: 4980891233594312977409239093082863238934739542391593122053700684099293180115127909887296442633846877504368963302944152711158841196336838005794542353949615
Please pick a value k.
631848371109707043743952693299490268764181076668331227399596029385515980923845283446992972196281803590815728834368499097720002212161673384776055444086842
Here are your messages!
Message 1:  2079259062656439012832438543209637964802201825939047160966099908708207615077204098952458093705981597594519714154232176545084474955734007455954384297589744
Message 2:  16441782473165749985269251414928450202051900518929647105868978172963309169080628914206924705003483790602

```

- Decrypting message 2 gives the correct flag: utflag{my_obl1v10u5_fr13nd_ru1n3d_my_c0de}

- May be here, msg0 and msg1 are randomly swapping so we got both correct and red herring flag from message 2.

---

## Challenge Information

- **CTF Name: UTCTF 2026**
- **Challenge Name: Smooth Criminal**
- **Category: CRYPTOGRAPHY**
- **Points: 100**

---

## Challenge Description

> Our cryptographer assured us that a 649-bit prime makes this completely unbreakable. He also said the order of the group "doesn't really matter that much." He no longer works here.

---

## Provided Files

- dlp.txt

```text
The flag has been encoded as a secret exponent x, where:

  h = g^x mod p

Your job: find x. Convert it from integer to bytes to get the flag.

p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517
```

---

## Thoughts

- Searched how to solve h = g^x(mod p) on google and found something called discrete log (x = log<sub>g</sub>(h)modp).
- Found discrete log function in sage documentation and use it to find x.

```sage
p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517

F = GF(p)
x = discrete_log(F(h), F(g))
print(hex(x))

```

```bash
0x7574666c61677b736d303074685f6372316d316e616c5f6361756768747d
```

- Use cyberchef to decode the above x ("From Hex") to get the flag: utflag{sm00th_cr1m1nal_caught}
