/*Backward bias determining programme for 256-bit SALSA20/7 
Here we go 4 round forward, 3 round backward

line 45 - 50 can be modified

command to run:  g++ stage1epsilona.cpp && ./a.out */

#include <cmath>    // pow function
#include <cstring>  // string
#include <ctime>    //  time
#include <iomanip>  // decimal numbers upto certain places
#include <iostream> // cin cout

using namespace std;

#define BitsInWord 32
typedef uint32_t u32;           // positive integer of 32 bits
typedef unsigned long long ull; // 32 - 64 bits memory
#define MOD 4294967296          // pow(2, BitsInWord)

// random number of 32 bits
static inline u32 drandom()
{
    return MOD * drand48();
}

// QR helping functions
#define ROTL(x, n) ((x << n) | (x >> (BitsInWord - n)))
#define UPDATE(a, b, c, n) (a ^ (ROTL((b + c), n)))

// --------------------------- Forward QR ---------------------------
#define QR(a, b, c, d) (     \
    b = UPDATE(b, a, d, 7),  \
    c = UPDATE(c, b, a, 9),  \
    d = UPDATE(d, c, b, 13), \
    a = UPDATE(a, d, c, 18))

// --------------------------- Backward QR ---------------------------
#define REVQR(a, b, c, d) ( \
    a ^= ROTL(d + c, 18),   \
    d ^= ROTL(c + b, 13),   \
    c ^= ROTL(b + a, 9),    \
    b ^= ROTL(a + d, 7))

// DIFFFERENTIAL ATTACK HELPERS
int IDword[] = {7}, IDbit[] = {0};
int ODword[] = {1}, ODbit[] = {15};

ull MAX_LIM = pow(2, 60), LOOP_LIM = pow(2, 22), counter{0};

void InitializeIV(u32 *x);
void InitializeKey(u32 *key);
void InsertKey(u32 *x, u32 *key);
void CopyState(u32 *x, u32 *x1, int size);
void InputDifference(u32 *x1, int word, int bit);
void XORDifference(u32 *x, u32 *x1, u32 *y, int n);
void ShowOnScreen(u32 *x, int size);
void AddStates(u32 *x, u32 *x1);
void SubtractStates(u32 *x, u32 *x1);
int NumberOfDifferences(u32 *x, u32 *x1, int check_digit, const char *checksum);

void odd_salsa_round(u32 x[16]);
void even_salsa_round(u32 x[16]);
void rev_odd_salsa_round(u32 x[16]);
void rev_even_salsa_round(u32 x[16]);

int notSignificantBits[] = {0, 1, 2, 3, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 46, 59, 66, 67, 72, 73, 74, 75, 76, 77, 78, 79, 80, 86, 87, 88, 89, 90, 91, 92, 93, 94, 96, 97, 98, 99, 100, 101, 102, 103, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 130, 131, 135, 136, 137, 138, 143, 144, 145, 149, 150, 151, 152, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 186, 187, 188, 189, 190, 191, 194, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 231, 232, 233, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255};
int notSignificantBitsCount = sizeof(notSignificantBits) / sizeof(notSignificantBits[0]);

int main()
{
    srand48(time(NULL));

    // PRINTING NEEDS
    cout << "            Backward bias determining programme\n";
    cout << "            Cipher Name: 256-bit Salsa20/7 (4 round forward, 3 round backward)\n            ID = ";
    for (int i{0}, n = sizeof(IDword) / sizeof(IDword[0]); i < n; ++i)
    {
        if (i == n - 1)
            cout << "(" << IDword[i] << ", " << IDbit[i] << ")\n";
        else
        {
            cout << "(" << IDword[i] << ", " << IDbit[i] << ")⊕";
        }
    }
    cout << "            OD = ";
    for (int i{0}, n = sizeof(ODword) / sizeof(ODword[0]); i < n; ++i)
    {
        if (i == n - 1)
            cout << "(" << ODword[i] << ", " << ODbit[i] << ")\n";
        else
        {
            cout << "(" << ODword[i] << ", " << ODbit[i] << ")⊕";
        }
    }
    cout <<"            # of bits that are not significant : " << notSignificantBitsCount <<"\n";
    cout << "            loop size : 2^" << log2(LOOP_LIM) << "\n";
    cout << "*************************************************\n";

    // M A I N       P R O G      S T A R T S
    u32 x0[16], strdx0[16], key[8], dx0[16], dstrdx0[16], z[16], dz[16], ds[16], fwdbit, bwdbit, loop{0};
    int WORD, BIT;
    double count{0};

    while (loop < MAX_LIM)
    {
        //~~~~~~~~~~~~~~~~~ forward rounds ~~~~~~~~~~~~~~~~~~
        InitializeIV(x0);
        InitializeKey(key);
        InsertKey(x0, key);
        CopyState(strdx0, x0, 16);
        CopyState(dx0, x0, 16);
        InputDifference(dx0, IDword[0], IDbit[0]);
        CopyState(dstrdx0, dx0, 16);
        // 0-1
        odd_salsa_round(x0);
        odd_salsa_round(dx0);
        // 1-2
        even_salsa_round(x0);
        even_salsa_round(dx0);
        // 2-3
        odd_salsa_round(x0);
        odd_salsa_round(dx0);
        // 3-4
        even_salsa_round(x0);
        even_salsa_round(dx0);

        XORDifference(x0, dx0, ds, 16);

        fwdbit = (ds[ODword[0]] >> ODbit[0]);
        // 4-5
        odd_salsa_round(x0);
        odd_salsa_round(dx0);
        // 5-6
        even_salsa_round(x0);
        even_salsa_round(dx0);
        // 6-7
        odd_salsa_round(x0);
        odd_salsa_round(dx0);

        // addition of states
        AddStates(x0, strdx0);
        AddStates(dx0, dstrdx0);

        // randomly flip the bits
        for (int j = 0; j < notSignificantBitsCount; ++j)
        {
            if ((notSignificantBits[j] / 32) > 3)
            {
                WORD = (notSignificantBits[j] / 32) + 7;
            }
            else
            {
                WORD = (notSignificantBits[j] / 32) + 1;
            }
            BIT = notSignificantBits[j] % 32;

            if (drand48() < 0.5)
            {
                strdx0[WORD] = strdx0[WORD] ^ (0x1 << BIT);
                dstrdx0[WORD] = dstrdx0[WORD] ^ (0x1 << BIT);
            }
        }

        SubtractStates(x0, strdx0);
        SubtractStates(dx0, dstrdx0);

        //~~~~~~~~~~~~~~~~~ reverse rounds ~~~~~~~~~~~~~~~~~~
        // 7-6
        rev_odd_salsa_round(x0);
        rev_odd_salsa_round(dx0);
        // 6-5
        rev_even_salsa_round(x0);
        rev_even_salsa_round(dx0);
        // 5-4
        rev_odd_salsa_round(x0);
        rev_odd_salsa_round(dx0);

        XORDifference(x0, dx0, ds, 16);

        bwdbit = ds[ODword[0]] >> ODbit[0];

        // epsilon_a find
        if ((fwdbit ^ bwdbit) & 0x1)
        {
            count++;
        }
        loop++;
        if (loop > 0 && loop % LOOP_LIM == 0)
            printf("#loop = %lld | bias = %.7lf ~ %.5lf \n", counter++, fabs(2 * (count / loop) - 1.0), fabs(2 * (count / loop) - 1.0));
    }
}

// F U N C T I O N   D E F I N I T I O N ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
void InitializeIV(u32 *x)
{
    x[0] = 0x61707865;
    x[5] = 0x3120646e;
    x[10] = 0x79622d36;
    x[15] = 0x6b206574;
    for (int i{6}; i < 10; ++i)
    {
        x[i] = drandom(); // IV
    }
}
void InitializeKey(u32 *k)
{
    for (int i{0}; i < 8; ++i)
    {
        k[i] = drandom(); // key
    }
}
// fitting the key k into the state matrix x
void InsertKey(u32 *x, u32 *k)
{
    for (int j{1}; j < 5; ++j)
        x[j] = k[j - 1];
    for (int j{11}; j < 15; ++j)
        x[j] = k[j - 7];
}
// x1 state is copied in x
void CopyState(u32 *x, u32 *x1, int n)
{
    for (int i{0}; i < n; ++i)
        x[i] = x1[i];
}
// function to input difference
void InputDifference(u32 *x, int word, int bit)
{
    x[word] ^= (0x1 << bit);
}
// function to store the xor difference y between two terms x and x1
void XORDifference(u32 *x, u32 *x1, u32 *y, int n)
{
    for (int i{0}; i < n; ++i)
    {
        y[i] = x[i] ^ x1[i];
    }
}
// sum is stored in x
void AddStates(u32 *x, u32 *x1)
{
    for (int i{0}; i < 16; ++i)
        x[i] += x1[i];
}
// subtraction is stored in x
void SubtractStates(u32 *x, u32 *x1)
{
    for (int i{0}; i < 16; ++i)
        x[i] -= x1[i];
}

void odd_salsa_round(u32 x[16])
{
    // Odd round
    QR(x[0], x[4], x[8], x[12]);  // column 1
    QR(x[5], x[9], x[13], x[1]);  // column 2
    QR(x[10], x[14], x[2], x[6]); // column 3
    QR(x[15], x[3], x[7], x[11]); // column 4
}

void even_salsa_round(u32 x[16])
{
    // Even round
    QR(x[0], x[1], x[2], x[3]);     // row 1
    QR(x[5], x[6], x[7], x[4]);     // row 2
    QR(x[10], x[11], x[8], x[9]);   // row 3
    QR(x[15], x[12], x[13], x[14]); // row 4
}

void rev_odd_salsa_round(u32 x[16])
{
    // Odd round
    REVQR(x[0], x[4], x[8], x[12]);  // column 1
    REVQR(x[5], x[9], x[13], x[1]);  // column 2
    REVQR(x[10], x[14], x[2], x[6]); // column 3
    REVQR(x[15], x[3], x[7], x[11]); // column 4
}

void rev_even_salsa_round(u32 x[16])
{
    // Even round
    REVQR(x[0], x[1], x[2], x[3]);     // row 1
    REVQR(x[5], x[6], x[7], x[4]);     // row 2
    REVQR(x[10], x[11], x[8], x[9]);   // row 3
    REVQR(x[15], x[12], x[13], x[14]); // row 4
}
