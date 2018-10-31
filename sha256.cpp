/*******************************************************************************************************
  A C++ implementation of the SHA-256 (secure hash algorithm).
  It is implemented by following the FIPS 180-2 publication, released by the NSA.
  The publication can be read for free here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

  When a comment within the source code refers to a chapter/section, it is refering that chapter/section in FIPS 180-2.
********************************************************************************************************/
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>

/***********************************************************************************************************************************/
// Constants used in hash algorithm. According to specification
const unsigned int K[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// This is an empty array which is used as a template for the message schedule
unsigned int W[64];

// These are the working variables which are used by the algorithm
unsigned int a, b, c, d, e, f, g, h, T1, T2;
/**********************************************************************************************************************************/

// Handles input. Reads string value and stores it inside a vector
std::vector<unsigned char> readInput(const std::string &input){
    std::vector<unsigned char> inputVector;
    int size = input.length();
    for (int i = 0, pos = 0; i < size / 2; ++i, pos += 2){
        // gets characters from the string as a hexadecimal value in pairs of 2. Then stores the values in inputvector
        unsigned char hexpair = std::stoi(input.substr(pos, 2), nullptr, 16);
        inputVector.push_back(hexpair);
    }
    return inputVector;
}

// Prints the hash value
void printHash(std::vector<std::vector<unsigned int>> H, int N){
    for (int i = 0; i < 8; i++){
        std::cout << std::hex << std::setw(8) << std::setfill('0') << H[N][i];
    }
    std::cout << "\n";
}

// Heturns the amount of bits of padding is required. Used by paddingMessage. Implemented as in section 5.1.1.
const int getPadding(long long length){
    int k = 0;
    while ((length + 1 + k) % 512 != 448){
        ++k;
    }
    return k;
}

// Pads the message contents according to section 5.1.
std::vector<unsigned char> paddingMessage(std::vector<unsigned char> M){
    // obtains the amount "k" bits which needs to be padded to the message
    int k = getPadding(M.size()*8);
    long long l = (M.size()*8);
    // Append a 1 before the least significant bit in the message
    M.push_back(0x80);
    k = k - 7;
    // Append the remaining zeroes of k
    for (int i = 0; i < (k / 8); ++i){
        M.push_back(0);
    }
    // Append the length (l) as 0's to the message
    for (int i = 1; i < 9; ++i){
        M.push_back(l >> (64 - i * 8));
    }
    // return the now padded message.
    return M;
}

// Parse the message into n 512-bit blocks
std::vector<std::vector<unsigned int>> parsingMessage(std::vector<unsigned char> bytes){
    // Create a 2d vector for storing all the blocks, in total we will obtain 16 32-bit blocks (16 * 32 = 512)
    std::vector<std::vector<unsigned int>> M;
    unsigned int n = 0;
    for (int i = 0; n < bytes.size() / 64; ++n){
        // Create a new block, since we handle our bits in pairs, 16 indices is enough for a 32-bit block
        std::vector<unsigned int> block(16);
        for (int j = 0; j < 16; ++j){
            unsigned int word = 0;
            for (int k = 0; k < 4; ++k, ++i){
                word <<= 8;
                word |= bytes[i];
            }
            // insert our created word at the current index in our current block
            block[j] = word;
        }
        // insert the finished block in our 2d vector
        M.push_back(block);
    }
    // return the parsed message
    return M;
}

/*
 The following eight functions are logical functions used by SHA-256 to perform operations on words.
 They are called upon by the compute hash function
*/
// Right shift function, implemented as presented in section 3.2.
const unsigned int SHR(const unsigned int &n, const unsigned int &x)
{
    return x >> n;
}

// Rotate right (circular right shift), implemented as presented in section 3.2. Our blocks never exceed a size of 32 bits. Therefore w is set as a constant.
const unsigned int ROTR(const unsigned int &n, const unsigned int &x)
{
    return (x >> n) | (x << (32 - n));
}

// The Ch function used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int Ch(const unsigned int &x, const unsigned int &y, const unsigned in
        for (int j = 0; j < 16; ++j){
            unsigned int word = 0;
            for (int k = 0; k < 4; ++k, ++i){
                word <<= 8;
                word |= bytes[i];
            }
            // insert our created word at the current index in our current block
            block[j] = word;
        }
        // insert the finished block in our t &z)
{
    return (x & y) ^ (~x & z);
}

// The Maj function used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int Maj(const unsigned int &x, const unsigned int &y, const unsigned int &z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// These functions depend on SHR and ROTR
// Capital sigma function 0 used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int capitalSigma_0(const unsigned int &x)
{
    return ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x);
}

// Capital sigma function 1 used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int capitalSigma_1(const unsigned int &x)
{
    return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
}

// Lowercase sigma function 0 used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int lowercaseSigma0(const unsigned int &x)
{
    return ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x);
}

// Lowercase sigma function 1 used by the hash algorithm. Implemented as presented in section 4.1.2.
const unsigned int lowercaseSigma1(const unsigned int &x)
{
    return ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x);
}

// Computes the hash value. Using the steps specified in section 6.2.2 the specification
std::vector<std::vector<unsigned int>> getHash(std::vector<std::vector<unsigned int>> M){
    // sets the initial hash value H0, according to specification
    std::vector<std::vector<unsigned int>> Hash;
    std::vector<unsigned int> H0 = {0x6a09e667,
                           0xbb67ae85,
                           0x3c6ef372,
                           0xa54ff53a,
                           0x510e527f,
                           0x9b05688c,
                           0x1f83d9ab,
                           0x5be0cd19};
    Hash.push_back(H0);

    // Creates a new block
    std::vector<unsigned int> currentBlock(8);
    int N = M.size();
    // we compute the hash, using the previous hash values, for all blocks 1 to N
    for (int i = 1; i <= N; ++i)
    {
        // The two different methods used for the message schedule, depending on the size of t.
        for (int t = 0; t <= 15; ++t)
            W[t] = M[i - 1][t]; // M^i in spec
        for (int t = 16; t <= 63; ++t)
            W[t] = lowercaseSigma1(W[t - 2]) + W[t - 7] + lowercaseSigma0(W[t - 15]) + W[t - 16];

        // We set the values of our working variables dependent of the values of the previous hash. Hence why we got to use an initial hash.
        a = Hash[i - 1][0];
        b = Hash[i - 1][1];
        c = Hash[i - 1][2];
        d = Hash[i - 1][3];
        e = Hash[i - 1][4];
        f = Hash[i - 1][5];
        g = Hash[i - 1][6];
        h = Hash[i - 1][7];

        // Logical operations performed as specififed in seection 6.2.2.
        for (int t = 0; t <= 63; ++t)
        {
            T1 = h + capitalSigma_1(e) + Ch(e, f, g) + K[t] + W[t];
            T2 = capitalSigma_0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // We then compute the intermediate hash values
        currentBlock[0] = a + Hash[i - 1][0];
        currentBlock[1] = b + Hash[i - 1][1];
        currentBlock[2] = c + Hash[i - 1][2];
        currentBlock[3] = d + Hash[i - 1][3];
        currentBlock[4] = e + Hash[i - 1][4];
        currentBlock[5] = f + Hash[i - 1][5];
        currentBlock[6] = g + Hash[i - 1][6];
        currentBlock[7] = h + Hash[i - 1][7];
        // push our currentblock to Hash and move on to the next block
        Hash.push_back(currentBlock);
    }
    // return the hash
    return Hash;
}


int main(){
    // Read each line from standard input
    for (std::string input; std::getline(std::cin, input);) {

        // Read the input
        std::vector<unsigned char> message = readInput(input);

        // Padding
        message = paddingMessage(message);

        // Parse the message into n blocks
        std::vector<std::vector<unsigned int>> parsed_message = parsingMessage(message);

        // Computes the hashvalue generated by the algorithm and prints it using stdout
        printHash(getHash(parsed_message), parsed_message.size());
    }
    return 0;
}
