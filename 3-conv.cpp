/*
목표 : 4문제
1. 사칙연산

3. conv
4. fc 레이어
2. relu연산
*/

#include <fstream>
#include <iostream>
#include <random>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;

const int RING_DIM = 16384;
const double TOL = 0.0001;

const size_t WIDTH = 32;
const size_t HEIGHT = 32;
const size_t KERNEL = 5;

void convolve2D(vector<double>& in,
                vector<double>& ker,
                vector<double>& out);

int main() {
    srand(static_cast<unsigned>(time(nullptr)));
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(RING_DIM);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    //You may add more rotation keys if needed.
    vector<int> rotvec;
    for(size_t i = 0; i < WIDTH; i++) {
        for(size_t j = 0; j < HEIGHT; j++) {
            rotvec.push_back(i + j * WIDTH - static_cast<int>(KERNEL / 2) * (WIDTH + 1));
        }
    }
    cc->EvalRotateKeyGen(kp.secretKey, rotvec);



    usint cyclOrder = cc->GetCyclotomicOrder();
    int32_t n = cyclOrder / 4;
    vector<double> vec(n, 0);
    for(size_t i = 0; i < WIDTH * HEIGHT; i++){
        vec[i] = 2 * double(rand())/RAND_MAX - 1;
    }
    Plaintext pt = cc->MakeCKKSPackedPlaintext(vec);
    auto ct = cc->Encrypt(kp.publicKey, pt);

    vector<double> kernel(KERNEL*KERNEL,0);
    for(size_t i = 0; i < KERNEL*KERNEL; i++){
        kernel[i] = 2 * double(rand())/RAND_MAX - 1;
    }


    Ciphertext<DCRTPoly> ct_res = ct->Clone();


    //Fill in the following section
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Plaintext pt_res;
    cc->Decrypt(kp.secretKey,ct_res,&pt_res);
    vector<double> vec_res = pt_res->GetRealPackedValue();

    vector<double> res_expected;
    convolve2D(vec,kernel,res_expected);
    bool ispass = true;
    for (size_t i=0;i<WIDTH * HEIGHT;i++){
        if (abs(res_expected[i] - vec_res[i]) > TOL){
            cout << "Wrong at " << i << " : " << res_expected[i] << " vs " << vec_res[i] << endl;
            ispass = false;
            break;
        }
    }
    cout << "Convolution : " << (ispass ? "PASS":"FAIL") << endl;
    return 0;
}




inline size_t idx(size_t x, size_t y)   { return y * WIDTH  + x; }
inline size_t kidx(size_t x, size_t y)  { return y * KERNEL + x; }

void convolve2D(vector<double>& in,
                vector<double>& ker,
                vector<double>& out)
{
    out.assign(WIDTH * HEIGHT, 0.0f);
    const int pad = static_cast<int>(KERNEL / 2);

    for (size_t y = 0; y < HEIGHT; ++y) {
        for (size_t x = 0; x < WIDTH; ++x) {
            double sum = 0.0f;
            for (size_t ky = 0; ky < KERNEL; ++ky) {
                for (size_t kx = 0; kx < KERNEL; ++kx) {
                    int ix = static_cast<int>(x) + static_cast<int>(kx) - pad;
                    int iy = static_cast<int>(y) + static_cast<int>(ky) - pad;
                    if (0 <= ix && ix < static_cast<int>(WIDTH) &&
                        0 <= iy && iy < static_cast<int>(HEIGHT)) {
                        sum += in[idx(static_cast<size_t>(ix), static_cast<size_t>(iy))]
                             * ker[kidx(kx, ky)];
                    }
                }
            }
            out[idx(x, y)] = sum;
        }
    }
}
