
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;

const double TOL = 0.0001;
const int LEN = 5;
const int CLEN = 5;


int main() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(10);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    vector<int> rotvec(LEN+CLEN-1);
    for(int i =0;i<LEN+CLEN-1;i++){
        rotvec[i] = LEN -1 - i;
    }
    cc->EvalRotateKeyGen(kp.secretKey, rotvec);


    usint cyclOrder = cc->GetCyclotomicOrder();
    int32_t n = cyclOrder / 4;
    vector<double> vec(n,0);
    for(int i = 0; i < LEN; i++){
        vec[i] = 2 * double(rand())/RAND_MAX - 1;
    }
    Plaintext pt = cc->MakeCKKSPackedPlaintext(vec);
    auto ct = cc->Encrypt(kp.publicKey, pt);

    vector<double> kernel;
    kernel.resize(LEN*CLEN);
    for(int i = 0; i < LEN * CLEN; i++){
        kernel[i] = 2 * double(rand())/RAND_MAX - 1;

    }


    Ciphertext<DCRTPoly> ct_res;
    //TODO : fill belllow code please!
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    vector<double> zeros(n,0);
    pt = cc->MakeCKKSPackedPlaintext(zeros);
    ct_res = cc->Encrypt(kp.publicKey,pt);
    vector<double>* kernel_;
    kernel_ = new vector<double>[CLEN+LEN-1];
    for (int i = 0;i<CLEN+LEN-1;i++){
        kernel_[i] = vector<double>(n,0);
    }

    for (int i = 0;i<CLEN;i++){
        for(int j=0;j<LEN;j++){
            kernel_[i-j+LEN - 1][i] = kernel[i*LEN + j];
        }
    }

    for(int idx=0; idx < LEN + CLEN - 1; idx++){
        auto pt_ = cc->MakeCKKSPackedPlaintext(kernel_[idx]);
        auto ctrot=cc->EvalRotate(ct,LEN - 1 -idx);
        auto res = cc->EvalMult(pt_,ctrot);

        cc->RescaleInPlace(res);
        ct_res = cc->EvalAdd(ct_res,res);
    }
    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Plaintext pt_res;
    cc->Decrypt(kp.secretKey,ct_res,&pt_res);
    vector<double> vec_res = pt_res->GetRealPackedValue();

    bool ispass = true;
    for (int i=0;i<CLEN;i++){
        double value = 0;
        for (int j=0;j<LEN;j++){
            value += kernel[i*LEN+j] * vec[j];
        }

        if (abs(value - vec_res[i]) > TOL){
            ispass = false;
            break;
        }
    }
    cout << "ReLU : " << (ispass ? "PASS":"FAIL") << endl;

    return 0;
}