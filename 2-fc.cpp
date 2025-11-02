
#include <fstream>
#include <iostream>
#include <random>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;

const int RING_DIM = 512;
const double TOL = 0.0001;

const int INPUT_DIM = 256;
const int OUTPUT_DIM = 10;


int main() {
    srand(static_cast<unsigned>(time(nullptr)));
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(RING_DIM);
    parameters.SetMultiplicativeDepth(10);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    //You may add more rotation keys if needed.
    vector<int> rotvec(INPUT_DIM+OUTPUT_DIM-1);
    for(int i =0;i<INPUT_DIM+OUTPUT_DIM-1;i++){
        rotvec[i] = INPUT_DIM -1 - i;
    }
    cc->EvalRotateKeyGen(kp.secretKey, rotvec);


    usint cyclOrder = cc->GetCyclotomicOrder();
    int32_t n = cyclOrder / 4;
    vector<double> vec(n,0);
    for(int i = 0; i < INPUT_DIM; i++){
        vec[i] = 2 * double(rand())/RAND_MAX - 1;
    }
    Plaintext pt = cc->MakeCKKSPackedPlaintext(vec);
    auto ct = cc->Encrypt(kp.publicKey, pt);

    vector<double> kernel;
    kernel.resize(INPUT_DIM*OUTPUT_DIM);
    for(int i = 0; i < INPUT_DIM * OUTPUT_DIM; i++){
        kernel[i] = 2 * double(rand())/RAND_MAX - 1;

    }


    Ciphertext<DCRTPoly> ct_res = ct->Clone();

    //Fill in the following section
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Plaintext pt_res;
    cc->Decrypt(kp.secretKey,ct_res,&pt_res);
    vector<double> vec_res = pt_res->GetRealPackedValue();

    bool ispass = true;
    for (int i=0;i<OUTPUT_DIM;i++){
        double value = 0;
        for (int j=0;j<INPUT_DIM;j++){
            value += kernel[i*INPUT_DIM+j] * vec[j];
        }

        if (abs(value - vec_res[i]) > TOL){
            cout << "Wrong at " << i << " : " << value << " vs " << vec_res[i] << endl;
            ispass = false;
            break;
        }
    }
    cout << "Fully Connect (Matrix Multiplication) : " << (ispass ? "PASS":"FAIL") << endl;

    return 0;
}