
#include <fstream>
#include <iostream>
#include <random>
#include <string>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;



const int RING_DIM = 65536;


//Hyperparameters for polynomial approximation precision. You can change the following parameters in 8, 11, 14
const int ALPHA = 8;
//Adjust based on ALPHA value., 8 : 0.003; 11 : 0.0004; 14 : 0.00006;
const double TOL = 0.003;

vector<double> evalChainedPolys(const vector<vector<double>>& coefs, const vector<double>& input);
vector<double> ReLU(const vector<double>& input);
int main() {
    srand(static_cast<unsigned>(time(nullptr)));
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(RING_DIM);
    //Recommended level (allowed multiplication depth) is around 20, but you may increase it if needed.
    parameters.SetMultiplicativeDepth(20);
    parameters.SetScalingModSize(40);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    KeyPair<DCRTPoly> kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);


    usint cyclOrder = cc->GetCyclotomicOrder();
    int32_t n = cyclOrder / 4;
    vector<double> vec(n,0);
    for(int i = 0; i < n; i++){
        vec[i] = 0.5*double(rand())/RAND_MAX + 0.3;
        if (int(rand())%2==0){
            vec[i] = -vec[i];
        }
    }
    Plaintext pt = cc->MakeCKKSPackedPlaintext(vec);
    auto ct = cc->Encrypt(kp.publicKey, pt);

    string filename = "../approx/alpha" + to_string(ALPHA) + ".txt";
    ifstream ifs(filename);
    
    vector<vector<double>> coefs;
    if (ifs.is_open()) {
        string line;
        int len = 0;
        while (getline(ifs, line)) {
            if (line.find(':') != string::npos) {
                int idx, deg;
                sscanf(line.c_str(), "%d : %d", &idx, &deg);
                cout << "Polynomial " << idx << " with degree " << deg << endl;
                vector<double> coef(deg + 1, 0.0);
                for (int i = 0; i <= deg; i++) {
                    getline(ifs, line);
                    coef[i] = stod(line);
                }
                cout << "Coefficients: " << coef << endl;
                coefs.push_back(coef);
                len++;
            }
        }
        coefs.resize(len);
        ifs.close();
    } else {
        cerr << "Error opening file: " << filename << endl;
        return 1;
    }


    // //The following code evaluates a polynomial on plaintext. Uncomment and run it if you want to test.
    // auto check=evalChainedPolys(coefs, vec);
    // for (size_t i = 0; i < 10; i++)
    // {
    //     cout << "1/2 * sign( "<< vec[i] << " ) = " << check[i] << endl;
    // }

    Ciphertext<DCRTPoly> ct_res = ct->Clone();
    
    //Fill in the following section
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    Plaintext pt_res;
    cc->Decrypt(kp.secretKey,ct_res,&pt_res);
    vector<double> vec_res = pt_res->GetRealPackedValue();

    vector<double> res_expected = ReLU(vec);
    bool ispass = true;
    for (int i=0;i<n;i++){
        if (abs(res_expected[i] - vec_res[i]) > TOL){
            cout << "Wrong at " << i << " : " << res_expected[i] << " vs " << vec_res[i] << endl;
            ispass = false;
            break;
        }
    }
    cout << "ReLU : " << (ispass ? "PASS":"FAIL") << endl;
    return 0;
}
static inline double chebEvalOne(const vector<double>& c, double x) {
    const int N = static_cast<int>(c.size()) - 1;
    double b_kp1 = 0.0; // b_{k+1}
    double b_kp2 = 0.0; // b_{k+2}
    // k = N..1
    for (int k = N; k >= 1; --k) {
        double b_k = 2.0 * x * b_kp1 - b_kp2 + c[k];
        b_kp2 = b_kp1;
        b_kp1 = b_k;
    }
    // y = x*b_1 - b_2 + 0.5*c_0
    return x * b_kp1 - b_kp2 + (N >= 0 ? 0.5 * c[0] : 0.0);
}

vector<double> evalChainedPolys(const vector<vector<double>>& coefs, const vector<double>& input) {
    vector<double> result = input;
    for (const auto& c : coefs) {
        vector<double> temp(result.size());
        for (size_t i = 0; i < result.size(); ++i) {
            temp[i] = chebEvalOne(c, result[i]);
        }
        result.swap(temp);
    }
    return result;
}


vector<double> ReLU(const vector<double>& input) {
    vector<double> result = input;
    for (auto& r : result) {
        if (r < 0) r = 0;
    }
    return result;
}