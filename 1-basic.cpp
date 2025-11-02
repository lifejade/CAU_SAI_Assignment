#include <fstream>
#include <iostream>
#include <random>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;

const int RING_DIM = 16384;
const double TOL = 0.0001;

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
  cc->EvalRotateKeyGen(kp.secretKey, {1,2,3,4,5});



  usint cyclOrder = cc->GetCyclotomicOrder();
  int32_t n = cyclOrder / 4;
  vector<complex<double>> vec1;
  vec1.resize(n);
  for(int i = 0; i < n; i++){
    vec1[i] = 2 * double(rand())/RAND_MAX - 1;
  }
  Plaintext pt1 = cc->MakeCKKSPackedPlaintext(vec1);

  vector<complex<double>> vec2;
  vec2.resize(n);
  for(int i = 0; i < n; i++){
    vec2[i] = 2 * double(rand())/RAND_MAX - 1;
  }
  Plaintext pt2 = cc->MakeCKKSPackedPlaintext(vec2);

  auto ct1 = cc->Encrypt(kp.publicKey, pt1);
  auto ct2 = cc->Encrypt(kp.publicKey, pt2);


  Ciphertext<DCRTPoly> add_ct_res = ct1->Clone();
  Ciphertext<DCRTPoly> sub_ct_res = ct1->Clone();
  Ciphertext<DCRTPoly> mul_ct_res = ct1->Clone();
  Ciphertext<DCRTPoly> rot_left3_ct_res = ct1->Clone();

  //Fill in the following section
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


  Plaintext pt_res;
  cc->Decrypt(kp.secretKey,add_ct_res,&pt_res);
  vector<complex<double>> add_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,sub_ct_res,&pt_res);
  vector<complex<double>> sub_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,mul_ct_res,&pt_res);
  vector<complex<double>> mul_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,rot_left3_ct_res,&pt_res);
  vector<complex<double>> rot_left3_vec_res = pt_res->GetCKKSPackedValue();


  bool ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] + vec2[i];
    if (abs(value - add_vec_res[i]) > TOL){
      cout << "Wrong at " << i << " : " << value << " vs " << add_vec_res[i] << endl;
      ispass = false;
      break;
    }
  }
  cout << "Addition : " << (ispass ? "PASS":"FAIL") << endl;

  ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] - vec2[i];
    if (abs(value - sub_vec_res[i]) > TOL){
      cout << "Wrong at " << i << " : " << value << " vs " << sub_vec_res[i] << endl;
      ispass = false;
      break;
    }
  }
  cout << "Subtraction : " << (ispass ? "PASS":"FAIL") << endl;

  ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] * vec2[i];
    if (abs(value - mul_vec_res[i]) > TOL){
      cout << "Wrong at " << i << " : " << value << " vs " << mul_vec_res[i] << endl;
      ispass = false;
      break;
    }
  }
  cout << "Multiplication : " << (ispass ? "PASS":"FAIL") << endl;

  ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[(i + 3) % n];
    if (abs(value - rot_left3_vec_res[i]) > TOL){
      cout << "Wrong at " << i << " : " << value << " vs " << rot_left3_vec_res[i] << endl;
      ispass = false;
      break;
    }
  }
  cout << "Rotation : " << (ispass ? "PASS":"FAIL") << endl;
  

  return 0;
}