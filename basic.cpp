/*
목표 : 4문제
1. 사칙연산

3. conv
4. fc 레이어
2. relu연산
*/

#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "openfhe.h"
#include "math/math-hal.h"

using namespace lbcrypto;
using namespace std;

const double TOL = 0.001;


int main() {
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(2);
  parameters.SetScalingModSize(40);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  KeyPair<DCRTPoly> kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);
  cc->EvalRotateKeyGen(kp.secretKey, {1,2,3});



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


  Ciphertext<DCRTPoly> add_ct_res;
  Ciphertext<DCRTPoly> sub_ct_res;
  Ciphertext<DCRTPoly> mul_ct_res;
  Ciphertext<DCRTPoly> rot_ct_res;
  //TODO : fill behind code please!
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  add_ct_res = cc->EvalAdd(ct1, ct2);
  sub_ct_res = cc->EvalSub(ct1, ct2);
  mul_ct_res = cc->EvalMultAndRelinearize(ct1,ct2);
  rot_ct_res = cc->EvalRotate(ct1, 3);
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


  Plaintext pt_res;
  cc->Decrypt(kp.secretKey,add_ct_res,&pt_res);
  vector<complex<double>> add_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,sub_ct_res,&pt_res);
  vector<complex<double>> sub_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,mul_ct_res,&pt_res);
  vector<complex<double>> mul_vec_res = pt_res->GetCKKSPackedValue();
  cc->Decrypt(kp.secretKey,rot_ct_res,&pt_res);
  vector<complex<double>> rot_vec_res = pt_res->GetCKKSPackedValue();


  bool ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] + vec2[i];
    if (abs(value - add_vec_res[i]) > TOL){
      ispass = false;
      break;
    }
  }
  cout << "Addition : " << (ispass ? "PASS":"FAIL") << endl;

  ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] - vec2[i];
    if (abs(value - sub_vec_res[i]) > TOL){
      ispass = false;
      break;
    }
  }
  cout << "Subtraction : " << (ispass ? "PASS":"FAIL") << endl;

  ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[i] * vec2[i];
    if (abs(value - mul_vec_res[i]) > TOL){
      ispass = false;
      break;
    }
  }
  cout << "Multiplication : " << (ispass ? "PASS":"FAIL") << endl;

    ispass = true;
  for (int i = 0;i<n;i++){
    complex value = vec1[(i + 3) % n];
    if (abs(value - rot_vec_res[i]) > TOL){
      ispass = false;
      break;
    }
  }
  cout << "Rotation : " << (ispass ? "PASS":"FAIL") << endl;
  

  return 0;
}