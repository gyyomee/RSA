# 주 제 1 : RSA 암호 구현하기

## RSA 암호화 과정

![1](https://user-images.githubusercontent.com/22466478/51464491-06aa1880-1da9-11e9-9349-23bed3577895.jpg)

**main** : 평문을 입력 받는다. RSA_Enc로 RSA 암호화를 시작. 완성된 암호문을 출력.

**RSA_Enc** : 수신자의 공개 키 파일인 `public_key.txt`를 연다. 파일에서 공개키 n을 배열N에 저장하고 공개키 e를 배열E에 저장한다. while문에서 117바이트씩 암호를 수행하여 평문이 모두 암호화 될 때까지 암호화한다. 이 과정은 다음과 같이 수행된다. `get_from_message` 함수로 평문을 이진형태로 바꾸어 h에 저장한다. `rsa_std.c`에 있는 `CONV_B_to_O`를 이용해 이진 평문으로 변환한 h를 octet으로 변환해 DATA에 저장한다. `rsa_std.c`에 있는 `rand_g`함수를 이용하여 패딩에 사용할 난수를 생성한다. 생성한 랜덤 패딩 ps는 `CONV_B_to_O`를 이용하여 octet으로 변환하여 O_PS에 저장한다. 다음 암호문블록 EB에 앞에서 생성한 O_PS와 DATA를 저장한다. 그리고 마지막으로 EB값을 이용해 bit값을 변경시켜 EB1에 저장하여 암호문 블록 패딩을 종료한다. `rsa_std.c`에 있는 `LeftTORight_Pow`함수를 이용해서 수신자의 공개 키로 암호화 즉 ![img](file:///C:\Users\rkdud\AppData\Local\Temp\msohtmlclip1\01\clip_image002.png) 을 진행한다. 이때 암호문은 S에 저장된다. `rsa_std.c`에 있는 `CONV_R_to_B`함수를 이용해서 생성된 암호문 S를 s에 이진형태로 저장한다. 마지막으로 `put_to_message` 함수를 이용해 결과를 result에 저장한다. 이렇게 암호화 과정이 반복된다.

**get_from_message** : msg, a, mn을 메시지로 받는다. Msg의 내용을 2진수로 변환시켜 a에 저장한다. mn은 msg의 길이이다.

**CONV_B_to_O(rsa_std)** : A, B, mn을 매개변수로 받는다. A의 값을 8진수로 변환시켜 B에 저장한다. mn은 A의 길이이다.

**rand_g(rsa_std)** : 매개변수는 out과 n. 랜덤으로 x를 생성해서 out에 랜덤으로 생성한 수를 저장한다.

**LeftTORight_Pow(rsa_std)** : A, E, C, N, mn을 매개변수. C를 초기화한다. CONV_R_to_B 함수를 이용해서 E를 이진형태로 e에 저장한다. Conv_mma함수를 이용해서 암호화를 수행한 다음 이 결과를 C배열에 저장한다.

**CONV_R_to_B(rsa_std)** : A, B, mn을 매개변수. A의 값을 이진형태로 변환시켜 B에 저장한다.

**put_to_message** : msg, a, mn을 매개변수. b에 a값을 바이트 형태로 변환시켜 저장한 다음 msg에 b의 내용을 저장한다.

**Conv_mma(rsa_std)** : 매개변수로 A, B, C, N, mn. acumA에 A, B, arryC, acumC의 내용을 이용하여 저장하고 arryC에 acum과 LAND값을 AND시켜 저장한 다음 acumA를 비트 이동시켜 acumC에 저장한다. 다음 X에 arrayC값을 저장하고 `rsa_std.c`의 `Modular`함수를 이용하여 X로 모듈러를 진행하여 마지막으로 C에 X값을 저장한다. 이 과정은 ![img](file:///C:\Users\rkdud\AppData\Local\Temp\msohtmlclip1\01\clip_image004.png)를 구하는 과정이다.

**Modular(rsa_std)** : 매개변수로 X, N, mn. X에 대해 mod n을 계산하는 함수이다. 



## RSA 복호화 과정

![2](https://user-images.githubusercontent.com/22466478/51464656-66082880-1da9-11e9-9610-13a23fbfb903.jpg)

**main** : 1_1에서 구한 암호문을 RSA_Dec로 RSA 복호화를 시작. 완성된 복호문을 출력

**RSA_Dec** : 비밀키 파일을 열어서 공개키 d와 모듈라 n을 배열 D와 N에저장한다. get_from_message함수를 이용해서 암호문을 이진형태로 s에 저장한다. CONV_B_to_R을 이용해서 s함수를 S에 Radix로 바꾸어 저장한다. LeftTORight_Pow함수를 이용해서 사용자의 비밀키로 복호화를 행하여 H에 저장한다. CONV_R_to_B함수를 이용해서 복호화된 데이터를 v_h에 이진형태로 저장한다. CONV_B_to_O함수를 이용해서 D_EB에 octet형태로 변환해서 저장한다. 다음 패딩을 제외한 복호문을 추출하여 D_DATA에 저장한 후 CONV_O_to_B를 이용하여 d_d에 이진형태로 밖어 저장한다. put_to_messgage를 이용하여 result에 바이트 형태로 저장한다.

**CONV_B_to_R(rsa_std)** : 매개변수 A, B, mn. A를 Radix형태로 B에 저장한다

**CONV_O_to_B(rsa_std)** : 매개변수 A, B, mn. A를 이진형태로 B에 저장한다.



## 결과 분석

![3](https://user-images.githubusercontent.com/22466478/51464805-c303de80-1da9-11e9-8ae5-5a60a3362aa4.jpg)



# 주 제 2 : RSA 서명 구현하기

## RSA 서명

![4](https://user-images.githubusercontent.com/22466478/51464888-f34b7d00-1da9-11e9-8cc8-a040f69abf49.jpg)

**RSA_Signature** : 서명에 사용할 비밀키 파일을 연다. 비밀키 파일로부터 비밀키 d와 모듈라 n을 배열 D와 N에 저장한다. 서명할 파일명을 가져온다. `MD5`를 수행하여 해시과정을 완료한다. 이 값은 `hash_text`에 저장되고 MD5식별값을 추가하여 이것을 이진 값으로 변환해 h에 저장. `CONV_B_to_O`를 이용해 이진데이터를 octet으로 변환하여 `HDATA`에 저장한다. 패딩과정을 수행하여 SB1에 저장한 다음 `LeftTORight_Pow`로 최종 메시지를 암호화하여 S에 저장한다. `CONV_R_to_B`로 Radix를 이진데이터로 변환하여 s에 저장한다. 다음 s를 `(filename).sgn`파일로 저장하여 서명을 완료한다.

**MD5** : 매개변수 fptr, result. MD5_init, padding, MD5_digest을 걸쳐서 result에 digest내용을 저장한다.

**padding** : 매개변수 in, msg_len. in에 MD5 패딩을 수행한다.

**MD5_init** : init_reg배열의 값을 초기화한다.

**MD5_digest** : 매개변수 in. FF, GG, HH, II 라운드 과정을 수행해 init_reg에 최종 값을 더하고 make_Bit128수행.

**make_Bit128** : 매개변수 in, a, b, c, d. word단위의 값을 byte단위의 값으로 변환시켜 in에 저장.



## RSA 검증

![5](https://user-images.githubusercontent.com/22466478/51465057-5fc67c00-1daa-11e9-9d56-64538a385bb0.jpg)

**RSA_Verification** : 서명자의 공개 키 파일을 연다. 공개키 파일로부터 공개키 e와 모듈라 n을 배열 E와 N에 저장. 검증할 파일명을 읽어와 MD5해쉬를 수행. 서명파일을 `get_from_file`을 통해 읽어와 `CONV_B_to_R` 로 이진데이터를 Radix에 저장. `LeftTORight_Pow`로 서명검증. `CONV_R_to_B`로 Radix를 이진수, `CONV_B_to_O`로 이진수를 ocetet. 완료한 값인 V_HDATA에서 MD5식별값을 제외하고 해쉬 값만 비교하여 일치하면 검증성공 일치하지 않으면 검증실패이다.



## 결과 분석

![6](https://user-images.githubusercontent.com/22466478/51465140-913f4780-1daa-11e9-864c-c541fb69fe26.jpg)

RSA 서명



![7](https://user-images.githubusercontent.com/22466478/51465141-913f4780-1daa-11e9-8aad-ff6bb1648129.jpg)

RSA 검증