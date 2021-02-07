## example for SGX
This is an example of using vdso-time in SGX. 
This example combines vdso-time example of io_uring and hello-rust example of incubator-teaclave-sgx-sdk.
- ./app : untrusted code
- ./bin : executable program
- ./enclave : trusted code
- ./lib : library

### run example in SGX
1. Prepare environments.
    - clone incubator-teaclave-sgx-sdk repo to ```./third_parties``` and checkout incubator-teaclave-sgx-sdk to ```d94996``` commit.
    ```
        ./vdso-time:
            ./src
            ./examples
            ./ocalls
        ./third_parties
            ./incubator-teaclave-sgx-sdk
    ```
    - prepare environments for incubator-teaclave-sgx-sdk.
2. ```make```
3. ```cd bin && ./app```
