#include "security_functions.cpp"
using namespace std;
int main() {
  //128 bit key (16 characters * 8 bit)
  unsigned char *key = (unsigned char *)"0123456789012345";

  //Our Plaintext
  unsigned char plaintext[] = "This is a Very Short message";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, depending on the
   * algorithm and mode*/
  const EVP_CIPHER* cipher = EVP_aes_128_cbc();
  int iv_len = EVP_CIPHER_iv_length(cipher);
  unsigned char* ciphertext = (unsigned char *) malloc(sizeof(plaintext)+16+iv_len);

  int decryptedtext_len, ciphertext_len;

  // Encrypt utility function
  ciphertext_len = cbc_encrypt (plaintext, strlen ((char *)plaintext), key, ciphertext);

  // Redirect our ciphertext to the terminal
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  // Buffer for the decrypted text 
  unsigned char* decryptedtext = (unsigned char *) malloc(sizeof(ciphertext_len));

  // Decrypt the ciphertext
decryptedtext_len = cbc_decrypt(ciphertext,strlen ((char *)ciphertext), key, decryptedtext );

  // Add a NULL terminator. We are expecting printable text
  decryptedtext[decryptedtext_len] = '\0';
  printf("%i\n", decryptedtext_len);
  // Show the decrypted text 
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);

return 0;
}
