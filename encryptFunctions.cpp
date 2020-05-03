#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <stddef.h>
#include <cstdlib>
#include <iostream>
#include <fstream>

#include <cstring>
#include <unistd.h>

#define KEY_SIZE 256
#define BLOCK_SIZE AES_BLOCK_SIZE

int encryptFile(char*& filename)
{
  FILE* keyFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int blocks = fsize/BLOCK_SIZE;
  //encrypt plaintext and move data into ciphertext
  for(int i = 0; i < blocks; i++){
    AES_encrypt(&cipherText[i*BLOCK_SIZE], plainText, &key);
  }
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(keyFile);

  free(keyString);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFile(char*& filename)
{
  FILE* keyFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int blocks = fsize/BLOCK_SIZE;
  //decrypt cyphertext and move data into plaintext
  for(int i = 0; i < blocks; i++){
    AES_decrypt(&plainText[i*BLOCK_SIZE], cipherText, &key);
  }
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(keyFile);

  free(keyString);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileCBC(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  AES_cbc_encrypt(plainText, cipherText, fsize, &key, iv, AES_ENCRYPT);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileCBC(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //decrypt cyphertext and move data into plaintext
  AES_cbc_encrypt(cipherText, plainText, fsize, &key, iv, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileECB(char*& filename)
{
  FILE* keyFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  int blocks = fsize/BLOCK_SIZE;
  for(int i = 0; i < blocks; i++){
    AES_ecb_encrypt(&cipherText[i*BLOCK_SIZE], plainText, &key, AES_ENCRYPT);
  }
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(keyFile);

  free(keyString);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileECB(char*& filename)
{
  FILE* keyFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int blocks = fsize/BLOCK_SIZE;
  //decrypt cyphertext and move data into plaintext
  for(int i = 0; i < blocks; i++){
    AES_ecb_encrypt(&plainText[i*BLOCK_SIZE], cipherText, &key, AES_DECRYPT);
  }
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(keyFile);

  free(keyString);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileCFB128(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  int num = 0;
  AES_cfb128_encrypt(plainText, cipherText, fsize, &key, iv, & num, AES_ENCRYPT);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileCFB128(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int num = 0;
  //decrypt cyphertext and move data into plaintext
  AES_cfb128_encrypt(cipherText, plainText, fsize, &key, iv, &num, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileCFB1(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  int num = 0;
  AES_cfb1_encrypt(plainText, cipherText, fsize, &key, iv, & num, AES_ENCRYPT);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileCFB1(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int num = 0;
  //decrypt cyphertext and move data into plaintext
  AES_cfb1_encrypt(cipherText, plainText, fsize, &key, iv, &num, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileCFB8(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  int num = 0;
  AES_cfb128_encrypt(plainText, cipherText, fsize, &key, iv, & num, AES_ENCRYPT);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileCFB8(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int num = 0;
  //decrypt cyphertext and move data into plaintext
  AES_cfb128_encrypt(cipherText, plainText, fsize, &key, iv, &num, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

int encryptFileOFB128(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToEncrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  fseek(fileToEncrypt, 0, SEEK_END);
  long fsize = ftell(fileToEncrypt);
  fseek(fileToEncrypt, 0, SEEK_SET);
  unsigned char* plainText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(plainText, sizeof(char), fsize, fileToEncrypt);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  int num = 0;
  AES_ofb128_encrypt(plainText, cipherText, fsize, &key, iv, & num);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen("encryptedFile", "w+");//file descript

  fwrite(cipherText, sizeof(char), strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFileOFB128(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;
  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));
  fileToDecrypt = fopen("encryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");
  fread(keyString, KEY_SIZE/8, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);
  AES_set_decrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  fseek(fileToDecrypt, 0, SEEK_END);
  long fsize = ftell(fileToDecrypt);
  fseek(fileToDecrypt, 0, SEEK_SET);
  unsigned char* cipherText = (unsigned char*)(malloc((fsize+1)*sizeof(char)));
  fread(cipherText, sizeof(char), fsize, fileToDecrypt);

  unsigned char* plainText = (unsigned char*)(malloc((fsize+BLOCK_SIZE+1)*sizeof(char)));
  int num = 0;
  //decrypt cyphertext and move data into plaintext
  AES_ofb128_encrypt(cipherText, plainText, fsize, &key, iv, &num);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen(filename, "w+");//file descript
  fwrite(plainText, sizeof(char), strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);

  free(keyString);
  free(iv);
  free(cipherText);
  free(plainText);
  return 1;
}
