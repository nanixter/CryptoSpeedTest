#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <stddef.h>
#include <cstdlib>
#include <iostream>
#include <fstream>

#include <cstring>
#include <unistd.h>
#include <chrono>

#define KEY_SIZE 256
#define BLOCK_SIZE AES_BLOCK_SIZE
#define IV_SIZE 128
#define MAX_FILE_SIZE 1000000

class Timer {
public:
  Timer() {
    this->reset();
  }

  void reset() {
    this->time  = std::chrono::high_resolution_clock::now();
  }

  double getElapsedNanoseconds() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::high_resolution_clock::now() - this->time).count();
  }

  private:
  std::chrono::high_resolution_clock::time_point time;
};

int encryptFile(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToEncrypt;
  AES_KEY key;

  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));

  fileToEncrypt = fopen("decryptedFile", "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");

  fread(keyString, KEY_SIZE, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);

  AES_set_encrypt_key((const unsigned char*)keyString, KEY_SIZE, &key);

  int bytesRead = 0;
  unsigned char* cipherText = (unsigned char*)(malloc(MAX_FILE_SIZE*sizeof(char)));
  int temp;
  while(1){
	temp = fread(cipherText, 1, BLOCK_SIZE, fileToEncrypt);
	bytesRead += temp;
  	if(temp != 0){
  		if(bytesRead == 0){
  			return -1;
  		}
  		break;
  	}
  }
  unsigned char* plainText = (unsigned char*)(malloc(MAX_FILE_SIZE*sizeof(char)));
  //encrypt plaintext and move data into ciphertext
  AES_cbc_encrypt(cipherText, plainText, bytesRead, &key, iv, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* encryptedFile = fopen(filename, "w+");//file descript
  fwrite(cipherText, 1, strlen((char*)cipherText), encryptedFile);
  fclose(encryptedFile);
  fclose(fileToEncrypt);
  fclose(ivFile);
  fclose(keyFile);
  return 1;
}

//done? 
//takes a file of given name, decrypts data and writes it into "decryptedFile"
//input: name of file containing encrypted data
//return: -1 if error, 1 otherwise
int decryptFile(char*& filename)
{
  FILE* keyFile;
  FILE* ivFile;
  FILE* fileToDecrypt;
  AES_KEY key;

  unsigned char* keyString = (unsigned char*)(malloc(KEY_SIZE*sizeof(char)));
  unsigned char* iv = (unsigned char*)(malloc(BLOCK_SIZE*sizeof(char)));

  fileToDecrypt = fopen(filename, "r");
  keyFile = fopen("aesKey", "r");
  ivFile = fopen("aesIv", "r");

  fread(keyString, KEY_SIZE, 1, keyFile);
  fread(iv, BLOCK_SIZE, 1, keyFile);

  AES_set_encrypt_key((const unsigned char*) keyString, KEY_SIZE, &key);

  int numBlocks = 0;
  unsigned char* plainText = (unsigned char*)(malloc(MAX_FILE_SIZE*sizeof(char)));
  while(fread(plainText, 1, BLOCK_SIZE, fileToDecrypt) != 0){numBlocks++;}
  if(numBlocks == 0){
    return -1;
  }

  unsigned char* cipherText = (unsigned char*)(malloc(MAX_FILE_SIZE*sizeof(char)));
  //decrypt cyphertext and move data into plaintext
  AES_cbc_encrypt(cipherText, plainText, numBlocks*BLOCK_SIZE, &key, iv, AES_DECRYPT);
  //write to"decryptedFile"
  FILE* decryptedFile = fopen("decryptedFile", "w+");//file descript
  fwrite(plainText, 1, strlen((char*)plainText), decryptedFile);
  fclose(decryptedFile);
  fclose(fileToDecrypt);
  fclose(ivFile);
  fclose(keyFile);
  return 1;
}

uint8_t* AllocPageAligned(int byteSize, volatile uint8_t **rawPtr) {
  const int PAGE_SIZE_MASK = 4095;
  *rawPtr = reinterpret_cast<uint8_t *>(malloc(byteSize + PAGE_SIZE_MASK));
  uintptr_t temp = reinterpret_cast<uintptr_t>(*rawPtr);
  temp = (temp + PAGE_SIZE_MASK) & ~PAGE_SIZE_MASK;
  return  reinterpret_cast<uint8_t*>(temp);
}

int main(int argc, char *argv[]) {
  printf("1");
  Timer timer;
  printf("2");
  if(argc < 2) {
    std::cout << "Usage: " <<argv[0] <<" something broke this?" <<std::endl;
    std::exit(EXIT_FAILURE);
  }

  printf("3");
  char* filename = argv[0];

  printf("4");
  timer.reset();
  //encrypt & decrypt
  printf("5");
  encryptFile(filename);
  printf("6");
  decryptFile(filename);
  printf("7");
  double total_time = timer.getElapsedNanoseconds();
  printf("8");
  //std::cout << "Access time for block of size "<< num_cache_lines_guess * L1_CACHE_LINE_SIZE <<" bytes: " << total_time/(num_cache_lines_guess * L1_CACHE_LINE_SIZE) <<" nanoseconds" <<std::endl;
  std::cout << total_time << std::endl;

  return 0;
}
