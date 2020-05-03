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

#include "encryptFunctions.cpp"

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

int main(int argc, char* argv[]) {
  Timer timer;

  char* filename = (char*)malloc(sizeof(char)*20);
  filename = argv[1];
  // strcpy(filename, "messageEncoder.c");
  char* filename2 = (char*)malloc(sizeof(char)*20);
  strcpy(filename2, "output");
  timer.reset();
  //encrypt & decrypt
  encryptFile(filename);
  decryptFile(filename2);
  double total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;
  
  timer.reset();
  //encrypt & decrypt
  encryptFileCBC(filename);
  decryptFileCBC(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout << total_time << std::endl;

  timer.reset();
  //encrypt & decrypt
  encryptFileECB(filename);
  decryptFileECB(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;

  timer.reset();
  //encrypt & decrypt
  encryptFileCFB128(filename);
  decryptFileCFB128(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;

  timer.reset();
  //encrypt & decrypt
  encryptFileCFB1(filename);
  decryptFileCFB1(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;

  timer.reset();
  //encrypt & decrypt
  encryptFileCFB8(filename);
  decryptFileCFB8(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;

  timer.reset();
  //encrypt & decrypt
  encryptFileOFB128(filename);
  decryptFileOFB128(filename2);
  total_time = timer.getElapsedNanoseconds();
  std::cout <<total_time << std::endl;

  return 0;
}
