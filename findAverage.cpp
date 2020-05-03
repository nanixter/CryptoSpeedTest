#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	FILE* fp;
	fp = fopen("result.txt", "r");
	if(fp == NULL){
	     printf("Error! opening file");
        // Program exits if file pointer returns NULL.
        exit(1);
    }
	char str[30];
	double basicAEStotal = 0;
	double CBCtotal = 0;
	double ECBtotal = 0;
	double CFB128total = 0;
	double CFB1total = 0;
	double CFB8total = 0;
	double OFB128total = 0;
	double basicAESaverage = 0;
	double CBCaverage  = 0;
	double ECBaverage  = 0;
	double CFB128average  = 0;
	double CFB1average  = 0;
	double CFB8average  = 0;
	double OFB128average  = 0;
	double temp;
	int counter = 0;
	int i = 0;
	while(fscanf(fp, "%lf", &temp) != -1){
		if(i == 7){
			i = 0;
			counter++;
		}
		switch(i){
			case 0:
				basicAEStotal += temp;
				break;
			case 1:
				CBCtotal += temp;
				break;
			case 2:
				ECBtotal += temp;
				break;
			case 3:
				CFB128total += temp;
				break;
			case 4:
				CFB1total += temp;
				break;
			case 5:
				CFB8total += temp;
				break;
			case 6:
				OFB128total += temp;
				break;
		}
		i++;
	}
	if(counter != 0){
		basicAESaverage = basicAEStotal/counter;
		CBCaverage = CBCtotal/counter;
		ECBaverage = ECBtotal/counter;
		CFB128average = CFB128total/counter;
		CFB1average = CFB1total/counter;
		CFB8average = CFB8total/counter;
		OFB128average = OFB128total/counter;

		basicAESaverage = basicAESaverage/1000000;
		CBCaverage = CBCaverage/1000000;
		ECBaverage = ECBaverage/1000000;
		CFB128average = CFB128average/1000000;
		CFB1average = CFB1average/1000000;
		CFB8average = CFB8average/1000000;
		OFB128average = OFB128average/1000000;
	}
	printf("Basic AES Average = %lf millisecs\n", basicAESaverage);
	printf("CBC Average = %lf millisecs\n", CBCaverage);
	printf("ECB Average = %lf millisecs\n", ECBaverage);
	printf("CFB128 Average = %lf millisecs\n", CFB128average);
	printf("CFB1 Average = %lf millisecs\n", CFB1average);
	printf("CFB8 Average = %lf millisecs\n", CFB8average);
	printf("OFB128 Average = %lf millisecs\n", OFB128average);

	//printf("%lf\n", basicAESaverage);
	//printf("%lf\n", CBCaverage);
	//printf("%lf\n", ECBaverage);
	//printf("%lf\n", CFB128average);
	//printf("%lf\n", CFB1average);
	//printf("%lf\n", CFB8average);
	//printf("%lf\n", OFB128average);

	fclose(fp);
}
