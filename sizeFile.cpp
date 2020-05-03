#include <stdio.h>
#include <string.h>

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

int main(int argc, char* argv[]) {
  int numKIB = std::atoi(argv[2]);
  char oneKIB[1025];
  strcpy(oneKIB, "MesopotamiaisoftenviewedasthecradleofcivilizationandthehomeofthefirstcitiesTheancientperiodfrom5500BCto3100BCisthetimewhereMesopotamiansocietiesgrewfromsmallsedentaryconglomerationstolargeurbanizedcitiesTheperiodcanbebrokenupintomainphases:theUbaidperiodapproximately55003800BCandtheUrukperiodapproximately38003100BCStein35Thesephasesareanalyzedbythetwoarticlescoveredinthispaper:GilSteinspapertitledEconomyRitualandPowerinUbaidMesopotamiadissectsUbaidperiodcommunitiesandcharacterizesthemasstaplefinancebasedchiefdomswhileGeoffEmberlingsUrbanSocialTransformationsandtheProblemoftheFirstCitydiscussesUrukperiodurbanizationandprovidesevidencebasedaroundthenorthernTellBraksettlementthatproteststhetheoryoflinearsouthtonorthdisseminationofurbanizationduringthisperiodInthispaperIwillfirstsummarizethemaintopicsandkeyideascoveredinbotharticlesIwillthendelveintotherelationshipbetweenthetwopapersaswellastheirrespectiveperiodsinanattempttoshowthattheUrukperiodurbanizationdemonstratesaadaptationfromthestrictUbaidperiodstaplefin");
  FILE* fp;
  char* filename = (char*)malloc(sizeof(char)*20);
  filename = argv[1];
  fp = fopen(filename, "w+");
  for (int i = 0; i < numKIB; ++i)
  {
  	fwrite(oneKIB, 1, 1024, fp);
  }
  return 0;
}
