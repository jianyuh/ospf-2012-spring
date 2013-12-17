#include <stdio.h>
#include "global.h"

using namespace std;

extern char errorlogfile[70];

void errorprint(error_type_t errNum, char errstring[])
{
    FILE * errLogFile = fopen(errorlogfile,"a+");
    switch(errNum)
    {
        case INITERROR:
            fprintf(errLogFile,"INIT ERROR:%s\n",errstring);
            break;
        case SENDPKTERROR:
            fprintf(errLogFile,"SEND PACKET ERROR:%s\n",errstring);
            break;
        case RECVPKTERROR:
            fprintf(errLogFile,"RECEIVE PACKET ERROR:%s\n",errstring);
            break;
        default:
            fprintf(errLogFile,"UNKNOWN TYPE:%s\n",errstring);
    }
    fclose(errLogFile);
}






