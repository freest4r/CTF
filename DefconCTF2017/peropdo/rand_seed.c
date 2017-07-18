#include<stdio.h>
int main(){
    unsigned int i, ret;
    int j;

    for(i=0xe73940; i<=0xffffffff; i++){
        srand(i);
        for (j=1;j<=22;j++){
            rand();
        }
        ret = rand();
        if (0x80ecf00 <= ret  && 0x80ee000 >= ret){
            printf("%x: %x\n", i, ret);
        }
    }
    return 0;
}
