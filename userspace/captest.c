void _start(void){
 volatile int r;
 asm volatile("int $0x80" : "=a"(r) : "a"(7), "b"(5), "c"(0), "d"(1) : "memory");
 asm volatile("int $0x80" : "=a"(r) : "a"(8), "b"(5), "c"(0) : "memory");
 asm volatile("int $0x80" : "=a"(r) : "a"(7), "b"(6), "c"(5), "d"(1) : "memory");
 for(;;){}
}