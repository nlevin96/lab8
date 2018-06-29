#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <string.h>
#define TRUE 1
#define FALSE 0

char* filename;
int fd = -1;
void* map_start;
struct stat fd_stat;
Elf64_Ehdr *header;
int num_of_section_headers;

int check_file(){
    if(fd == -1) {
        perror("ERROR! fd == -1");
        return 0;
    }
    return 1;
}

void examine_elf_file(){
    char* data_en_msg ;
    if(filename != NULL) free(filename);
    filename = malloc(100);
    printf("%s\n","Please enter a filename:");
    scanf("%s",filename);
    if(fd != -1) close(fd);
    if( (fd = open(filename, O_RDWR)) < 0 ) {
      perror("error in open");
      exit(-1);
   }
   if( fstat(fd, &fd_stat) != 0 ) {
      perror("stat failed");
      exit(-1);
   }
   if ( (map_start = mmap(0, fd_stat.st_size, PROT_READ | PROT_WRITE , MAP_SHARED, fd, 0)) == MAP_FAILED ) {
      perror("mmap failed");
      exit(-4);
   }
   header = (Elf64_Ehdr *) map_start;
   num_of_section_headers = header->e_shnum;
   //bytes 1,2,3 of the magic number 
   printf("Magic:\t\t\t\t%c %c %c\n", header -> e_ident[1], header -> e_ident[2], header -> e_ident[3]);
   //data encoding scheme of the object file.
   if(header -> e_ident[5] == 1) data_en_msg = "'s complement, little endian";
   else data_en_msg = "'s complement, big endian";
   printf("Data:\t\t\t\t%d%s\n", header -> e_ident[5], data_en_msg );
   //entry point
   printf("Entry point address:\t\t0x%lx\n", header -> e_entry);
   //file offset
   printf("Start of section headers:\t%ld (bytes into file)\n", header -> e_shoff);
   //number of section header entries
   printf("Number of section headers: \t%d \n", header -> e_shnum);
   //size of each section header entry.
   printf("Size of section headers: \t%d (bytes)\n", header -> e_shentsize);
   //file offset in which the program header table resides
   printf("Start of program headers:\t%ld (bytes into file)\n", header -> e_phoff);
   //number of program header entries
   printf("Number of program headers:\t%d \n", header -> e_phnum);
   //size of each program header entry
   printf("Size of program headers:\t%d (bytes)\n", header -> e_phentsize);
}

void print_section_names(){
    //TODO FIX UGLY PRINTS
    if(!check_file()) return;
    Elf64_Shdr* sections = (Elf64_Shdr*)((void*)header + header -> e_shoff);
    printf("%s\n","Section Headers:");
    printf("[Nr]\tName\t\tAddress\t\t\tOffset\t\t\tSize\t\t\tType\n");
    Elf64_Shdr* get_name_helper = (Elf64_Shdr*)((void*)header + header -> e_shoff + (header->e_shstrndx)*(header->e_shentsize)); //strtab
    //index     e_shstrndx;	/* Section header string table index */
    //name      sh_name;	/* Section name (string tbl index) */
    //address   sh_addr;	/* Section virtual addr at execution */
    //offset    sh_offset;	/* Section file offset */
    //size      sh_size;	/* Section size in bytes */
    for(int i = 0; i < num_of_section_headers; i++){
        char* sec_name = (void*)header + get_name_helper -> sh_offset + sections -> sh_name;
        printf("[%d]\t%s\t\t%lx\t\t\t%ld\t\t\t%lx\t\t\t%d\n", i, sec_name, sections -> sh_addr, sections -> sh_offset, sections -> sh_size, sections -> sh_type);
        sections = (Elf64_Shdr*)((void*)sections + sizeof(Elf64_Shdr));
    }
    
}

void print_symbols(){
    if(!check_file()) return;
    int i;
    Elf64_Off sym_offset;
    Elf64_Xword sym_size;
    Elf64_Xword ent_size;
    Elf64_Shdr* sections = (Elf64_Shdr*)((void*)header + header -> e_shoff);
    Elf64_Shdr* get_name_helper = (Elf64_Shdr*)((void*)header + header -> e_shoff + (header->e_shstrndx)*(header->e_shentsize)); 
    for(i = 0; i < num_of_section_headers; i++){
        char* sec_name = (void*)header + get_name_helper -> sh_offset + sections -> sh_name;
        if(strcmp(sec_name,".symtab")==0){
            sym_offset = sections -> sh_offset;
            sym_size = sections -> sh_size;
            ent_size = sections -> sh_entsize;
            break;
        }
        sections = (Elf64_Shdr*)((void*)sections + sizeof(Elf64_Shdr));
    }
    int num_of_symbols = sym_size / ent_size;
    Elf64_Sym* symbols = (Elf64_Sym*)((void*)header + sym_offset);
    printf("Num\tValue\t\tSection index\t\tSection name\t\tSymbol name\n");
    //Elf64_Sym
    //value         st_value;       /* Symbol value */
    //section index st_shndx;       /* Section index */
    //section name
    //name          st_name;        /* Symbol name (string tbl index) */
    Elf64_Sym* set_symname_helper = (void*)header + sym_offset + sym_size;
    for(i = 0; i < num_of_symbols;i++){
        //(char*)( map_start + sections_start[section->sh_link].sh_offset + sym_table[j].st_name);
        char* sym_name = (void*)set_symname_helper + symbols -> st_name;
        char* sec_name;
        //find symbol section
        if(symbols -> st_shndx < num_of_section_headers) {
            Elf64_Shdr* sym_sec = (Elf64_Shdr*)((void*)header + header -> e_shoff + (symbols -> st_shndx)*(header->e_shentsize));
            //get section name
            sec_name = (void*)header + get_name_helper -> sh_offset + sym_sec -> sh_name;
        }
        else sec_name = "";
        
        printf("%d:\t%lx\t\t%d\t\t\t%s\t\t\t%s\n", i, symbols -> st_value, symbols -> st_shndx,sec_name, sym_name);
        symbols = (Elf64_Sym*)((void*)symbols + sizeof(Elf64_Sym));
    }
    

}

void quit(){
    if(filename != NULL) free(filename);
    _exit(0);
}

int main(int argc, char **argv) {
    int num_of_functions = 4;
    char func_strnum[100];
    int func_num;
    
    //set an array of functions
    void(*func_array[num_of_functions])(void);
    
    func_array[0] = examine_elf_file;
    func_array[1] = print_section_names;
    func_array[2] = print_symbols;
    func_array[3] = quit;
    
    while(TRUE){
        
        printf("%s\n","Choose action:");
        printf("%s\n","1-Examine ELF file");
        printf("%s\n","2-Print Section Names");
        printf("%s\n","3-Print Symbols");
        printf("%s\n","4-Quit");
        
        scanf("%s", func_strnum);
        func_num = atoi(func_strnum) - 1;
        //if invalid input
        if(func_num < 0 || func_num>=num_of_functions) _exit(-1);
        
        (*func_array[func_num])();
        
    }
    
    return 0;
}