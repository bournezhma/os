#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_PROCS 256

struct ps_tree {
    __pid_t pid;
    struct ps_tree **child;   
};

struct procs_affi {
    __pid_t pid;
    __pid_t ppid;
    struct ps_tree *node;
};

void
parse_args(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++) {
        assert(argv[i]);
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    assert(!argv[argc]);
}

int
get_procs(struct procs_affi *pa) {
    DIR *dir_ptr;
    FILE *fp;
    struct dirent *dir_entry;
    char *napid;
    int i;
    char filename[20];
    char line[256];
    char *token;


    dir_ptr = opendir("/proc");
    if (!dir_ptr) {
        perror("can't open /proc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; (dir_entry = readdir(dir_ptr)) != NULL; ) {
        napid = dir_entry->d_name;
        if (!isdigit(napid[0])) {
            continue;
        }

        pa[i].pid = atoi(napid);
        sprintf(filename, "/proc/%d/status", pa[i].pid);
        fp = fopen(filename, "r");
        if (!fp) {
            perror("can't open status file");
            exit(EXIT_FAILURE);
        }
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PPid:", 5) == 0) {
                token = strtok(line, " \t");
                token = strtok(NULL, " \t");
                pa[i].ppid = atoi(token);
            }
        }
        i++;
    }

    closedir(dir_ptr);
    return i;    
}

int 
get_index(struct procs_affi pa[], int proc_num, int pid) {
    int i;

    for (i = 0; i < proc_num; i++) {
        if (pa[i].pid == pid) {
            return i;
        }
    }
}


int
create_tree(struct ps_tree *root, struct procs_affi pa[], int proc_num) {
    int i, j, index;
    __pid_t pid, ppid;
    struct ps_tree *pst;

    for (i = 0; i < proc_num; i++) {
        pid = pa[i].pid;
        ppid = pa[i].ppid;
        pst = malloc(sizeof(struct ps_tree));
        pst->pid = pid;
        pst->child = NULL;
        pa[i].node = pst;
        if (pid == 1) {
            root = pst;
        } else {
            index = get_index(pa, proc_num, ppid); 
            for (j = 0; pa[index].node->child[j] != NULL; j++);
            pa[index].node->child[j] = pst;
            pa[index].node->child[j+1] = NULL;
        }
    }
    return 0;
}

void
print_tree(struct ps_tree *root) {
    int i;

    if (root->child == NULL) {
        printf("%d\n", root->pid);
        free(root);
    } else {
        for (i = 0; root->child[i] != NULL; i++) {
            print_tree(root->child[i]);
        }
        printf("%d\n", root->pid);
        free(root);
    }
}

int 
main(int argc, char *argv[]) {
    struct procs_affi pa[MAX_PROCS];
    int proc_num;
    struct ps_tree *root;

    // 1. 解析参数
    parse_args(argc, argv);

    // 2. 遍历/proc，获取进程号以及父进程
    proc_num = get_procs(pa);
    for (int i = 0; i < proc_num; i++) {
        printf("pid: %d, ppid: %d\n", pa[i].pid, pa[i].ppid);
    }

    // 3. 在内存中建树
    create_tree(root, pa, proc_num);

    print_tree(root); 

    return 0;
}
