#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define MAX_PROCS 512

struct ps_node {
    __pid_t pid;
    struct ps_node *parent;
    struct ps_node *child; 
    struct ps_node *sibling;  
};

struct procs_affi {
    __pid_t pid;
    __pid_t ppid;
    struct ps_node *node;
};

struct ps_node*
create_node(int pid) {
    struct ps_node *new_node = (struct ps_node *) malloc(sizeof(struct ps_node));

    new_node->pid = pid;
    new_node->child = NULL;
    new_node->parent = NULL;
    new_node->sibling = NULL;

    return new_node;
}

void
add_child(struct ps_node *parent, struct ps_node *child) {
    if (parent->child == NULL) {
        parent->child = child;
    } else {
        struct ps_node *sibling = parent->child;
        for (; sibling->sibling != NULL; sibling = sibling->sibling);
        sibling->sibling = child; 
    }
    child->parent = parent;
}

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

    return -1;
}

int
populate_tree(struct ps_node *root, struct procs_affi pa[], int proc_num) {
    int i, j, index;
    __pid_t pid, ppid;
    struct ps_node *child, *parent;

    for (i = 0; i < proc_num; i++) {
        pid = pa[i].pid;
        ppid = pa[i].ppid;

        child = create_node(pid);
        pa[i].node = child;

        index = get_index(pa, proc_num, ppid);
        parent = (index == -1) ? root : pa[index].node;
        add_child(parent, child);
    }

    return 0;
}

void
print_tree(struct ps_node *node, int level) {
    int i;

    for (i = 0; i < level; i++) {
        printf("  ");
    }
    printf("|--%d\n", node->pid);
    
    if (node->child != NULL) {
        print_tree(node->child, level + 1);
    }

    if (node->sibling != NULL) {
        print_tree(node->sibling, level);
    }

    free(node);
}

int 
main(int argc, char *argv[]) {
    struct procs_affi pa[MAX_PROCS];
    int proc_num;
    struct ps_node *root;

    // 1. 解析参数
    parse_args(argc, argv);

    // 2. 遍历/proc，获取进程号以及父进程
    proc_num = get_procs(pa);
    for (int i = 0; i < proc_num; i++) {
        printf("pid: %d, ppid: %d\n", pa[i].pid, pa[i].ppid);
    }

    // 3. 在内存中建树
    root = create_node(0);
    populate_tree(root, pa, proc_num);

    print_tree(root->child, 0); 

    return 0;
}
