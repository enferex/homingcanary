#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

// vim: set ts=4:set et:retab

// This represents a single entry from /proc/<pid>/maps
typedef struct _map_t
{
    uintptr_t      lower;
    uintptr_t      upper;
    struct _map_t *next;
} map_t;

static void usage(const char *execname)
{
    printf("Usage: %s [-h] -p pid\n"
           "  -h:       This help message.\n"
           "  -p <pid>: PID of process to scan.\n",
           execname);
}

/* Call 'free_maps' to reclaim memory associated to the return item. */
static map_t *find_maps(pid_t target)
{
    FILE  *fp;
    map_t *head      = NULL;
    char   buf[1024] = {0};

    snprintf(buf, sizeof(buf)-1, "/proc/%d/maps", target);

    if (!(fp = fopen(buf, "r"))) {
        fprintf(stderr, "[-] Error opening %s: %s\n", buf, strerror(errno));
        return NULL;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        char  *field;
        map_t *map = calloc(1, sizeof(map_t));
        if (!map) {
            fprintf(stderr, "[-] Error allocating map entry.\n");
            exit(EXIT_FAILURE);
        }

        map->lower = strtoul(strtok(buf, "-"), NULL, 16);
        map->upper = strtoul(strtok(NULL, " "), NULL, 16);
        (void)strtok(NULL, " ");     // Ignore perms column
        (void)strtok(NULL, " ");     // Ignore offset column
        (void)strtok(NULL, " ");     // Ignore dev column
        (void)strtok(NULL, " ");     // Ignore inode column
        field = strtok(NULL, " \n"); // Optional pathname column
        if (field == NULL) {         // Should be empty
            map->next = head;
            head = map;
        }
        else
          free(map);
    }

    fclose(fp);
    return head;
}

static void free_maps(map_t *map)
{
    while (map) {
        map_t *next = map->next;
        free(map);
        map = next;
    }
}

// Special thanks to Google for helping locate the Shannon entropy equation.
// I probably snagged the math from the wikipedia entry for Shannon entropy.
static double shannon_entropy(uintptr_t data)
{
    double shannon;
    int counts[0xff+1] = {0};

    // Count byte occurances
    for (int i=0; i<sizeof(data); ++i)
      ++counts[(data>>(i*8)) & 0xff];

    // Math
    shannon = 0.0;
    for (int i=0; i<sizeof(data); ++i) {
        const int n = counts[(data>>(i*8)) & 0xff];
        const double freq = (double)n / sizeof(data);
        shannon += freq * log2(freq);
    }

    return shannon;
}

// Calculate by running our shannon algorithm on a word where each byte is a
// different value.
static double max_entropy(void)
{
#if UINTPTR_MAX == UINT64_MAX
    return shannon_entropy(0x0102030405060708);
#else
    return shannon_entropy(0x01020304);
#endif
}

static uintptr_t read_word(uintptr_t addr, pid_t target)
{
    int       fd;
    uintptr_t word = 0;
    char      buf[128];

    sprintf(buf, "/proc/%d/mem", target);

    if ((fd = open(buf, O_RDONLY | __O_LARGEFILE)) == -1) {
        fprintf(stderr, "[-] Error opening memory for pid %d: %s\n",
                target, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((pread(fd, (void *)&word, sizeof(word), addr) != sizeof(word)) && errno) {
        fprintf(stderr, "[-] Error reading data for "
                "pid %d at address %p: %s\n",
                target, (void *)addr, strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(fd);
    return word;
}

static void write_word(uintptr_t addr, pid_t target, uintptr_t word)
{
    int       fd;
    char      buf[128];

    sprintf(buf, "/proc/%d/mem", target);

    if ((fd = open(buf, O_WRONLY | __O_LARGEFILE)) == -1) {
        fprintf(stderr, "[-] Error opening memory for pid %d: %s\n",
                target, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (pwrite(fd, (void *)&word, sizeof(word), addr) != sizeof(word)) {
        fprintf(stderr, "[-] Error writting patch for "
                "pid %d at address %p: %s\n",
                target, (void *)addr, strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(fd);
}

static bool in_range(const map_t *maps, uintptr_t addr)
{
    for (const map_t *m=maps; m; m=m->next)
      if (addr >= m->lower && addr < m->upper)
        return true;

    return false;
}

// Locate return addresses within 'map' and patch them with '0xdeadbeef'.
static void patch_map(const map_t *map, pid_t target, const map_t *maps)
{
    printf("[+] Scanning %d [%p-%p]\n",
           target, (void *)map->lower, (void *)map->upper);

    // [rbp + 8] <--- Return address
    // [rbp]     <--- Old rsp
    // [rbp - 8] <--- Stack canary (assume word-size block with max entropy)
    for (uintptr_t addr=map->lower; addr<map->upper; addr+=sizeof(uintptr_t)) {
        const uintptr_t canary  = read_word(addr, target);
        const double    shannon = shannon_entropy(canary);
        if (shannon == max_entropy()) {
            const uintptr_t ret = read_word(addr+16, target);
            if (in_range(maps, ret)) {
                printf("[+] Found canary:         %lx at %p\n",
                       canary, (void *)addr);
                printf("[+] Patching return addr: %p at %p\n",
                       (void *)ret, (void *)addr+16);
                write_word(ret, target, 0xdeadbeef);
            }
        }
    }
}

// If we are generating a heat map, figure out how many different bytes
// this word has.
static void to_heatmap(FILE *heatmap, uintptr_t word, int word_index)
{
    char suffix;
    int n_diff, counts[0xFF] = {0};

    // Count byte occurrences.
    n_diff = 0;
    if (word != 0x0) {
        for (int i=0; i<sizeof(uintptr_t); ++i) {
            const int byte = (word >> (i*8)) & 0xff;
            ++counts[byte];
            n_diff += !!(counts[byte] != 1);
        }

        if (word == 0x0)
          n_diff = 0;
    }

    suffix = ((word_index>0) && (word_index%8 == 0)) ? '\n' : ',';
    fprintf(heatmap, "%d%c", n_diff, suffix);
}

/* Return the number of words counted, or 0 on error. */
static uint64_t count_max_entropy(
    pid_t        pid,
    const map_t *map,
    uint64_t    *n_max,
    FILE        *heatmap)
{
    int fd;
    char buf[128];
    uint64_t n_words;

    *n_max = 0;

    sprintf(buf, "/proc/%d/mem", pid);
    if ((fd = open(buf, O_RDONLY | __O_LARGEFILE)) == -1)
      return 0;

    n_words = 0;
    printf("[*] Scanning %s\t[%p - %p]\n",
           buf, (void *)map->lower, (void *)map->upper);
    for (uintptr_t addr=map->lower; addr<map->upper; addr+=sizeof(uintptr_t)) {
        uintptr_t word;
        if (pread(fd, &word, sizeof(word), addr) == -1) {
            *n_max = 0;
            close(fd);
            return 0;
        }

        ++n_words;
        *n_max += (shannon_entropy(word) == max_entropy());

        if (heatmap)
          to_heatmap(heatmap, word, n_words);
    }

    close(fd);
    return n_words;
}

static void scan_memory(pid_t pid, const char *heatmap_fname)
{
    FILE *heatmap;
    map_t *maps;
    uint64_t n_words_scanned, n_max_entropy_words;

    // If we fail to open the heatmap output file, continue anyways.
    if (heatmap_fname && !(heatmap = fopen(heatmap_fname, "w")))
        fprintf(stderr, "[-] Error creating heatmap file: %s (%s).",
                        heatmap_fname, strerror(errno));

    maps = find_maps(pid);
    n_words_scanned = n_max_entropy_words = 0;
    for (const map_t *m=maps; m; m=m->next) {
        uint64_t n_max;
        uint64_t n_words = count_max_entropy(pid, m, &n_max, heatmap);
        n_words_scanned     += n_words;
        n_max_entropy_words += n_max;
    }
    free_maps(maps);

    printf("[+] %lu/%lu (%02f) [max_entropy to words counted ratio]\n",
           n_max_entropy_words, n_words_scanned,
           (double)n_max_entropy_words / n_words_scanned);
}

// Parse all /proc/<pid>/mem and count number of max vs non-max entropy.
static void calc_all_accessable_entropy(void)
{
    DIR *dir;
    struct dirent *ent;

    if (!(dir = opendir("/proc")))
      return;

    while ((ent = readdir(dir))) {
        pid_t pid;

        if (ent->d_name[0] == '.')
          continue;
        if (!(pid = atoi(ent->d_name)))
          continue;

        scan_memory(pid, NULL);
    }

    closedir(dir);
}

// Scan /proc/<pid>/maps, look for return addresses and patch them.
static void hack(pid_t target, const char *heatmap)
{
    map_t *maps;

    if (!(maps = find_maps(target))) {
        fprintf(stderr, "[-] Error locating memory maps.\n");
        exit(EXIT_FAILURE);
    }

    if (heatmap)
      scan_memory(target, heatmap);

    for (const map_t *map=maps; map; map=map->next)
      patch_map(map, target, maps);
}

int main(int argc, char **argv)
{
    int opt;
    pid_t pid;
    const char *heatmap;

    pid = 0;
    heatmap = NULL;

    while ((opt = getopt(argc, argv, "xX:hp:")) != -1) {
        switch (opt) {
        case 'h': usage(argv[0]); exit(EXIT_SUCCESS);
        case 'p': pid = atoi(optarg); break;

        // Unpublished options "-X <filename> ... generates a heatmap"
        case 'x': calc_all_accessable_entropy(); return 0;
        case 'X': heatmap = optarg; break;

        default: break;
        }
    }

    if (!pid) {
        fprintf(stderr, "Option '-p' must be specified.\n");
        exit(EXIT_FAILURE);
    }

    hack(pid, heatmap);

    return 0;
}
