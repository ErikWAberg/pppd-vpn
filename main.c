/*
 * main.c
 *
 * Purpose:
 * Linked when builing the executable, but not when building the library.
 */

#include "vpn.h"

/*
 * Assumes that the program is launched from a terminal.
 */
int main(int argc, char *argv[]) {
    return vpn_run_cli(argc, argv);
}