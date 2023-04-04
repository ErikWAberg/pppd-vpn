/*
 * utils.c | utils.h
 * The utils-module
 *
 * Purpose:
 *
 *
 */

#include "utils.h"
#include "definitions.h"

#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>


/*
 * Reads a keypress, doesn't echo.
 */
int util_getchar(void) {

    char ch = -1;
    int error;
    local_persist struct termios Otty, Ntty;

    fflush(stdout);
    tcgetattr(0, &Otty);
    Ntty = Otty;

    Ntty.c_iflag = 0;        /* input mode		*/
    Ntty.c_oflag = 0;        /* output mode		*/
    Ntty.c_lflag &= ~ICANON;    /* line settings 	*/

#if 1
    /* disable echoing the char as it is typed */
    Ntty.c_lflag &= ~ECHO;    /* disable echo 	*/
#else
    /* enable echoing the char as it is typed */
    Ntty.c_lflag |=  ECHO;	/* enable echo	 	*/
#endif

#ifdef __APPLE__
    Ntty.c_cc[VMIN] = CMIN;    /* minimum chars to wait for */
    Ntty.c_cc[VTIME] = CTIME;    /* minimum wait time	*/
#else
    Ntty.c_cc[VMIN] = 1;    /* minimum chars to wait for */
    Ntty.c_cc[VTIME] = 0;    /* minimum wait time	*/
#endif


#if 1
    /*
    * use this to flush the input buffer before blocking for new input
    */
#define FLAG TCSAFLUSH

#else
    /*
    * use this to return a char from the current input buffer, or block if
    * no input is waiting.
    */
#define FLAG TCSANOW

#endif

    if ((error = tcsetattr(0, FLAG, &Ntty)) == 0) {
        error = read(0, &ch, 1);          /* get char from stdin */
        error += tcsetattr(0, FLAG, &Otty);   /* restore old settings */
    }

    return (error == 1 ? (int) ch : -1);

}

/*
 * Returns a string from the user via stdin.
 * Does not support 'backspace'.
 */
char *util_get_input_string(void) {
    local_persist char string[64] = {0};
    int index = 0;

    while (1) {

        int c = util_getchar();

        if (c >= 0) {
            if (index < 64 - 1) {
                if (c == 13 || c == 10) {
                    if (index == 0) return NULL;

                    string[index] = '\0';
                    return string;
                }
                printf("*");
                string[index++] = (char) c;
            } else {
                fprintf(stderr, "String too large! (63 characters max)");
                return NULL;
            }
        }

    }

}
