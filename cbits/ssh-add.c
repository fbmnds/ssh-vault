

#include "ssh-add.h"

// $ gcc -c -Wall -Werror -fpic ssh-add.c
// $ gcc -shared -o ssh-add.so ssh-add.o


int ssh_add(char *duration, char *path, char *expect, char *answer)
{
int fdm, fds;
int rc;
char input[150];


fdm = posix_openpt(O_RDWR);
if (fdm < 0)
{
fprintf(stderr, "Error %d on posix_openpt()\n", errno);
return 1;
}

rc = grantpt(fdm);
if (rc != 0)
{
fprintf(stderr, "Error %d on grantpt()\n", errno);
return 1;
}

rc = unlockpt(fdm);
if (rc != 0)
{
fprintf(stderr, "Error %d on unlockpt()\n", errno);
return 1;
}

// Open the slave side ot the PTY
fds = open(ptsname(fdm), O_RDWR);

// Create the child process
if (fork())
{
fd_set fd_in;

  // FATHER

  // Close the slave side of the PTY
  close(fds);

  int done = 0;
  while (1)
  {
    // Wait for data from standard input and master side of PTY
    FD_ZERO(&fd_in);
    FD_SET(0, &fd_in);
    FD_SET(fdm, &fd_in);

    rc = select(fdm + 1, &fd_in, NULL, NULL, NULL);
    switch(rc)
    {
      case -1 : fprintf(stderr, "Error %d on select()\n", errno);
                exit(1);

      default :
      {
        // If data on standard input
        if (FD_ISSET(0, &fd_in))
        {
          rc = read(0, input, sizeof(input));
          if (rc > 0 && done == 0)
          {
            // Send data on the master side of PTY
            write(fdm, input, rc);
            done = 1;
          }
          else
          {
            if (rc < 0)
            {
              fprintf(stderr, "Error %d on read standard input\n", errno);
              exit(1);
            }
          }
        }

        // If data on master side of PTY
        if (FD_ISSET(fdm, &fd_in))
        {
          rc = read(fdm, input, sizeof(input));
          if (rc > 0)
          {
            // Send answer on standard output
            if(done == 0 && strstr(input, expect) != NULL) {
              write(fdm, answer, strlen(answer));
              write(fdm, "\r", 1);
              done = 1;
              //exit(0);
            }
            else if (done == 0)
            {
              fprintf(stderr, "Error, expected %s, received %s\n", expect, input);
            }
            else
            {
              fprintf(stdout, "%s\n", input);
            }
          }
          else
          {
            if (errno == 5)
            {
              exit(0);
            }
            else
            {
              fprintf(stderr, "Error %d on read master PTY\n", errno);
              exit(1);
            }
          }
        }
      }
    } // End switch
  } // End while
}
else
{
struct termios slave_orig_term_settings; // Saved terminal settings
struct termios new_term_settings; // Current terminal settings
void cfmakeraw(struct termios *termios_p);
  // CHILD

  // Close the master side of the PTY
  close(fdm);

  // Save the defaults parameters of the slave side of the PTY
  rc = tcgetattr(fds, &slave_orig_term_settings);

  // Set RAW mode on slave side of PTY
  new_term_settings = slave_orig_term_settings;
  cfmakeraw (&new_term_settings);
  tcsetattr (fds, TCSANOW, &new_term_settings);

  // The slave side of the PTY becomes the standard input and outputs of the child process
  close(0); // Close standard input (current terminal)
  close(1); // Close standard output (current terminal)
  close(2); // Close standard error (current terminal)

  dup(fds); // PTY becomes standard input (0)
  dup(fds); // PTY becomes standard output (1)
  dup(fds); // PTY becomes standard error (2)

  // Now the original file descriptor is useless
  close(fds);

  // Make the current process a new session leader
  setsid();

  // As the child is a session leader, set the controlling terminal to be the slave side of the PTY
  // (Mandatory for programs like the shell to make them manage correctly their outputs)
  ioctl(0, TIOCSCTTY, 1);

  // Execution of the program
  {
  char **av;

    // Build the command line
    av = (char **)malloc(5 * sizeof(char *));
    av[0] = "ssh-add";
    av[1] = "-t";
    av[2] = strdup(duration);
    av[3] = strdup(path);
    av[4] = NULL;
    rc = execvp(av[0], av);
  }

  // if Error...
  return 1;
}

return 0;
} // ssh-add

/*
int main(int ac, char *av[])
{
  exit(ssh_add(5,av,av[5],av[6]));
}
*/
