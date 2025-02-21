#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sched.h>
#include <seccomp.h>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#ifndef _CONTAINERIZE_H_
#define _CONTAINERIZE_H_

typedef struct program {
  int (*program)();
  std::vector<std::string> &args;
} Program;

int containerize(Program &program);

#endif
