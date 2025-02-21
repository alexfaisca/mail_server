#include "containerize.h"

namespace fs = std::filesystem;

// Define the size for the child's stack.
#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

const char *jail_dir = "./app";
const std::string proc_path = std::string(jail_dir) + "/proc";
const std::string dev_path = std::string(jail_dir) + "/dev";
const std::string users_path = std::string(jail_dir) + "/users";

// Test function
int print_hello_world() {

  /* Terminal output and error streams */
  std::cerr << "[stderr] Hello World!" << std::endl;
  std::cout << "[stdout] Hello World!" << std::endl;

  /* File creatiion, access and modification */
  std::ofstream example_file;
  example_file.open("example.txt");
  example_file << "Writing this to a file." << std::endl;
  example_file.close();

  std::cout << "Test success! Press [enter] to exit." << std::endl;
  std::cin.ignore();

  return 0;
}

// Setup the jail
int setup_chroot() {

  // Create the jail directory if it doesn't exist.
  if (mkdir(jail_dir, 0755) != 0 && errno != EEXIST) {
    std::cerr << "mkdir(" << jail_dir << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

  // Create subdirectories in the jail.
  if (mkdir(proc_path.c_str(), 0755) != 0 && errno != EEXIST) {
    std::cerr << "mkdir(" << proc_path << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

  if (mkdir(dev_path.c_str(), 0755) != 0 && errno != EEXIST) {
    std::cerr << "mkdir(" << dev_path << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

  if (mkdir(users_path.c_str(), 0755) != 0 && errno != EEXIST) {
    std::cerr << "mkdir(" << users_path << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

  // Bind-mount /proc to jail/proc.
  if (mount("/proc", proc_path.c_str(), "proc", MS_BIND | MS_REC, "") != 0) {
    std::cerr << "mount(/proc -> " << proc_path
              << ") failed: " << strerror(errno) << std::endl;
    return -1;
  }

  // Bind-mount /dev to jail/dev.
  if (mount("/dev", dev_path.c_str(), nullptr, MS_BIND | MS_REC, "") != 0) {
    std::cerr << "mount(/dev -> " << dev_path << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

#ifdef DEBUG
  std::cout << "Before chroot: Current path is " << fs::current_path()
            << std::endl;
#endif

  // Change root to the jail directory.
  if (chroot(jail_dir) != 0) {
    std::cerr << "chroot(" << jail_dir << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

  // Change the working directory to the new root.
  if (chdir("/") != 0) {
    std::cerr << "chdir(" << "/" << ") failed: " << strerror(errno)
              << std::endl;
    return -1;
  }

#ifdef DEBUG
  std::cout << "After chroot: Current path is " << fs::current_path() << " :)"
            << std::endl;
#endif

  return 0;
}

// Setup the jail
int release_chroot() {
  // Unmount jail/proc.
  if (umount("/proc") != 0) {
#ifdef DEBUG
    std::cerr << "umount(/proc) failed: " << strerror(errno) << std::endl;
#endif
    if (umount2("/proc", MNT_DETACH) != 0) {
      std::cout << "Lazy unmount also failed @ /proc." << std::endl;
      return -1;
    }
  }

  // Unmount jail/dev.
  if (umount("/dev") != 0) {
#ifdef DEBUG
    std::cerr << "umount(/dev) failed: " << strerror(errno) << std::endl;
#endif
    if (umount2("/dev", MNT_DETACH) != 0) {
      std::cout << "Lazy unmount also failed @ /dev." << std::endl;
      return -1;
    }
  }

  return 0;
}

int setup_seccomp() {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_LOG);

  if (!ctx) {
    std::cerr << "seccomp_init failed" << std::endl;
    return -1;
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0) < 0)
    goto seccomp_fail;
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0) < 0)
    goto seccomp_fail;

  if (seccomp_load(ctx) < 0) {
    std::cerr << "seccomp_load failed: " << strerror(errno) << std::endl;
    seccomp_release(ctx);
    return -1;
  }

  seccomp_release(ctx);
  return 0;

seccomp_fail:
  std::cerr << "seccomp_rule_add failed: " << strerror(errno) << std::endl;
  seccomp_release(ctx);
  return -1;
}

int child_func(void *arg) {
  if (sethostname("email_container", 15) != 0) {
    std::cerr << "sethostname failed: " << strerror(errno) << std::endl;
    return -1;
  }

  if (setup_chroot() != 0) {
    std::cerr << "Failed to setup chroot" << std::endl;
    return -1;
  }

  if (setup_seccomp() != 0) {
    std::cerr << "Failed to setup seccomp" << std::endl;
    return -1;
  }

  auto program = reinterpret_cast<Program *>(arg);
  program->program();

#ifdef DEBUG
  std::cerr << "program ended" << std::endl;
#endif

  if (release_chroot() != 0) {
    std::cerr << "Failed to unmount filesystem" << std::endl;
    return -1;
  }

#ifdef DEBUG
  std::cerr << "Unmmount successful" << std::endl;
#endif

  return 0;
}

int containerize(Program &program) {
  int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS |
              CLONE_NEWNET | SIGCHLD;

  std::cout.setf(std::ios::unitbuf);

  // Create the child process in the new namespace and pass program as
  // argument to be executed
  pid_t child_pid = clone(child_func, child_stack + STACK_SIZE, flags,
                          reinterpret_cast<void *>(&program));
  if (child_pid == -1) {
    std::cerr << "clone failed: " << strerror(errno) << std::endl;
    return -1;
  }

  // Wait for the child process to exit.
  if (waitpid(child_pid, nullptr, 0) == -1) {
    std::cerr << "waitpid failed: " << strerror(errno) << std::endl;
    return -1;
  }

#ifdef DEBUG
  std::cout << "Container process exited.\n";
#endif

  return 0;
}

int main() {
  std::vector<std::string> args = {};
  Program p = {print_hello_world, args};
  containerize(p);
  return EXIT_SUCCESS;
}
