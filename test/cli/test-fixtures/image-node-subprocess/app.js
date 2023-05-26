require("child_process").spawn("griffon", [
    "-vv",
    "registry:busybox:latest",
], {
  // we want to see any output from stdout/stderr which is why they are inherited from the parent process.
  // The real test is to make certain that piped input will not hang forever when nothing is provided on stdin
  // and there is input from the user to not use stdin. That is --make certain that we don't use "stdin is a pipe"
  // as the only indicator to expect analysis input from stdin.
  stdio: ["pipe", "inherit", "inherit"]
});
