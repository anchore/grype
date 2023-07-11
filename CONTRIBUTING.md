# Contributing to Grype

If you are looking to contribute to this project and want to open a GitHub pull request ("PR"), there are a few guidelines of what we are looking for in patches. Make sure you go through this document and ensure that your code proposal is aligned.

## Setting up your environment

Before you can contribute to Grype, you need to configure your development environment.

### Debian setup

You will need to install Go. The version on https://go.dev works best, using the system golang doesn't always work the way you might expect.

Refer to the go.mod file in the root of this repo for the recommended version of Go to install.

You will also need Docker. There's no reason the system packages shouldn't work, but we used the official Docker package. You can find instructions for installing Docker in Debian [here](https://docs.docker.com/engine/install/debian/).

You also need to install some Debian packages

```sh
sudo apt-get install build-essential git libxml2-utils
```

## Configuring Git

You will need to configure your git client with your name and email address. This is easily done from the command line.

```text
$ git config --global user.name "John Doe"
$ git config --global user.email "john.doe@example.com"
```

This username and email address will matter later in this guide.

## Fork the repo

You should fork the Grype repo using the "Fork" button at the top right of the Grype GitHub [site](https://github.com/anchore/grype/). You will be doing your development in your fork, then submit a pull request to Grype. There are many resources how to use GitHub effectively, we will not cover those here.

## Adding a feature or fix

If you look at the Grype [Issue](https://github.com/anchore/grype/issues) there are plenty of bugs and feature requests. Maybe look at the [good first issue](https://github.com/anchore/grype/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22) list if you're not sure where to start.

## Commit guidelines

In the Grype project we like commits and pull requests (PR) to be easy to understand and review. Open source thrives best when everything happening is over documented and small enough to be understood.

### Granular commits

Please try to make every commit as simple as possible, but no simpler. The idea is that each commit should be a logical unit of code. Try not to commit too many tiny changes, for example every line changed in a file as a separate commit. And also try not to make a commit enormous, for example committing all your work at the end of the day.

Rather than try to follow a strict guide on what is or is not best, we try to be flexible and simple in this space. Do what makes the most sense for the changes you are trying to include.

### Commit title and description

Remember that the message you leave for a commit is for the reviewer in the present, and for someone (maybe you) changing something in the future. Please make sure the title and description used is easy to understand and explains what was done. Jokes and clever comments generally don't age well in commit messages. Just the facts please.

## Sign off your work

The `sign-off` is an added line at the end of the explanation for the commit, certifying that you wrote it or otherwise have the right to submit it as an open-source patch. By submitting a contribution, you agree to be bound by the terms of the DCO Version 1.1 and Apache License Version 2.0.

Signing off a commit certifies the below Developer's Certificate of Origin (DCO):

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

   (a) The contribution was created in whole or in part by me and I
       have the right to submit it under the open source license
       indicated in the file; or

   (b) The contribution is based upon previous work that, to the best
       of my knowledge, is covered under an appropriate open source
       license and I have the right under that license to submit that
       work with modifications, whether created in whole or in part
       by me, under the same open source license (unless I am
       permitted to submit under a different license), as indicated
       in the file; or

   (c) The contribution was provided directly to me by some other
       person who certified (a), (b) or (c) and I have not modified
       it.

   (d) I understand and agree that this project and the contribution
       are public and that a record of the contribution (including all
       personal information I submit with it, including my sign-off) is
       maintained indefinitely and may be redistributed consistent with
       this project or the open source license(s) involved.
```

All contributions to this project are licensed under the [Apache License Version 2.0, January 2004](http://www.apache.org/licenses/).

When committing your change, you can add the required line manually so that it looks like this:

```text
Signed-off-by: John Doe <john.doe@example.com>
```

Alternatively, configure your Git client with your name and email to use the `-s` flag when creating a commit:

```text
$ git config --global user.name "John Doe"
$ git config --global user.email "john.doe@example.com"
```

Creating a signed-off commit is then possible with `-s` or `--signoff`:

```text
$ git commit -s -m "this is a commit message"
```

To double-check if the commit was signed-off, look at the log output:

```text
$ git log -1
commit 37ceh170e4hb283bb73d958f2036ee5k07e7fde7 (HEAD -> issue-35, origin/main, main)
Author: John Doe <john.doe@example.com>
Date:   Mon Aug 1 11:27:13 2020 -0400

    this is a commit message

    Signed-off-by: John Doe <john.doe@example.com>
```

## Test your changes

This project has a `Makefile` which includes many helpers running both unit and integration tests. Although PRs will have automatic checks for these, it is useful to run them locally, ensuring they pass before submitting changes. Ensure you've bootstrapped once before running tests:

```text
$ make bootstrap
```

You only need to bootstrap once. After the bootstrap process, you can run the tests as many times as needed:

```text
$ make unit
$ make integration
```

You can also run `make all` to run a more extensive test suite, but there is additional configuration that will be needed for those tests to run correctly. We will not cover the extra steps here.

## Pull Request

If you made it this far and all the tests are passing, it's time to submit a Pull Request (PR) for Grype. Submitting a PR is always a scary moment as what happens next can be an unknown. The Grype project strives to be easy to work with, we appreciate all contributions. Nobody is going to yell at you or try to make you feel bad. We love contributions and know how scary that first PR can be.

### PR Title and Description

Just like the commit title and description mentioned above, the PR title and description is very important for letting others know what's happening. Please include any details you think a reviewer will need to more properly review your PR.

A PR that is very large or poorly described has a higher likelihood of being pushed to the end of the list. Reviewers like PRs they can understand and quickly review.

### What to expect next

Please be patient with the project. We try to review PRs in a timely manner, but this is highly dependent on all the other tasks we have going on. It's OK to ask for a status update every week or two, it's not OK to ask for a status update every day.

It's very likely the reviewer will have questions and suggestions for changes to your PR. If your changes don't match the current style and flow of the other code, expect a request to change what you've done.

## Document your changes

And lastly, when proposed changes are modifying user-facing functionality or output, it is expected the PR will include updates to the documentation as well. Grype is not a project that is heavy on documentation. This will mostly be updating the README and help for the tool.

If nobody knows new features exist, they can't use them!

## Security Vulnerabilities

Found a security vulnerability? See in our [Security Policy](SECURITY.md) to see how to report it to be solved as soon as possible. 
