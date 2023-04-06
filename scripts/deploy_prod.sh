#!/bin/bash

initial_branch=`git branch --show-current`

# Ensure working directory is clean
if ! git diff-index --quiet HEAD; then
  echo "Working directory not clean, please commit your changes first"
  exit
fi

# Fast forward dev on master, then push master
# Deployment to Clever Cloud is actually triggered via a hook
# on a push on this branch

# synchronize dev and master by replaying the local branches on top of remote ones
git fetch origin
git checkout dev
git rebase origin/dev dev
git checkout master
git rebase origin/master master

# fast merge master onto dev
git rebase dev master
git push origin master

# When we are done, we want to restore the initial state
# (in order to avoid writing things directly on master by accident)
if [ -z $initial_branch ]; then
    # The initial_branch is empty when user is in detached state, so we simply go back to dev
    git checkout dev
    echo
    echo "You were on detached state before deploying, you are back to dev"
else
    git checkout $initial_branch
    echo
    echo "Back to $initial_branch"
fi
