#!/bin/bash

initial_branch=`git branch --show-current`

# Ensure working directory is clean
if ! git diff-index --quiet HEAD; then
  echo "Working directory not clean, please commit your changes first"
  exit
fi

# Fast forward main on main_clever, then push main_clever
# Deployment to Clever Cloud is actually triggered via a hook
# on a push on this branch

# synchronize main and maint_clever by replaying the local branches on top of remote ones
git fetch origin
git checkout main
git rebase origin/main main
git checkout main_clever
git rebase origin/main_clever main_clever

# fast merge main_clever onto main
git rebase main main_clever
git push origin main_clever

# When we are done, we want to restore the initial state
# (in order to avoid writing things directly on main_clever by accident)
if [ -z $initial_branch ]; then
    # The initial_branch is empty when user is in detached state, so we simply go back to main
    git checkout main
    echo
    echo "You were on detached state before deploying, you are back to main"
else
    git checkout $initial_branch
    echo
    echo "Back to $initial_branch"
fi
