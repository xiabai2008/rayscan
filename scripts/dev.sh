#!/bin/bash
# RayScan Development Launcher
# Launches Claude Code with permissions bypass for autonomous dev work.
# Usage: scripts/dev.sh [task description]
set -e
if [ $# -eq 0 ]; then
    claude --dangerously-skip-permissions \
           --allowedTools "Bash,Read,Edit,Write,Glob,Grep,Agent,TaskCreate,TaskUpdate"
else
    claude --dangerously-skip-permissions \
           --allowedTools "Bash,Read,Edit,Write,Glob,Grep,Agent,TaskCreate,TaskUpdate" \
           -p "$*"
fi
