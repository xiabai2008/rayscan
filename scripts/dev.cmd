@echo off
REM RayScan Development Launcher
REM Launches Claude Code with permissions bypass for autonomous dev work.
REM Usage: scripts\dev.cmd [task description]
echo [RayScan Dev] Starting autonomous mode...
if "%1"=="" (
    claude --dangerously-skip-permissions --allowedTools "Bash,Read,Edit,Write,Glob,Grep,Agent,TaskCreate,TaskUpdate"
) else (
    claude --dangerously-skip-permissions --allowedTools "Bash,Read,Edit,Write,Glob,Grep,Agent,TaskCreate,TaskUpdate" -p "%*"
)
