# Implementation Command

Start implementing a feature based on GitHub issue #$ARGUMENTS.

## Instructions

Follow these steps in order:

### Step 1: Read the GitHub Issue

Fetch the issue details:

```bash
gh issue view $ARGUMENTS
```

Display the issue title, body, labels, and any relevant metadata to confirm with the user.

### Step 2: Create a Git Worktree

Create a new git worktree for the feature implementation:

```bash
git worktree add ../rvc-feature-$ARGUMENTS -b feature/$ARGUMENTS
```

This creates:
- A new directory `../rvc-feature-$ARGUMENTS` with a fresh working copy
- A new branch `feature/$ARGUMENTS` based on the current branch

If the branch already exists, use:
```bash
git worktree add ../rvc-feature-$ARGUMENTS feature/$ARGUMENTS
```

### Step 3: Analyze and Plan (Ultrathink)

Use extended thinking (ultrathink) to deeply analyze the requirements:

1. **Understand the Problem**
   - Parse the issue description thoroughly
   - Identify the core requirements and acceptance criteria
   - Note any constraints or dependencies mentioned

2. **Explore the Codebase**
   - Identify relevant files and modules that need modification
   - Understand existing patterns and conventions
   - Find related code that can be referenced or reused

3. **Design the Solution**
   - Break down the implementation into concrete steps
   - Consider edge cases and error handling
   - Plan the testing strategy (following TDD as per CLAUDE.md)

4. **Create Implementation Plan**
   - Write a detailed, step-by-step plan
   - Prioritize tasks in logical order
   - Identify any blockers or questions for the user

### Step 4: Present the Plan

Present the implementation plan to the user with:
- Summary of what will be implemented
- List of files to be created or modified
- Step-by-step implementation tasks
- Any questions or clarifications needed

Wait for user approval before proceeding with implementation.

## Notes

- The worktree is created in the parent directory to keep it separate from the main repository
- Always follow the TDD cycle (RED -> GREEN -> REFACTOR) as specified in CLAUDE.md
- Use `cargo fmt` and `cargo clippy` before committing any changes
