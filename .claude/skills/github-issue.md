# GitHub Issue Skill

Interact with GitHub issues using the `gh` CLI tool.

## Usage

```
/github-issue <action> [options]
```

## Actions

### read

View an issue or list issues.

**View a specific issue:**
```bash
gh issue view <issue_number>
```

**List issues:**
```bash
gh issue list
gh issue list --state open
gh issue list --state closed
gh issue list --label "bug"
gh issue list --assignee @me
gh issue list --limit 20
```

### update

Update an existing issue.

**Edit issue title:**
```bash
gh issue edit <issue_number> --title "New title"
```

**Edit issue body:**
```bash
gh issue edit <issue_number> --body "New description"
```

**Add labels:**
```bash
gh issue edit <issue_number> --add-label "bug,priority:high"
```

**Remove labels:**
```bash
gh issue edit <issue_number> --remove-label "wontfix"
```

**Assign users:**
```bash
gh issue edit <issue_number> --add-assignee @me
gh issue edit <issue_number> --add-assignee username
```

**Close an issue:**
```bash
gh issue close <issue_number>
```

**Reopen an issue:**
```bash
gh issue reopen <issue_number>
```

**Add a comment:**
```bash
gh issue comment <issue_number> --body "Comment text"
```

### create

Create a new issue.

**Interactive creation:**
```bash
gh issue create
```

**Create with title and body:**
```bash
gh issue create --title "Issue title" --body "Issue description"
```

**Create with labels and assignees:**
```bash
gh issue create --title "Bug report" --body "Description" --label "bug" --assignee @me
```

**Create from file:**
```bash
gh issue create --title "Issue title" --body-file path/to/file.md
```

## Instructions

When the user invokes this skill:

1. Parse the arguments to determine the action (`read`, `update`, or `create`)
2. If no action is specified, ask the user what they want to do
3. Execute the appropriate `gh issue` command based on the action and options provided
4. Display the results to the user

### Examples

- `/github-issue read 123` - View issue #123
- `/github-issue read` - List all open issues
- `/github-issue update 123 --title "New title"` - Update issue #123 title
- `/github-issue create --title "Bug" --body "Description"` - Create a new issue
