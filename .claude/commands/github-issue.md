# GitHub Issue Command

Interact with GitHub issues using the `gh` CLI tool.

Arguments: $ARGUMENTS

## Instructions

Parse the arguments to determine the action and execute accordingly.

### Actions

**read** - View an issue or list issues:
- `read <number>` - View specific issue: `gh issue view <number>`
- `read` - List open issues: `gh issue list`
- `read --state closed` - List closed issues
- `read --label "bug"` - List issues with label

**update** - Update an existing issue:
- `update <number> --title "New title"` - Edit title
- `update <number> --body "New body"` - Edit body
- `update <number> --add-label "bug"` - Add labels
- `update <number> --remove-label "wontfix"` - Remove labels
- `update <number> --add-assignee @me` - Assign users
- `update <number> --close` - Close issue: `gh issue close <number>`
- `update <number> --reopen` - Reopen issue: `gh issue reopen <number>`
- `update <number> --comment "text"` - Add comment: `gh issue comment <number> --body "text"`

**create** - Create a new issue:
- `create` - Interactive creation: `gh issue create`
- `create --title "Title" --body "Body"` - Create with details
- `create --title "Title" --label "bug" --assignee @me` - Create with labels and assignees

## Behavior

1. Parse `$ARGUMENTS` to identify the action (`read`, `update`, `create`)
2. If no action specified, ask the user what they want to do
3. Execute the appropriate `gh issue` command
4. Display results to the user

## Examples

- `/github-issue read 123` - View issue #123
- `/github-issue read` - List all open issues
- `/github-issue update 123 --title "New title"` - Update issue #123 title
- `/github-issue create --title "Bug" --body "Description"` - Create a new issue
