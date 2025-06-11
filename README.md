# GitHub Commit Finder

A simple Python tool with a friendly GUI to find and save GitHub commits from repositories or organizations. exploring commits, downloading their changes.

## What It Does

- **Find Commits**: Scans GitHub repositories or organizations to discover commits using GitHub's API.
- **Download Changes**: Saves commit diffs or patches to your computer in an `output` folder.
- **Export Results**: Saves commit URLs to a text file with a timestamp (e.g., `commits_20250611_215100.txt`).
- **Customizable**: Set thread count, batch size, or use a proxy for scanning.

## What You Need

- **GitHub Personal Access Token (PAT)**: You need a token from *your* GitHub account with `repo` permissions. [Learn how to create one here](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token).


## How to Set It Up

1. Download or clone this project to your computer:
   ```bash
   git clone https://github.com/Abdulrahman-Gamil/GitHub-Commits-Finder.git
   cd GitHub-Commits-Finder
   ```

## How to Use It

1. Start the tool:
   ```bash
   python github_commit_finder_gui.py
   ```
   The window opens full-screen but resizes if you adjust it.
2. Enter your **GitHub Personal Access Token** in the "GitHub Token" field. This must come from your GitHub account
3. Choose what to scan:
   - **Repository**: Paste a repo URL (e.g., `https://github.com/owner/repo`).
   - **Organization**: Type an organization name or pick a text file with organization names (one per line).
4. (Optional) Adjust settings:
   - **Thread Count**: How many tasks run at once (default: 2).
   - **Batch Size**: Commits checked per request (default: 300).
   - **Proxy**: Add a proxy like `http://host:port` if needed.
5. Click **Start** to begin scanning.
6. Watch the output log for updates.
7. Click **Export Commits** to save commit URLs to a text file.
8. Use **Stop** to pause or **Clear Output** to reset the log.

## Where Results Go

- **Downloaded Files**: Commit diffs or patches are saved in `output/owner_repo/` (e.g., `output/owner_repo/abc123.diff`).
- **Exported Commits**: Commit URLs are saved to a text file, one per line, with a name like `commits_20250611_215100.txt`.

## Important Notes

- **Your Token**: Always use a PAT from your GitHub account. Don’t share it.
- **Big Repos**: For large repositories, try increasing the thread count or batch size for faster scanning.
- **Rate Limits**: The tool waits and retries if GitHub limits your requests.
- **Platform Support**: Works on Windows, Linux, and macOS. Linux/macOS users may see a maximized window matching your screen size.
