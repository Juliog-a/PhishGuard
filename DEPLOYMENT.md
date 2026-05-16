# Deployment Guide

## Recommended deployment: GitHub Pages from branch

This is the easiest option if you want to upload the files through the GitHub web interface.

1. Unzip the project.
2. Create a new GitHub repository, for example `phishguard-ai`.
3. Upload the project files to the repository root.
4. Go to `Settings` → `Pages`.
5. Under `Build and deployment`, select `Deploy from a branch`.
6. Select:
   - Branch: `main`
   - Folder: `/root`
7. Save.
8. Open the published URL when GitHub finishes the deployment.

Expected URL format:

```text
https://YOUR_USERNAME.github.io/phishguard-ai/
```

## Alternative: GitHub Actions

The repository includes `.github/workflows/static.yml`. To use it:

1. Go to `Settings` → `Pages`.
2. Under `Build and deployment`, select `GitHub Actions`.
3. Push or upload a change to the `main` branch.

## Important privacy note

The app processes emails locally in the browser. However, the website itself will be public if deployed through a public GitHub Pages repository. Do not commit real email evidence, real customer data or real confidential attachments into the repository.
