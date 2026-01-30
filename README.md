# service-auth

This service is responsible for authentication throught the system.
It relies on profile service to be working for it to perform optimally.


Development:
***

To update the profile api one needs to run the following grpc update command.

```protoc -I ../api/service/profile/v1/ ../api/service/profile/v1/profile.proto --go_out=plugins=grpc:grpc/profile```

### Git Hooks

This repository includes a pre-commit hook that automatically runs `make format` before each commit to ensure consistent code formatting.

**Enable the hook:**
```bash
git config core.hooksPath .githooks
```

**What it does:**
- Detects staged `.go` files
- Runs `make format` to apply gofmt/goimports
- If formatting changes any files, the commit is blocked
- You must review and stage the formatted files before committing again

**To disable temporarily:**
```bash
git commit --no-verify
```



