# completions

Print a shell completion script.

```bash
mlab-scw completions bash
mlab-scw completions zsh
mlab-scw completions fish
mlab-scw completions elvish
mlab-scw completions powershell
```

The script goes to stdout with nothing else on it, so it can be redirected
straight to where the shell will look for it.

## Installing it

**zsh** — anywhere on `$fpath`:

```bash
mkdir -p ~/.zfunc
mlab-scw completions zsh > ~/.zfunc/_mlab-scw
```

and, in `~/.zshrc` before `compinit`:

```bash
fpath=(~/.zfunc $fpath)
```

**bash**:

```bash
mlab-scw completions bash > ~/.local/share/bash-completion/completions/mlab-scw
```

or system-wide, `/etc/bash_completion.d/mlab-scw`.

**fish**:

```bash
mlab-scw completions fish > ~/.config/fish/completions/mlab-scw.fish
```

## What it completes

Subcommands, their aliases, and every flag with its value hints — so `--region`
offers the four regions and `--zone` the ten zones, straight from the enum the
code itself validates against.

Product keys for `catalog` are not completed: they come from the catalogue at
runtime rather than from the clap definition. `mlab-scw catalog` with no
argument lists them.

## Regenerating

The script encodes the CLI surface at the moment it was generated. Regenerate it
after upgrading, or the new flags will not be offered.
