# config

Where the config file is, and what is in it.

```bash
mlab-scw config path
mlab-scw config show
```

## path

Prints the location and nothing else — no colour, no heading, no blank lines —
because this one is meant to be pasted into another command.

```bash
$ mlab-scw config path
/home/you/.mlab/scw.conf

chmod 600 "$(mlab-scw config path)"
cp "$(mlab-scw config path)" ~/backup/
```

## show

The whole file, with every secret key masked.

```
$ mlab-scw config show

  /home/you/.mlab/scw.conf

  default  prod

  profiles

    prod
    access_key       SCWEXAMPLEACCESSKEY0
    organization_id  aaaaaaaa-1111-2222-3333-444444444444
    secret_key       ****4444

    lab
    access_key       SCWEXAMPLE2NDKEY0AB
    organization_id  aaaaaaaa-1111-2222-3333-444444444444
    region           fr-par
    secret_key       ****9911
```

If the file is readable by anyone but you, it says so — here and at the start of
every command that loads credentials:

```
  ! config /home/you/.mlab/scw.conf has mode 0644; it holds secret keys, 0600 is recommended
```

The file is written 0600 inside a 0700 directory. That warning means something
else changed it.

See [Configuration](Configuration) for the file's shape, the environment
variables and the precedence rules.
