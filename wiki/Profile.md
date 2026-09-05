# profile

List, inspect, select and delete saved profiles.

```bash
mlab-scw profile list
mlab-scw profile show prod
mlab-scw profile use lab
mlab-scw profile remove old
```

Aliases: `list`/`ls`, `remove`/`rm`/`delete`.

Profiles are created by [`login`](Login) and live in the config file described
in [Configuration](Configuration). This command never touches credentials beyond
moving and deleting them.

## list

```
$ mlab-scw profile list

  ● prod  SCWEXAMPLEACCESSKEY0  all localities
  · lab   SCWEXAMPLE2NDKEY0AB   fr-par

  ● default profile
```

The third column is the profile's locality narrowing — `all localities` when it
sweeps everything, which is the default and usually what an audit wants.

## show

```
$ mlab-scw profile show prod

  Profile prod

  access_key       SCWEXAMPLEACCESSKEY0
  organization_id  aaaaaaaa-1111-2222-3333-444444444444
  secret_key       ****4444
```

The secret key is masked to its last four characters, here and everywhere else.
Nothing in this tool prints it in full.

## use

```
$ mlab-scw profile use lab
  ✔ default profile is now "lab"
```

The default is what every command uses when `--profile` is not given. A config
holding exactly one profile does not need a default set — it is used
automatically.

## remove

```
$ mlab-scw profile remove old
  ✔ removed profile "old"
```

Removing the default promotes another profile rather than leaving the config
pointing at nothing. This deletes the stored credential; it does **not** revoke
the API key, which has to be deleted in the console.
